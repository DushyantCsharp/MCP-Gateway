"""Weekend 3 "done when": every call has a trace and a verifiable audit row.

A gateway with authentication, the finance policy, a Postgres audit chain and
in-memory span capture sits in front of recorded sample servers. Each test
drives calls through it and then checks both sides: the spans the gateway
emitted, and the audit rows it committed, which must verify as a chain.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import httpx2
import psycopg
import pytest
from opentelemetry.trace import SpanKind, StatusCode

from customs_demo import finance_server, workspace_server
from customs_demo._serve import http_app
from mcp_customs import jsonrpc
from mcp_customs.audit import Hasher, MemoryAuditStore
from mcp_customs.audit.chain import sha256_of
from mcp_customs.audit.verify import verify_database
from mcp_customs.telemetry import SCHEMA_URL
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.clients import TEST_AUDIENCE, TEST_SECRET, RawSession, answer_of, mint
from tests.support.recorder import Recorder
from tests.support.servers import serve_in_thread
from tests.support.spans import CapturedSpans

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

POLICY = Path(__file__).parents[2] / "policies" / "examples" / "finance-agent.yaml"
AUDIT_KEY = "observability-test-key"
AUTH = {"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}}


@dataclass(frozen=True)
class Observed:
    gateway: Gateway
    recorders: dict[str, Recorder]
    spans: CapturedSpans
    dsn: str
    chain: str


@pytest.fixture(scope="module")
def observed(pg_dsn: str) -> Iterator[Observed]:
    recorders = {
        "workspace": Recorder(http_app(workspace_server.build_server(), json_response=False)),
        "finance": Recorder(http_app(finance_server.build_server(), json_response=True)),
    }
    spans = CapturedSpans()
    chain = f"obs-{uuid.uuid4().hex[:10]}"
    with serve_in_thread(recorders["workspace"]) as ws, serve_in_thread(recorders["finance"]) as fin:
        config = make_config(
            {"workspace": f"{ws}/mcp", "finance": f"{fin}/mcp"},
            auth=AUTH,
            stages=[{"type": "policy", "file": str(POLICY)}],
            audit={"dsn": pg_dsn, "chain": chain, "key": AUDIT_KEY},
            approvals={"dsn": pg_dsn},
        )
        with running_gateway(config, telemetry=spans.telemetry) as gateway:
            yield Observed(gateway, recorders, spans, pg_dsn, chain)


async def audit_events(dsn: str, chain: str) -> list[dict[str, Any]]:
    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        cursor = await conn.execute("SELECT event FROM customs_audit WHERE chain = %s ORDER BY seq", (chain,))
        return [row[0] for row in await cursor.fetchall()]


async def eventually(dsn: str, chain: str, done: Any) -> list[dict[str, Any]]:
    """Result events are written after the response; poll until ``done(events)`` holds."""
    events: list[dict[str, Any]] = []
    for _ in range(100):
        events = await audit_events(dsn, chain)
        if done(events):
            return events
        await anyio.sleep(0.05)
    raise AssertionError(f"audit log never reached the expected state; last saw {len(events)} events")


def server_span(spans: CapturedSpans, request_id: str) -> Any:
    matches = []
    for span in spans.spans:
        # OpenTelemetry's recursive AnyValue alias defeats mypy's equality check; compare as Any.
        attributes: dict[str, Any] = dict(span.attributes or {})
        if span.kind == SpanKind.SERVER and attributes.get("jsonrpc.request.id") == request_id:
            matches.append(span)
    assert len(matches) == 1, f"expected one server span for {request_id}, found {len(matches)}"
    return matches[0]


CALLS: list[tuple[str, str, dict[str, Any], str]] = [
    ("workspace", "tools/call", {"name": "read_doc", "arguments": {"doc_id": "report-q3"}}, "forwarded"),
    ("workspace", "tools/call", {"name": "send_email", "arguments": {"to": "x@evil.example"}}, "denied"),
    ("workspace", "resources/read", {"uri": "workspace://documents"}, "forwarded"),
    ("workspace", "prompts/get", {"name": "leak_everything", "arguments": {}}, "denied"),
    (
        "finance",
        "tools/call",
        {"name": "get_balance", "arguments": {"account_id": "ACC-OPERATING"}},
        "forwarded",
    ),
    ("finance", "tools/call", {"name": "transfer_funds", "arguments": {"amount": "18450.00"}}, "denied"),
]


@pytest.mark.parametrize("era", ["stateless", "handshake"])
async def test_every_call_has_a_trace_and_a_verifiable_audit_row(observed: Observed, era: str) -> None:
    sent: list[tuple[str, str]] = []
    async with httpx2.AsyncClient() as http:
        sessions: dict[str, RawSession] = {}
        for upstream, method, params, expected in CALLS:
            if upstream not in sessions:
                sessions[upstream] = RawSession(
                    http, observed.gateway.url(upstream), mint("ap-agent"), modern=era == "stateless"
                )
                await sessions[upstream].open()
            extra = {"mcp-param-account": "ACC-OPERATING"} if params.get("name") == "get_balance" else None
            request_id, response = await sessions[upstream].request(method, params, extra_headers=extra)
            assert response.status_code == 200
            assert answer_of(response) is not None
            sent.append((request_id, expected))

    def complete(events: list[dict[str, Any]]) -> bool:
        requests = {e["jsonrpc_id"]: e for e in events if e["type"] == "request"}
        results = {e["request"] for e in events if e["type"] == "result"}
        return all(
            rid in requests and (expected == "denied" or requests[rid]["id"] in results)
            for rid, expected in sent
        )

    events = await eventually(observed.dsn, observed.chain, complete)
    requests = {e["jsonrpc_id"]: e for e in events if e["type"] == "request"}
    results = {e["request"]: e for e in events if e["type"] == "result"}
    for request_id, expected in sent:
        span = server_span(observed.spans, request_id)
        row = requests[request_id]
        assert row["decision"] == expected
        assert row["agent"] == "ap-agent"
        assert row["trace_id"] == format(span.context.trace_id, "032x")
        assert span.attributes["customs.decision"] == expected
        if expected == "forwarded":
            assert results[row["id"]]["outcome"] in ("ok", "tool_error")
            assert results[row["id"]]["trace_id"] == row["trace_id"]
        else:
            assert row["id"] not in results
            assert row["stage"] == "policy"

    (report,) = await verify_database(observed.dsn, Hasher(AUDIT_KEY.encode()), observed.chain)
    assert report.ok, report.problem


async def test_spans_follow_the_semantic_conventions(observed: Observed) -> None:
    observed.spans.clear()
    async with httpx2.AsyncClient() as http:
        session = RawSession(http, observed.gateway.url("workspace"), mint("ap-agent"), modern=True)
        request_id, _ = await session.request(
            "tools/call", {"name": "read_doc", "arguments": {"doc_id": "x"}}
        )

    span = server_span(observed.spans, request_id)
    assert span.name == "tools/call read_doc"
    assert span.instrumentation_scope is not None
    assert span.instrumentation_scope.schema_url == SCHEMA_URL
    attributes = dict(span.attributes or {})
    assert {
        key: attributes[key] for key in ("mcp.method.name", "gen_ai.operation.name", "gen_ai.tool.name")
    } == {
        "mcp.method.name": "tools/call",
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": "read_doc",
    }
    assert attributes["mcp.protocol.version"] == "2026-07-28"
    assert attributes["customs.agent"] == "ap-agent"
    assert attributes["http.response.status_code"] == 200

    children = [s for s in observed.spans.in_trace(span.context.trace_id) if s.parent == span.context]
    stage = next(s for s in children if s.name == "stage policy")
    assert stage.attributes is not None
    assert stage.attributes["customs.policy.decision"] == "allow"
    assert stage.attributes["customs.policy.rule"] == "ap-read-documents"
    upstream = next(s for s in children if s.kind is SpanKind.CLIENT)
    assert upstream.name == "POST workspace"
    assert upstream.attributes is not None
    assert upstream.attributes["http.response.status_code"] == 200


async def test_the_gateway_joins_the_callers_trace(observed: Observed) -> None:
    trace_id, caller_span = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
    traceparent = f"00-{trace_id}-{caller_span}-01"
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "traceparent": traceparent,
    }
    body = {
        "jsonrpc": "2.0",
        "id": "joined-1",
        "method": "tools/call",
        "params": {"name": "search_docs", "arguments": {"query": "invoice"}, "_meta": meta},
    }
    headers = {
        "accept": "application/json, text/event-stream",
        "authorization": f"Bearer {mint('ap-agent')}",
        "mcp-protocol-version": "2026-07-28",
        "mcp-method": "tools/call",
        "mcp-name": "search_docs",
    }
    async with httpx2.AsyncClient() as http:
        await http.post(observed.gateway.url("workspace"), json=body, headers=headers)

    span = server_span(observed.spans, "joined-1")
    assert format(span.context.trace_id, "032x") == trace_id
    assert span.parent is not None
    assert format(span.parent.span_id, "016x") == caller_span

    upstream_span = next(
        s
        for s in observed.spans.in_trace(span.context.trace_id)
        if s.kind is SpanKind.CLIENT and s.parent == span.context
    )
    seen = observed.recorders["workspace"].headers_for("joined-1")
    assert seen["traceparent"].split("-")[1:3] == [trace_id, format(upstream_span.context.span_id, "016x")]
    forwarded = next(
        b
        for _, b in observed.recorders["workspace"].received
        if isinstance(b, dict) and b.get("id") == "joined-1"
    )
    assert forwarded["params"]["_meta"]["traceparent"] == traceparent  # the body is not rewritten


async def test_denied_calls_never_open_an_upstream_span(observed: Observed) -> None:
    async with httpx2.AsyncClient() as http:
        session = RawSession(http, observed.gateway.url("finance"), mint("ap-agent"), modern=True)
        request_id, _ = await session.request("tools/call", {"name": "transfer_funds", "arguments": {}})
    span = server_span(observed.spans, request_id)
    assert span.attributes is not None
    assert span.attributes["customs.decision"] == "denied"
    assert not [s for s in observed.spans.in_trace(span.context.trace_id) if s.kind is SpanKind.CLIENT]


async def test_rejected_requests_are_traced_and_audited(observed: Observed) -> None:
    marker = uuid.uuid4().hex
    async with httpx2.AsyncClient() as http:
        response = await http.post(
            observed.gateway.url("workspace"),
            json={"jsonrpc": "2.0", "id": marker, "method": "tools/list"},
            headers={"accept": "application/json", "authorization": "Bearer forged.token.value"},
        )
    assert response.status_code == 401
    events = await eventually(
        observed.dsn,
        observed.chain,
        lambda evs: any(e["type"] == "rejected" and "Malformed token" in e.get("reason", "") for e in evs),
    )
    rejected = [e for e in events if e["type"] == "rejected"][-1]
    assert rejected["http_status"] == 401
    assert rejected["client"].startswith("127.0.0.1:")
    failed = [
        s
        for s in observed.spans.spans
        if s.status.status_code is StatusCode.ERROR and s.name == "POST /mcp/workspace"
    ]
    assert failed


async def test_arguments_are_digested_not_stored(observed: Observed) -> None:
    arguments = {"doc_id": "policy-payments"}
    async with httpx2.AsyncClient() as http:
        session = RawSession(http, observed.gateway.url("workspace"), mint("ap-agent"), modern=True)
        request_id, _ = await session.request("tools/call", {"name": "read_doc", "arguments": arguments})
    events = await eventually(
        observed.dsn, observed.chain, lambda evs: any(e.get("jsonrpc_id") == request_id for e in evs)
    )
    row = next(e for e in events if e.get("jsonrpc_id") == request_id)
    assert row["arguments_sha256"] == sha256_of(arguments)
    assert "arguments" not in row


async def test_durable_audit_refuses_calls_it_cannot_record(workspace_url: str) -> None:
    recorder = Recorder(http_app(workspace_server.build_server(), json_response=False))
    store = MemoryAuditStore()
    with serve_in_thread(recorder) as ws:
        config = make_config(
            {"workspace": f"{ws}/mcp"},
            audit={"dsn": "postgresql://unused", "chain": "outage", "commit_timeout_s": 0.2},
        )
        with running_gateway(config, audit_store=store) as gateway:
            store.fail_appends = 10**9
            async with httpx2.AsyncClient() as http:
                session = RawSession(http, gateway.url("workspace"), None, modern=True)
                request_id, response = await session.request(
                    "tools/call", {"name": "read_doc", "arguments": {"doc_id": "x"}}
                )
                ready = await http.get(f"{gateway.base}/readyz")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == jsonrpc.AUDIT_UNAVAILABLE
    assert not recorder.saw(request_id)
    assert ready.status_code == 503
