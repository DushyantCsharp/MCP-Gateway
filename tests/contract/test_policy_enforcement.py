"""Weekend 2 "done when": deterministic tests show 100% of disallowed calls blocked.

The gateway runs with authentication and the example finance policy in front
of the real sample servers, each wrapped in a recorder. A call counts as
blocked only if the upstream never received it: the gateway's own report is
not trusted. Every case in the shared decision table is sent in both protocol
eras, then a few hundred generated transfers are fuzzed through as well.

A call the policy sends for approval must not arrive either: it must be held,
answered with a resumable stream and nothing else. Nobody approves it here.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
import pytest
from hypothesis import given, settings
from mcp import MCPError
from mcp_types.version import LATEST_MODERN_VERSION

from customs_demo import finance_server, workspace_server
from customs_demo._serve import http_app
from mcp_customs import jsonrpc
from mcp_customs.approvals import TOKEN_PREFIX, MemoryApprovalStore
from mcp_customs.policy import Effect, TargetKind
from mcp_customs.proxy.sse import SseParser
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.clients import (
    TEST_AUDIENCE,
    TEST_SECRET,
    RawSession,
    answer_of,
    mcp_client,
    mint,
    token_for,
)
from tests.support.finance_cases import (
    AP,
    AUDITOR,
    FINANCE_CASES,
    INTRUDER,
    Case,
    author_intends,
    transfer,
    transfer_arguments,
)
from tests.support.recorder import Recorder
from tests.support.servers import serve_in_thread

pytestmark = [pytest.mark.contract]

POLICY = Path(__file__).parents[2] / "policies" / "examples" / "finance-agent.yaml"
METHODS = {
    TargetKind.TOOL: "tools/call",
    TargetKind.PROMPT: "prompts/get",
    TargetKind.RESOURCE: "resources/read",
}


@dataclass(frozen=True)
class Enforced:
    gateway: Gateway
    recorders: dict[str, Recorder]
    upstream_urls: dict[str, str]


@pytest.fixture(scope="module")
def enforced() -> Iterator[Enforced]:
    recorders = {
        "workspace": Recorder(http_app(workspace_server.build_server(), json_response=False)),
        "finance": Recorder(http_app(finance_server.build_server(), json_response=True)),
    }
    with serve_in_thread(recorders["workspace"]) as ws, serve_in_thread(recorders["finance"]) as fin:
        urls = {"workspace": f"{ws}/mcp", "finance": f"{fin}/mcp"}
        config = make_config(
            urls,
            auth={"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}},
            stages=[{"type": "policy", "file": str(POLICY)}],
            # Held calls answer with a short stream, so the table runs quickly; nobody decides them.
            approvals={"dsn": "postgresql://unused", "stream_s": 0.1, "max_pending_per_agent": 10_000},
        )
        with running_gateway(config, approval_store=MemoryApprovalStore()) as gateway:
            yield Enforced(gateway, recorders, urls)


def call_params(case: Case) -> tuple[str, dict[str, Any], dict[str, str]]:
    method = METHODS[case.kind]
    params: dict[str, Any] = {"uri": case.name} if case.kind is TargetKind.RESOURCE else {"name": case.name}
    if case.arguments is not None:
        params["arguments"] = case.arguments
    extra: dict[str, str] = {}
    if case.name == "get_balance" and isinstance(account := (case.arguments or {}).get("account_id"), str):
        extra["mcp-param-account"] = account  # the tool's x-mcp-header, which modern servers require
    return method, params, extra


def is_held(response: httpx2.Response) -> bool:
    """A stream that opens with a resume token and carries no answer."""
    if not response.headers.get("content-type", "").startswith("text/event-stream"):
        return False
    events = list(SseParser().feed(response.content))
    first_id = events[0].id if events else None
    return bool(first_id and first_id.startswith(TOKEN_PREFIX)) and answer_of(response) is None


def is_policy_denial(answer: Any) -> bool:
    if not isinstance(answer, dict):
        return False
    if "error" in answer:
        return bool(answer["error"]["code"] in (jsonrpc.POLICY_DENIED, jsonrpc.UNAUTHENTICATED))
    result = answer.get("result", {})
    text = " ".join(block.get("text", "") for block in result.get("content", []))
    return bool(result.get("isError")) and text.startswith("Blocked by gateway policy")


@pytest.mark.anyio
@pytest.mark.parametrize("era", ["stateless", "handshake"])
async def test_every_disallowed_call_is_blocked_and_every_allowed_call_arrives(
    enforced: Enforced, era: str
) -> None:
    leaked: list[str] = []
    wrongly_blocked: list[str] = []
    async with httpx2.AsyncClient() as http:
        sessions: dict[tuple[str, str | None], RawSession] = {}
        for case in FINANCE_CASES:
            key = (case.upstream, case.identity.agent if case.identity else None)
            if key not in sessions:
                session = RawSession(
                    http,
                    enforced.gateway.url(case.upstream),
                    token_for(case.identity),
                    modern=era == "stateless",
                )
                await session.open()
                sessions[key] = session
            method, params, extra = call_params(case)
            request_id, response = await sessions[key].request(method, params, extra_headers=extra)
            arrived = enforced.recorders[case.upstream].saw(request_id)
            denied = response.status_code == 401 or is_policy_denial(answer_of(response))
            held = is_held(response)

            match case.expected:
                case Effect.DENY if arrived or not denied:
                    leaked.append(f"{case.label}: arrived={arrived}, denied={denied}")
                case Effect.APPROVE if arrived or not held:
                    leaked.append(f"{case.label}: arrived={arrived}, held={held}")
                case Effect.ALLOW if not arrived or denied or held:
                    wrongly_blocked.append(f"{case.label}: arrived={arrived}, HTTP {response.status_code}")
                case _:
                    pass

    disallowed = sum(case.expected is not Effect.ALLOW for case in FINANCE_CASES)
    held_count = sum(case.expected is Effect.APPROVE for case in FINANCE_CASES)
    print(
        f"\n[{era}] {disallowed} disallowed calls ({held_count} held for approval), "
        f"{disallowed - len(leaked)} blocked; "
        f"{len(FINANCE_CASES) - disallowed} allowed calls, {len(wrongly_blocked)} wrongly blocked"
    )
    assert leaked == []
    assert wrongly_blocked == []


FUZZ_TOKEN = mint("ap-agent", ttl=3600)


@settings(max_examples=300, deadline=None)
@given(transfer_arguments)
def test_generated_transfers_reach_the_upstream_only_when_allowed(
    enforced: Enforced, arguments: dict[str, Any]
) -> None:
    request_id = f"fuzz-{uuid.uuid4().hex}"
    meta = {
        "io.modelcontextprotocol/protocolVersion": LATEST_MODERN_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "transfer_funds", "arguments": arguments, "_meta": meta},
    }
    headers = {
        "accept": "application/json, text/event-stream",
        "authorization": f"Bearer {FUZZ_TOKEN}",
        "mcp-protocol-version": LATEST_MODERN_VERSION,
        "mcp-method": "tools/call",
        "mcp-name": "transfer_funds",
    }
    with httpx2.Client() as http:
        response = http.post(enforced.gateway.url("finance"), json=body, headers=headers)
    intended = author_intends(arguments)
    assert enforced.recorders["finance"].saw(request_id) is (intended is Effect.ALLOW)
    if intended is Effect.APPROVE:
        assert is_held(response)
    else:
        assert is_policy_denial(response.json()) is (intended is Effect.DENY)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("identity", "workspace_tools", "finance_tools"),
    [
        (
            AP,
            {"search_docs", "read_doc", "send_email"},
            {"get_balance", "list_transactions", "transfer_funds"},
        ),
        (AUDITOR, {"search_docs", "read_doc"}, {"get_balance", "list_transactions"}),
        (INTRUDER, set(), set()),
    ],
    ids=["ap-agent", "auditor", "intruder"],
)
async def test_agents_see_only_the_tools_they_may_call(
    mode: str, enforced: Enforced, identity: Any, workspace_tools: set[str], finance_tools: set[str]
) -> None:
    token = token_for(identity)
    for upstream, expected in (("workspace", workspace_tools), ("finance", finance_tools)):
        async with mcp_client(enforced.gateway.url(upstream), token=token, mode=mode) as client:
            assert {tool.name for tool in (await client.list_tools()).tools} == expected


@pytest.mark.anyio
async def test_task_scoped_tokens_narrow_the_listing(enforced: Enforced) -> None:
    token = mint("ap-agent", scope="openid mcp:workspace:read_doc")
    async with mcp_client(enforced.gateway.url("workspace"), token=token) as client:
        assert [tool.name for tool in (await client.list_tools()).tools] == ["read_doc"]
        blocked = await client.call_tool("search_docs", {"query": "invoice"})
    assert blocked.is_error
    assert "outside the scope of the caller's token" in str(blocked.content)


@pytest.mark.anyio
async def test_a_denied_payment_reads_as_a_tool_error_and_moves_nothing(
    mode: str, enforced: Enforced
) -> None:
    finance_base = enforced.upstream_urls["finance"].removesuffix("/mcp")
    async with httpx2.AsyncClient() as http:
        before = (await http.get(f"{finance_base}/transfers")).json()
    async with mcp_client(enforced.gateway.url("finance"), token=mint("ap-agent"), mode=mode) as client:
        await client.list_tools()
        result = await client.call_tool(
            "transfer_funds", transfer(amount="60000.00")
        )  # over the approval cap
    assert result.is_error
    assert str(result.content).count("Blocked by gateway policy: arguments not permitted by rule") == 1
    async with httpx2.AsyncClient() as http:
        assert (await http.get(f"{finance_base}/transfers")).json() == before


@pytest.mark.anyio
async def test_denied_resources_and_prompts_are_json_rpc_errors(mode: str, enforced: Enforced) -> None:
    async with mcp_client(enforced.gateway.url("workspace"), token=mint("ap-agent"), mode=mode) as client:
        with pytest.raises(MCPError) as resource:
            await client.read_resource("workspace://secrets")
        with pytest.raises(MCPError) as prompt:
            await client.get_prompt("leak_everything", {})
    assert resource.value.code == prompt.value.code == jsonrpc.POLICY_DENIED


@pytest.mark.anyio
async def test_the_scripted_agent_still_completes_its_task(mode: str, enforced: Enforced) -> None:
    from customs_demo.agent import run_task

    report = await run_task(
        enforced.gateway.url("workspace"), enforced.gateway.url("finance"), mode=mode, token=mint("ap-agent")
    )
    assert report.invoice_id == "inv-2026-091"
