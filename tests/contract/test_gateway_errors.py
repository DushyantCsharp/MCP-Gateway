"""What the gateway refuses, and how it reports failures it cannot fix."""

import json
from typing import Any

import anyio
import httpx2
import pytest
from mcp import Client, MCPError
from mcp_types.version import LATEST_MODERN_VERSION

from mcp_customs import jsonrpc
from mcp_customs.proxy.sse import SseParser
from tests.contract.conftest import ALLOWED_ORIGIN, Gateway, make_config, running_gateway
from tests.support.rogue import RogueState

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

ACCEPT = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def rpc(method: str, request_id: int | None = 1, **params: Any) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params:
        message["params"] = params
    return message


async def post(
    url: str, body: bytes | dict[str, Any], headers: dict[str, str] | None = None
) -> httpx2.Response:
    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    async with httpx2.AsyncClient() as http:
        return await http.post(url, content=content, headers={**ACCEPT, **(headers or {})})


def error_of(response: httpx2.Response) -> tuple[Any, int]:
    payload = response.json()
    return payload["id"], payload["error"]["code"]


# -- client input the gateway refuses -------------------------------------------------------------


async def test_unknown_upstream_is_404(gateway: Gateway) -> None:
    resp = await post(gateway.url("nope"), rpc("tools/list"))
    assert resp.status_code == 404
    assert error_of(resp) == (None, jsonrpc.INVALID_REQUEST)


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b'{"jsonrpc": "2.0", "id": 1, "method": ', jsonrpc.PARSE_ERROR),
        (b"\xff\xfe not utf-8", jsonrpc.PARSE_ERROR),
        (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_doc","name":"send_email"}}',
            jsonrpc.PARSE_ERROR,
        ),
        (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"limit":NaN}}', jsonrpc.PARSE_ERROR),
        (b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"1.0","id":1,"method":"tools/list"}', jsonrpc.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":true,"method":"tools/list"}', jsonrpc.INVALID_REQUEST),
    ],
    ids=["truncated", "not-utf8", "duplicate-keys", "nan", "batch", "wrong-version", "bool-id"],
)
async def test_malformed_messages_are_refused(gateway: Gateway, body: bytes, code: int) -> None:
    resp = await post(gateway.url("workspace"), body)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == code


async def test_oversized_bodies_are_refused(workspace_url: str) -> None:
    config = make_config({"workspace": workspace_url}, limits={"max_request_bytes": 512})
    with running_gateway(config) as gw:
        resp = await post(
            gw.url("workspace"), rpc("tools/call", name="read_doc", arguments={"doc_id": "x" * 600})
        )
    assert resp.status_code == 413


async def test_foreign_browser_origins_are_refused(gateway: Gateway) -> None:
    refused = await post(gateway.url("rogue"), rpc("rogue/echo_headers"), {"origin": "http://evil.example"})
    assert refused.status_code == 403
    allowed = await post(gateway.url("rogue"), rpc("rogue/echo_headers"), {"origin": ALLOWED_ORIGIN})
    assert allowed.status_code == 200
    seen = dict(allowed.json()["result"]["headers"])
    assert "origin" not in seen


MODERN = {"mcp-protocol-version": LATEST_MODERN_VERSION}
META = {
    "io.modelcontextprotocol/protocolVersion": LATEST_MODERN_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


@pytest.mark.parametrize(
    "headers",
    [
        {**MODERN, "mcp-method": "tools/list", "mcp-name": "read_doc"},
        {**MODERN, "mcp-method": "tools/call", "mcp-name": "search_docs"},
        {**MODERN, "mcp-method": "tools/call"},
        {"mcp-protocol-version": "2025-11-25", "mcp-method": "tools/call", "mcp-name": "search_docs"},
    ],
    ids=["method-differs", "name-differs", "name-missing", "legacy-but-inconsistent"],
)
async def test_routing_headers_must_match_the_body(gateway: Gateway, headers: dict[str, str]) -> None:
    body = rpc("tools/call", 5, name="read_doc", arguments={"doc_id": "report-q3"}, _meta=META)
    resp = await post(gateway.url("workspace"), body, headers)
    assert resp.status_code == 400
    assert error_of(resp) == (5, jsonrpc.HEADER_MISMATCH)


async def test_duplicated_routing_headers_are_refused(gateway: Gateway) -> None:
    body = json.dumps(rpc("tools/call", 6, name="read_doc", arguments={}, _meta=META)).encode()
    headers = [
        *ACCEPT.items(),
        ("mcp-protocol-version", LATEST_MODERN_VERSION),
        ("mcp-method", "tools/call"),
        ("mcp-name", "read_doc"),
        ("mcp-name", "send_email"),
    ]
    async with httpx2.AsyncClient() as http:
        resp = await http.post(gateway.url("workspace"), content=body, headers=headers)
    assert resp.status_code == 400
    assert error_of(resp) == (6, jsonrpc.HEADER_MISMATCH)


async def test_base64_encoded_names_are_decoded_before_comparison(gateway: Gateway) -> None:
    body = rpc("tools/call", 9, name="read_doc", arguments={"doc_id": "report-q3"}, _meta=META)
    headers = {**MODERN, "mcp-method": "tools/call", "mcp-name": "=?base64?cmVhZF9kb2M=?="}
    resp = await post(gateway.url("workspace"), body, headers)
    assert resp.status_code == 200
    assert resp.json()["result"]["isError"] is False


# -- upstream failures the gateway reports ---------------------------------------------------------


async def test_unreachable_upstream_is_a_json_rpc_error(gateway: Gateway) -> None:
    resp = await post(gateway.url("dead"), rpc("tools/list", 3))
    assert resp.status_code == 502
    assert error_of(resp) == (3, jsonrpc.UPSTREAM_UNAVAILABLE)


async def test_unreachable_upstream_surfaces_to_the_sdk_client(gateway: Gateway) -> None:
    async with Client(gateway.url("dead"), mode=LATEST_MODERN_VERSION) as client:
        with pytest.raises(MCPError) as caught:
            await client.list_tools()
    assert caught.value.code == jsonrpc.UPSTREAM_UNAVAILABLE


@pytest.mark.parametrize(
    "method",
    ["rogue/invalid_json", "rogue/duplicate_keys", "rogue/wrong_id", "rogue/not_jsonrpc"],
)
async def test_invalid_upstream_answers_are_withheld(gateway: Gateway, method: str) -> None:
    resp = await post(gateway.url("rogue"), rpc(method, 4))
    assert resp.status_code == 502
    assert error_of(resp) == (4, jsonrpc.UPSTREAM_BAD_RESPONSE)


async def test_upstream_http_error_documents_pass_through(gateway: Gateway) -> None:
    resp = await post(gateway.url("rogue"), rpc("rogue/http_error_document"))
    assert resp.status_code == 400
    assert resp.json() == {"detail": "upstream says no"}


async def test_oversized_upstream_answers_are_withheld(rogue_url: str) -> None:
    config = make_config({"rogue": rogue_url}, limits={"max_response_bytes": 1024})
    with running_gateway(config) as gw:
        resp = await post(gw.url("rogue"), rpc("rogue/too_large", 2))
    assert resp.status_code == 502
    assert error_of(resp) == (2, jsonrpc.UPSTREAM_BAD_RESPONSE)


async def sse_messages(url: str, body: dict[str, Any]) -> list[Any]:
    parser = SseParser()
    raw: list[bytes] = []
    messages: list[Any] = []
    async with httpx2.AsyncClient() as http, http.stream("POST", url, json=body, headers=ACCEPT) as resp:
        async for chunk in resp.aiter_bytes():
            for event in parser.feed(chunk):
                raw.append(event.raw)
                if event.data is not None:
                    messages.append(json.loads(event.data))
    return messages


async def test_a_truncated_event_stream_still_answers_the_request(gateway: Gateway) -> None:
    messages = await sse_messages(gateway.url("rogue"), rpc("rogue/sse_truncated", 11))
    assert messages == [
        jsonrpc.error_object(11, jsonrpc.UPSTREAM_BAD_RESPONSE, messages[0]["error"]["message"])
    ]


async def test_a_stream_whose_only_answer_was_dropped_still_answers(gateway: Gateway) -> None:
    messages = await sse_messages(gateway.url("rogue"), rpc("rogue/sse_garbage_only", 14))
    assert [(m["id"], m["error"]["code"]) for m in messages] == [(14, jsonrpc.UPSTREAM_BAD_RESPONSE)]


@pytest.mark.parametrize("method", ["rogue/sse_garbage_then_answer", "rogue/sse_wrong_id_then_answer"])
async def test_invalid_stream_events_are_dropped(gateway: Gateway, method: str) -> None:
    messages = await sse_messages(gateway.url("rogue"), rpc(method, 12))
    assert messages == [{"jsonrpc": "2.0", "id": 12, "result": {"ok": True}}]


async def test_keepalive_comments_are_relayed(gateway: Gateway) -> None:
    async with (
        httpx2.AsyncClient() as http,
        http.stream(
            "POST", gateway.url("rogue"), json=rpc("rogue/sse_ping_then_answer", 13), headers=ACCEPT
        ) as resp,
    ):
        body = b"".join([chunk async for chunk in resp.aiter_bytes()])
    assert body.startswith(b": ping\r\n\r\n")
    assert body.endswith(b'"result": {"ok": true}}\r\n\r\n')


async def test_server_initiated_streams_are_relayed(gateway: Gateway) -> None:
    async with (
        httpx2.AsyncClient() as http,
        http.stream("GET", gateway.url("rogue"), headers={"accept": "text/event-stream"}) as resp,
    ):
        body = b"".join([chunk async for chunk in resp.aiter_bytes()])
    assert resp.status_code == 200
    assert b'"method": "notifications/message"' in body


async def test_health_endpoint(gateway: Gateway) -> None:
    async with httpx2.AsyncClient() as http:
        resp = await http.get(f"{gateway.base}/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_a_client_disconnect_closes_the_upstream_stream(gateway: Gateway) -> None:
    """An abandoned stream must not pin an upstream connection open."""
    RogueState.held_stream_closed.clear()
    headers = {"accept": "text/event-stream", "x-rogue": "hold"}
    async with (
        httpx2.AsyncClient() as http,
        http.stream("GET", gateway.url("rogue"), headers=headers) as resp,
    ):
        first = await anext(resp.aiter_bytes())
        assert b"held" in first
        assert not RogueState.held_stream_closed.is_set()
    assert await anyio.to_thread.run_sync(RogueState.held_stream_closed.wait, 5)
