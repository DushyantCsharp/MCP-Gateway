"""On the wire, the gateway forwards exactly what it was given and returns exactly what came back.

These tests speak raw HTTP so they can compare bytes, not parsed models.
"""

import json
from typing import Any

import httpx2
import pytest
from mcp_types.version import LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION

from mcp_customs.proxy.sse import SseParser
from tests.contract.conftest import Gateway

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

META = {
    "io.modelcontextprotocol/protocolVersion": LATEST_MODERN_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}
ACCEPT = "application/json, text/event-stream"


def modern_call(request_id: int, tool: str, arguments: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments, "_meta": META},
    }
    headers = {
        "accept": ACCEPT,
        "content-type": "application/json",
        "mcp-protocol-version": LATEST_MODERN_VERSION,
        "mcp-method": "tools/call",
        "mcp-name": tool,
    }
    return json.dumps(body).encode(), headers


async def test_json_response_bytes_are_identical(gateway: Gateway, finance_url: str) -> None:
    body, headers = modern_call(7, "list_transactions", {"account_id": "ACC-OPERATING", "limit": 3})
    async with httpx2.AsyncClient() as http:
        direct = await http.post(finance_url, content=body, headers=headers)
        proxied = await http.post(gateway.url("finance"), content=body, headers=headers)
    assert direct.status_code == proxied.status_code == 200
    assert proxied.headers["content-type"] == direct.headers["content-type"]
    assert proxied.content == direct.content


async def test_sse_events_are_relayed_unchanged(gateway: Gateway, workspace_url: str) -> None:
    body, headers = modern_call(8, "reindex", {})
    payload = json.loads(body)
    payload["params"]["_meta"] = {**META, "progressToken": "p1"}
    body = json.dumps(payload).encode()

    async def event_data(url: str) -> list[str]:
        parser = SseParser()
        seen: list[str] = []
        async with (
            httpx2.AsyncClient() as http,
            http.stream("POST", url, content=body, headers=headers) as resp,
        ):
            assert resp.headers["content-type"].startswith("text/event-stream")
            async for chunk in resp.aiter_bytes():
                seen.extend(event.data for event in parser.feed(chunk) if event.data is not None)
        return seen

    direct = await event_data(workspace_url)
    proxied = await event_data(gateway.url("workspace"))
    assert len(direct) == 7  # six progress notifications, then the result
    assert proxied == direct


async def test_legacy_session_lifecycle_passes_through(gateway: Gateway) -> None:
    url = gateway.url("workspace")
    base = {"accept": ACCEPT, "content-type": "application/json"}
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_HANDSHAKE_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "raw", "version": "0"},
        },
    }
    async with httpx2.AsyncClient() as http:
        resp = await http.post(url, json=initialize, headers=base)
        assert resp.status_code == 200
        session = resp.headers["mcp-session-id"]
        headers = {**base, "mcp-session-id": session, "mcp-protocol-version": LATEST_HANDSHAKE_VERSION}

        notified = await http.post(
            url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers
        )
        assert notified.status_code == 202

        async with http.stream("GET", url, headers={**headers, "accept": "text/event-stream"}) as stream:
            assert stream.status_code == 200
            assert stream.headers["content-type"].startswith("text/event-stream")

        assert (await http.delete(url, headers=headers)).status_code == 200

        after = await http.post(
            url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=headers
        )
        assert after.status_code == 404


async def test_client_credentials_stop_at_the_gateway(gateway: Gateway) -> None:
    """Authorization and cookies are not passed through; configured upstream headers are injected."""
    async with httpx2.AsyncClient() as http:
        resp = await http.post(
            gateway.url("rogue"),
            json={"jsonrpc": "2.0", "id": 1, "method": "rogue/echo_headers"},
            headers={
                "authorization": "Bearer client-token",
                "cookie": "session=client-cookie",
                "x-forwarded-for": "203.0.113.9",
                "x-upstream-token": "client-tries-to-set-this",
                "mcp-session-id": "abc",
                "x-custom": "kept",
                "connection": "keep-alive, x-hop",
                "x-hop": "dropped because Connection names it",
            },
        )
    seen = dict(resp.json()["result"]["headers"])
    assert "authorization" not in seen
    assert "cookie" not in seen
    assert "x-forwarded-for" not in seen
    assert "x-hop" not in seen
    assert seen["x-upstream-token"] == "token-from-gateway-config"
    assert seen["mcp-session-id"] == "abc"
    assert seen["x-custom"] == "kept"
    assert seen["accept-encoding"] == "identity"


async def test_repeated_response_headers_survive(gateway: Gateway) -> None:
    async with httpx2.AsyncClient() as http:
        resp = await http.post(
            gateway.url("rogue"), json={"jsonrpc": "2.0", "id": 1, "method": "rogue/repeated_headers"}
        )
    assert resp.headers.get_list("x-trace") == ["one", "two"]
