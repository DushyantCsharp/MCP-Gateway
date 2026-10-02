"""A real MCP client sees no difference between a server and the same server behind the gateway.

Every test runs twice: once negotiating the stateless 2026-07-28 revision and
once over the handshake-era session transport. The workspace server answers
with SSE framing and the finance server with plain JSON, so both relay paths
are covered in both eras.
"""

from typing import Any

import pytest
from mcp import Client, MCPError
from mcp_types import CallToolResult
from mcp_types.version import LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION

from tests.contract.conftest import Gateway

pytestmark = [pytest.mark.anyio, pytest.mark.contract]


def outcome(result: CallToolResult) -> tuple[bool, Any, Any]:
    return result.is_error, [block.model_dump() for block in result.content], result.structured_content


async def test_negotiates_the_same_protocol_revision(mode: str, gateway: Gateway, workspace_url: str) -> None:
    expected = LATEST_MODERN_VERSION if mode == "auto" else LATEST_HANDSHAKE_VERSION
    async with (
        Client(workspace_url, mode=mode) as direct,
        Client(gateway.url("workspace"), mode=mode) as proxied,
    ):
        assert direct.session.protocol_version == expected
        assert proxied.session.protocol_version == expected


@pytest.mark.parametrize("upstream", ["workspace", "finance"])
async def test_tool_listing_is_identical(
    mode: str, upstream: str, gateway: Gateway, direct_urls: dict[str, str]
) -> None:
    async with (
        Client(direct_urls[upstream], mode=mode) as direct,
        Client(gateway.url(upstream), mode=mode) as proxied,
    ):
        assert (await proxied.list_tools()) == (await direct.list_tools())


@pytest.mark.parametrize(
    ("upstream", "tool", "arguments"),
    [
        ("workspace", "search_docs", {"query": "invoice northwind"}),
        ("workspace", "read_doc", {"doc_id": "policy-payments"}),
        ("workspace", "read_doc", {"doc_id": "does-not-exist"}),
        ("finance", "get_balance", {"account_id": "ACC-OPERATING"}),
        ("finance", "list_transactions", {"account_id": "ACC-OPERATING", "limit": 2}),
        ("finance", "get_balance", {"account_id": "ACC-UNKNOWN"}),
    ],
)
async def test_tool_calls_return_identical_results(
    mode: str,
    upstream: str,
    tool: str,
    arguments: dict[str, Any],
    gateway: Gateway,
    direct_urls: dict[str, str],
) -> None:
    async with (
        Client(direct_urls[upstream], mode=mode) as direct,
        Client(gateway.url(upstream), mode=mode) as proxied,
    ):
        await direct.list_tools()
        await proxied.list_tools()
        assert outcome(await proxied.call_tool(tool, arguments)) == outcome(
            await direct.call_tool(tool, arguments)
        )


async def test_tool_errors_reach_the_client_as_tool_errors(mode: str, gateway: Gateway) -> None:
    async with Client(gateway.url("workspace"), mode=mode) as client:
        result = await client.call_tool("read_doc", {"doc_id": "does-not-exist"})
    assert result.is_error
    assert "No document with id 'does-not-exist'" in str(result.content)


async def test_protocol_errors_are_identical(mode: str, gateway: Gateway, workspace_url: str) -> None:
    errors: list[tuple[int, str]] = []
    for url in (workspace_url, gateway.url("workspace")):
        async with Client(url, mode=mode) as client:
            try:
                result = await client.call_tool("no_such_tool", {})
            except MCPError as exc:
                errors.append((exc.code, exc.message))
            else:
                errors.append((-1, str(result.content)))
    assert errors[0] == errors[1]


async def test_progress_notifications_stream_through(mode: str, gateway: Gateway, workspace_url: str) -> None:
    seen: dict[str, list[tuple[float, float | None, str | None]]] = {}
    for label, url in (("direct", workspace_url), ("proxied", gateway.url("workspace"))):
        updates: list[tuple[float, float | None, str | None]] = []

        async def on_progress(
            progress: float,
            total: float | None,
            message: str | None,
            updates: list[tuple[float, float | None, str | None]] = updates,
        ) -> None:
            updates.append((progress, total, message))

        async with Client(url, mode=mode) as client:
            result = await client.call_tool("reindex", {}, progress_callback=on_progress)
        assert not result.is_error
        seen[label] = updates
    assert len(seen["direct"]) == 6
    assert seen["proxied"] == seen["direct"]


async def test_resources_and_prompts_pass_through(mode: str, gateway: Gateway, workspace_url: str) -> None:
    async with (
        Client(workspace_url, mode=mode) as direct,
        Client(gateway.url("workspace"), mode=mode) as proxied,
    ):
        assert (await proxied.list_resources()) == (await direct.list_resources())
        index_direct = await direct.read_resource("workspace://documents")
        assert (await proxied.read_resource("workspace://documents")) == index_direct
        assert (await proxied.list_prompts()) == (await direct.list_prompts())
        prompt = await proxied.get_prompt("summarise_document", {"doc_id": "report-q3"})
        assert prompt == await direct.get_prompt("summarise_document", {"doc_id": "report-q3"})


async def test_mcp_param_headers_reach_the_upstream(gateway: Gateway) -> None:
    """``get_balance`` declares ``x-mcp-header``; the upstream refuses calls whose header is missing."""
    async with Client(gateway.url("finance"), mode="auto") as client:
        await client.list_tools()
        result = await client.call_tool("get_balance", {"account_id": "ACC-PAYROLL"})
    assert not result.is_error
    assert result.structured_content == {
        "account_id": "ACC-PAYROLL",
        "available": "120000.00",
        "currency": "USD",
    }
