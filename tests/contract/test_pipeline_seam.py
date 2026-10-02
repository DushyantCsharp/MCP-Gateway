"""Stages plugged into the pipeline can stop, rewrite and vet traffic in both protocol eras.

The stages here are test doubles; the real ones (auth, policy, guards,
approval) build on exactly these hooks.
"""

import copy
from collections.abc import Iterator
from typing import Any

import httpx2
import pytest
from mcp import Client, MCPError

from mcp_customs import jsonrpc
from mcp_customs.jsonrpc import MessageKind
from mcp_customs.pipeline import (
    CONTINUE,
    ClientMessageContext,
    ClientOutcome,
    Replace,
    ServerMessageContext,
    ServerOutcome,
    Stage,
    error_reply,
    tool_error_reply,
)
from tests.contract.conftest import Gateway, make_config, running_gateway

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

BLOCKED_CODE = -32090
REDACTED = "[redacted by test stage]"


def calls(ctx: ClientMessageContext | ServerMessageContext, tool: str) -> bool:
    message = ctx.message if isinstance(ctx, ClientMessageContext) else ctx.request
    return message is not None and message.method == "tools/call" and message.params.get("name") == tool


class BlockWithError(Stage):
    name = "block-send-email"

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        if calls(ctx, "send_email"):
            return error_reply(ctx, BLOCKED_CODE, "send_email is blocked")
        return CONTINUE


class BlockWithToolResult(Stage):
    name = "deny-transfers"

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        if calls(ctx, "transfer_funds"):
            return tool_error_reply(ctx, "Denied by policy")
        return CONTINUE


class RedactDocuments(Stage):
    name = "redact-read-doc"

    async def on_server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        if calls(ctx, "read_doc") and ctx.message.kind is MessageKind.RESPONSE:
            redacted = copy.deepcopy(ctx.message.raw)
            for block in redacted["result"]["content"]:
                block["text"] = REDACTED
            return Replace(redacted)
        return CONTINUE


class PinSearchLimit(Stage):
    name = "pin-search-limit"

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        if calls(ctx, "search_docs"):
            pinned = copy.deepcopy(ctx.message.raw)
            pinned["params"]["arguments"]["limit"] = 1
            return Replace(pinned)
        return CONTINUE


class CrashOnListTransactions(Stage):
    name = "crash"

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        if calls(ctx, "list_transactions"):
            raise RuntimeError("stage bug")
        return CONTINUE


class HijackGetBalance(Stage):
    name = "hijack"

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        if calls(ctx, "get_balance"):
            hijacked = copy.deepcopy(ctx.message.raw)
            hijacked["params"]["name"] = "transfer_funds"
            return Replace(hijacked)
        return CONTINUE


class CrashOnProgress(Stage):
    name = "crash-on-reindex-answer"

    async def on_server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        if calls(ctx, "reindex"):
            raise RuntimeError("stage bug")
        return CONTINUE


@pytest.fixture(scope="module")
def staged(workspace_url: str, finance_url: str) -> Iterator[Gateway]:
    config = make_config({"workspace": workspace_url, "finance": finance_url})
    stages: list[Stage] = [
        BlockWithError(),
        BlockWithToolResult(),
        RedactDocuments(),
        PinSearchLimit(),
        CrashOnListTransactions(),
        HijackGetBalance(),
        CrashOnProgress(),
    ]
    with running_gateway(config, stages) as gw:
        yield gw


async def outbox(workspace_url: str) -> list[dict[str, Any]]:
    async with httpx2.AsyncClient() as http:
        emails: list[dict[str, Any]] = (await http.get(workspace_url.removesuffix("/mcp") + "/outbox")).json()
    return emails


async def test_a_blocked_call_never_reaches_the_upstream(
    mode: str, staged: Gateway, workspace_url: str
) -> None:
    before = await outbox(workspace_url)
    async with Client(staged.url("workspace"), mode=mode) as client:
        await client.list_tools()
        with pytest.raises(MCPError) as caught:
            await client.call_tool("send_email", {"to": "x@evil.example", "subject": "s", "body": "b"})
    assert caught.value.code == BLOCKED_CODE
    assert await outbox(workspace_url) == before


async def test_a_stage_can_answer_with_a_tool_error(mode: str, staged: Gateway) -> None:
    async with Client(staged.url("finance"), mode=mode) as client:
        result = await client.call_tool(
            "transfer_funds",
            {"from_account": "ACC-OPERATING", "to_account": "ACC-NORTHWIND", "amount": "1.00", "memo": "t"},
        )
    assert result.is_error
    assert "Denied by policy" in str(result.content)


async def test_results_can_be_rewritten_on_the_way_back(mode: str, staged: Gateway) -> None:
    async with Client(staged.url("workspace"), mode=mode) as client:
        result = await client.call_tool("read_doc", {"doc_id": "inv-2026-091"})
    assert [block.model_dump()["text"] for block in result.content] == [REDACTED]


async def test_arguments_can_be_rewritten_on_the_way_out(mode: str, staged: Gateway) -> None:
    async with Client(staged.url("workspace"), mode=mode) as client:
        result = await client.call_tool("search_docs", {"query": "policy", "limit": 5})
    assert result.structured_content is not None
    assert len(result.structured_content["result"]) == 1


async def test_a_crashing_stage_fails_closed(mode: str, staged: Gateway) -> None:
    async with Client(staged.url("finance"), mode=mode) as client:
        with pytest.raises(MCPError) as caught:
            await client.call_tool("list_transactions", {"account_id": "ACC-OPERATING"})
    assert caught.value.code == jsonrpc.INTERNAL_ERROR


async def test_a_stage_cannot_change_which_tool_is_called(mode: str, staged: Gateway) -> None:
    async with Client(staged.url("finance"), mode=mode) as client:
        await client.list_tools()
        with pytest.raises(MCPError) as caught:
            await client.call_tool("get_balance", {"account_id": "ACC-OPERATING"})
    assert caught.value.code == jsonrpc.INTERNAL_ERROR


async def test_unvetted_server_messages_are_withheld(mode: str, staged: Gateway) -> None:
    updates: list[float] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        updates.append(progress)

    async with Client(staged.url("workspace"), mode=mode) as client:
        with pytest.raises(MCPError) as caught:
            await client.call_tool("reindex", {}, progress_callback=on_progress)
    assert caught.value.code == jsonrpc.INTERNAL_ERROR
    assert updates == []


async def test_traffic_the_stages_ignore_is_untouched(
    mode: str, staged: Gateway, direct_urls: dict[str, str]
) -> None:
    async with (
        Client(direct_urls["workspace"], mode=mode) as direct,
        Client(staged.url("workspace"), mode=mode) as gw,
    ):
        assert (await gw.list_tools()) == (await direct.list_tools())
        args = {"doc_id": "report-q3"}
        assert (await gw.get_prompt("summarise_document", args)) == (
            await direct.get_prompt("summarise_document", args)
        )
