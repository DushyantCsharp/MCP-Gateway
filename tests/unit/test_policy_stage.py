import json
from typing import Any

import pytest
from starlette.datastructures import Headers

from mcp_customs import jsonrpc
from mcp_customs.auth import Identity
from mcp_customs.jsonrpc import parse_message
from mcp_customs.pipeline import (
    CONTINUE,
    ClientMessageContext,
    Exchange,
    Replace,
    Respond,
    ServerMessageContext,
)
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.policy import PolicyDocument, RulePolicy

pytestmark = pytest.mark.anyio

STAGE = PolicyStage(
    RulePolicy(
        PolicyDocument.model_validate(
            {"version": 1, "rules": [{"id": "read", "effect": "allow", "agents": ["a"], "tools": ["read_*"]}]}
        )
    )
)


def exchange(version: str | None = "2026-07-28") -> Exchange:
    return Exchange("up", "POST", Headers(), version, None, Identity("a"))


def message(body: dict[str, Any]) -> jsonrpc.Message:
    return parse_message(json.dumps({"jsonrpc": "2.0", **body}).encode())


async def outgoing(body: dict[str, Any]) -> Any:
    return await STAGE.on_client_message(ClientMessageContext(exchange(), message(body)))


async def incoming(request: dict[str, Any], answer: dict[str, Any]) -> Any:
    return await STAGE.on_server_message(ServerMessageContext(exchange(), message(answer), message(request)))


async def test_allowed_and_ungoverned_requests_continue() -> None:
    assert await outgoing({"id": 1, "method": "tools/call", "params": {"name": "read_doc"}}) is CONTINUE
    assert await outgoing({"id": 1, "method": "tools/list"}) is CONTINUE
    assert await outgoing({"method": "notifications/cancelled", "params": {"requestId": 1}}) is CONTINUE
    assert await outgoing({"id": 9, "result": {}}) is CONTINUE


async def test_denied_tool_calls_become_tool_errors_shaped_for_the_revision() -> None:
    outcome = await outgoing({"id": 1, "method": "tools/call", "params": {"name": "write_doc"}})
    assert isinstance(outcome, Respond)
    result = outcome.message["result"]
    assert result["isError"] is True
    assert result["resultType"] == "complete"
    assert result["content"][0]["text"] == "Blocked by gateway policy: no rule allows this tool."


async def test_other_denials_are_json_rpc_errors() -> None:
    outcome = await outgoing({"id": 2, "method": "subscriptions/listen", "params": {}})
    assert isinstance(outcome, Respond)
    assert outcome.message["error"]["code"] == jsonrpc.POLICY_DENIED
    assert "data" not in outcome.message["error"]


async def test_malformed_governed_requests_are_invalid_params() -> None:
    outcome = await outgoing({"id": 3, "method": "tools/call", "params": {"arguments": {}}})
    assert isinstance(outcome, Respond)
    assert outcome.message["error"]["code"] == jsonrpc.INVALID_PARAMS


async def test_listings_are_filtered_and_made_private() -> None:
    tools = [{"name": "read_doc"}, {"name": "write_doc"}, {"title": "nameless"}, "junk"]
    answer = {"id": 4, "result": {"tools": tools, "cacheScope": "public", "ttlMs": 60000}}
    outcome = await incoming({"id": 4, "method": "tools/list"}, answer)
    assert isinstance(outcome, Replace)
    assert outcome.message["result"] == {
        "tools": [{"name": "read_doc"}],
        "cacheScope": "private",
        "ttlMs": 60000,
    }


async def test_unfiltered_private_listings_are_left_alone() -> None:
    answer = {"id": 5, "result": {"tools": [{"name": "read_doc"}], "cacheScope": "private"}}
    assert await incoming({"id": 5, "method": "tools/list"}, answer) is CONTINUE


async def test_a_public_listing_is_made_private_even_when_nothing_is_removed() -> None:
    answer = {"id": 6, "result": {"tools": [{"name": "read_doc"}], "cacheScope": "public"}}
    outcome = await incoming({"id": 6, "method": "tools/list"}, answer)
    assert isinstance(outcome, Replace)
    assert outcome.message["result"]["cacheScope"] == "private"


@pytest.mark.parametrize(
    ("request_body", "answer"),
    [
        ({"id": 7, "method": "tools/list"}, {"id": 7, "result": {"tools": "not a list"}}),
        ({"id": 7, "method": "tools/list"}, {"id": 7, "error": {"code": -1, "message": "m"}}),
        (
            {"id": 7, "method": "tools/call", "params": {"name": "read_doc"}},
            {"id": 7, "result": {"content": []}},
        ),
    ],
)
async def test_other_server_messages_pass(request_body: dict[str, Any], answer: dict[str, Any]) -> None:
    assert await incoming(request_body, answer) is CONTINUE
