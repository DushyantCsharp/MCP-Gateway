import json
from typing import Any

import pytest
from starlette.datastructures import Headers

from mcp_customs.detectors.sensitive import SensitiveScanner
from mcp_customs.jsonrpc import parse_message
from mcp_customs.pipeline import (
    CONTINUE,
    ClientMessageContext,
    Exchange,
    Replace,
    Respond,
    ServerMessageContext,
)
from mcp_customs.pipeline.redaction import META_KEY, SENSITIVE_DATA, RedactionStage
from tests.unit.test_sensitive import FAKE

pytestmark = pytest.mark.anyio

KEY = FAKE["aws_access_key"]
CARD = "4111 1111 1111 1111"


def exchange(version: str = "2025-11-25") -> Exchange:
    return Exchange("up", "POST", Headers(), version, None)


def call(arguments: dict[str, Any], method: str = "tools/call") -> ClientMessageContext:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {"name": "send_email", "arguments": arguments},
    }
    return ClientMessageContext(exchange(), parse_message(json.dumps(body).encode()))


def answer(
    result: dict[str, Any], method: str = "tools/call", version: str = "2025-11-25"
) -> ServerMessageContext:
    request = parse_message(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode())
    reply = parse_message(json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode())
    return ServerMessageContext(exchange(version), reply, request)


def stage(mode: str = "redact", **options: Any) -> RedactionStage:
    return RedactionStage(SensitiveScanner(allow=options.pop("allow", ())), mode=mode, **options)  # type: ignore[arg-type]


async def test_secrets_in_arguments_are_redacted_before_they_leave() -> None:
    context = call({"to": "ap@acme.example", "body": f"use {KEY} to log in", "tags": ["a", KEY]})
    outcome = await stage().on_client_message(context)
    assert isinstance(outcome, Replace)
    arguments = outcome.message["params"]["arguments"]
    assert arguments["body"] == "use [REDACTED:aws_access_key] to log in"
    assert arguments["tags"] == ["a", "[REDACTED:aws_access_key]"]
    assert arguments["to"] == "ap@acme.example"  # personal data is not scrubbed from requests by default
    assert outcome.message["params"]["name"] == "send_email"
    assert context.annotations["redaction"] == {
        "direction": "request",
        "found": 2,
        "kinds": "aws_access_key",
        "action": "redact",
    }


async def test_clean_arguments_pass() -> None:
    assert await stage().on_client_message(call({"body": "nothing to see"})) is CONTINUE


async def test_block_refuses_the_call_and_names_kinds_not_values() -> None:
    outcome = await stage("block").on_client_message(call({"body": KEY}))
    assert isinstance(outcome, Respond)
    text = json.dumps(outcome.message)
    assert "aws_access_key" in text
    assert "arguments.body" in text
    assert KEY not in text
    prompt = await stage("block").on_client_message(call({"x": KEY}, method="prompts/get"))
    assert isinstance(prompt, Respond)
    assert prompt.message["error"]["code"] == SENSITIVE_DATA


async def test_flag_changes_nothing_but_records_the_finding() -> None:
    context = call({"body": KEY})
    assert await stage("flag").on_client_message(context) is CONTINUE
    assert context.annotations["redaction"]["action"] == "flag"


async def test_results_are_scrubbed_of_secrets_and_personal_data() -> None:
    result = {
        "content": [{"type": "text", "text": f"Card {CARD}, owner jane@example.com"}],
        "structuredContent": {"card": CARD, "note": "fine"},
        "isError": False,
    }
    outcome = await stage().on_server_message(answer(result))
    assert isinstance(outcome, Replace)
    scrubbed = outcome.message["result"]
    assert scrubbed["content"][0]["text"] == "Card [REDACTED:card], owner [REDACTED:email]"
    assert scrubbed["structuredContent"] == {"card": "[REDACTED:card]", "note": "fine"}
    assert scrubbed["_meta"][META_KEY]["kinds"] == ["card", "email"]


async def test_allow_listed_values_survive() -> None:
    result = {"content": [{"type": "text", "text": "ask ap@acme.example or x@other.example"}]}
    outcome = await stage(allow=[r".*@acme\.example"]).on_server_message(answer(result))
    assert isinstance(outcome, Replace)
    assert outcome.message["result"]["content"][0]["text"] == "ask ap@acme.example or [REDACTED:email]"


@pytest.mark.parametrize(("version", "tagged"), [("2026-07-28", True), ("2025-11-25", False)])
async def test_block_withholds_results(version: str, tagged: bool) -> None:
    outcome = await stage("block").on_server_message(
        answer({"content": [{"type": "text", "text": CARD}]}, version=version)
    )
    assert isinstance(outcome, Replace)
    result = outcome.message["result"]
    assert result["isError"] is True
    assert ("resultType" in result) is tagged
    assert "1111" not in json.dumps(result)
    resource = await stage("block").on_server_message(
        answer({"contents": [{"uri": "x://1", "text": CARD}]}, method="resources/read")
    )
    assert isinstance(resource, Replace)
    assert resource.message["error"]["code"] == SENSITIVE_DATA


async def test_flagged_results_are_unchanged_apart_from_meta() -> None:
    result = {"content": [{"type": "text", "text": CARD}]}
    outcome = await stage("flag").on_server_message(answer(result))
    assert isinstance(outcome, Replace)
    assert outcome.message["result"]["content"] == result["content"]
    assert outcome.message["result"]["_meta"][META_KEY]["action"] == "flag"


async def test_unrelated_traffic_is_ignored() -> None:
    listing = answer({"tools": [{"name": "t", "description": CARD}]}, method="tools/list")
    assert await stage().on_server_message(listing) is CONTINUE
    assert (
        await stage(responses=()).on_server_message(answer({"content": [{"type": "text", "text": CARD}]}))
        is CONTINUE
    )
