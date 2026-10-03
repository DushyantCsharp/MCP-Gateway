import json
from typing import Any

import pytest
from starlette.datastructures import Headers

from mcp_customs.detectors import Detection
from mcp_customs.jsonrpc import parse_message
from mcp_customs.pipeline import CONTINUE, Exchange, Replace, ServerMessageContext
from mcp_customs.pipeline.content import text_fields
from mcp_customs.pipeline.injection import INJECTION_BLOCKED, META_KEY, REMOVED, WARNING, InjectionStage

pytestmark = pytest.mark.anyio

MARKER = "MARKER-7731"


class MarkerDetector:
    """Flags any text containing a made-up marker word, and reports where it is."""

    name = "marker"

    def detect(self, text: str) -> Detection:
        start = text.find(MARKER)
        if start < 0:
            return Detection(0.01, self.name)
        return Detection(0.99, self.name, rules=("marker",), spans=((start, start + len(MARKER)),))


def ctx(method: str, result: dict[str, Any], version: str = "2025-11-25") -> ServerMessageContext:
    request = parse_message(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode())
    answer = parse_message(json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode())
    return ServerMessageContext(Exchange("up", "POST", Headers(), version, None), answer, request)


def tool_result(*texts: str, structured: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": t} for t in texts], "isError": False}
    if structured is not None:
        result["structuredContent"] = structured
    return result


def test_text_fields_cover_what_a_model_reads() -> None:
    result = {
        "content": [
            {"type": "text", "text": "a"},
            {"type": "image", "data": "...", "mimeType": "image/png"},
            {"type": "resource", "resource": {"uri": "x://1", "text": "b"}},
        ],
        "structuredContent": {"items": [{"note": "c", "n": 3}], "title": "d"},
    }
    assert dict(text_fields(result, "tools/call")) == {
        ("content", 0, "text"): "a",
        ("content", 2, "resource", "text"): "b",
        ("structuredContent", "items", 0, "note"): "c",
        ("structuredContent", "title"): "d",
    }
    assert dict(text_fields({"contents": [{"uri": "x", "text": "e"}]}, "resources/read")) == {
        ("contents", 0, "text"): "e"
    }
    prompt = {"messages": [{"role": "user", "content": {"type": "text", "text": "f"}}]}
    assert dict(text_fields(prompt, "prompts/get")) == {("messages", 0, "content", "text"): "f"}


async def test_clean_results_pass_untouched() -> None:
    context = ctx("tools/call", tool_result("all good"))
    assert await InjectionStage(MarkerDetector()).on_server_message(context) is CONTINUE
    assert context.annotations["injection"]["verdict"] == "clean"


async def test_other_methods_are_not_inspected() -> None:
    context = ctx("tools/list", {"tools": [{"name": MARKER}]})
    assert await InjectionStage(MarkerDetector()).on_server_message(context) is CONTINUE
    assert "injection" not in context.annotations


@pytest.mark.parametrize(("version", "tagged"), [("2026-07-28", True), ("2025-11-25", False)])
async def test_block_withholds_a_tool_result(version: str, tagged: bool) -> None:
    context = ctx("tools/call", tool_result(f"report {MARKER} text"), version)
    outcome = await InjectionStage(MarkerDetector(), mode="block").on_server_message(context)
    assert isinstance(outcome, Replace)
    result = outcome.message["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"].startswith("Withheld by the gateway")
    assert MARKER not in json.dumps(result)
    assert ("resultType" in result) is tagged
    assert context.annotations["injection"] == {
        "verdict": "detected",
        "score": 0.99,
        "detector": "marker",
        "action": "block",
        "fields": 1,
    }


async def test_block_answers_other_methods_with_an_error() -> None:
    context = ctx("resources/read", {"contents": [{"uri": "x://1", "text": MARKER}]})
    outcome = await InjectionStage(MarkerDetector(), mode="block").on_server_message(context)
    assert isinstance(outcome, Replace)
    assert outcome.message["error"]["code"] == INJECTION_BLOCKED


async def test_flag_delivers_with_a_warning_and_meta() -> None:
    context = ctx("tools/call", tool_result("intro", f"body {MARKER}"))
    outcome = await InjectionStage(MarkerDetector(), mode="flag").on_server_message(context)
    assert isinstance(outcome, Replace)
    result = outcome.message["result"]
    assert [block["text"] for block in result["content"]] == [WARNING, "intro", f"body {MARKER}"]
    assert result["_meta"][META_KEY]["fields"] == ["content.1.text"]


async def test_strip_removes_only_the_flagged_spans() -> None:
    structured = {"note": f"keep this {MARKER} and this"}
    context = ctx("tools/call", tool_result(f"a {MARKER} b", "clean", structured=structured))
    outcome = await InjectionStage(MarkerDetector(), mode="strip").on_server_message(context)
    assert isinstance(outcome, Replace)
    result = outcome.message["result"]
    texts = [block["text"] for block in result["content"]]
    assert texts[1:] == [f"a {REMOVED} b", "clean"]
    assert texts[0].startswith("[mcp-customs] Parts of this tool result were removed")
    assert result["structuredContent"] == {"note": f"keep this {REMOVED} and this"}
    assert MARKER not in json.dumps(result)


async def test_strip_without_spans_removes_the_whole_field() -> None:
    class Blunt:
        name = "blunt"

        def detect(self, text: str) -> Detection:
            return Detection(0.9 if MARKER in text else 0.0, self.name)

    context = ctx("tools/call", tool_result(f"x {MARKER} y"))
    outcome = await InjectionStage(Blunt(), mode="strip").on_server_message(context)
    assert isinstance(outcome, Replace)
    assert outcome.message["result"]["content"][1]["text"] == REMOVED
