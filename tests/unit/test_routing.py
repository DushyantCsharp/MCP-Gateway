import json
from typing import Any

import pytest
from starlette.datastructures import Headers

from mcp_customs.jsonrpc import parse_message
from mcp_customs.proxy.routing import is_modern, protocol_version_of, routing_header_mismatch

MODERN = "2026-07-28"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
META = {VERSION_KEY: MODERN, "io.modelcontextprotocol/clientCapabilities": {}}


def check(body: dict[str, Any], headers: list[tuple[str, str]]) -> str | None:
    message = parse_message(json.dumps(body).encode())
    folded = Headers(raw=[(k.encode(), v.encode()) for k, v in headers])
    return routing_header_mismatch(message, folded, headers)


def call(name: str = "read_doc", **params: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "_meta": META, **params},
    }


def modern(method: str = "tools/call", name: str | None = "read_doc") -> list[tuple[str, str]]:
    headers = [("mcp-protocol-version", MODERN), ("mcp-method", method)]
    return headers + ([("mcp-name", name)] if name is not None else [])


def test_consistent_modern_request_passes() -> None:
    assert check(call(), modern()) is None


@pytest.mark.parametrize(
    ("body", "headers", "fragment"),
    [
        (call(), modern(method="tools/list"), "Mcp-Method"),
        (call(), modern(name="send_email"), "Mcp-Name"),
        (call(), modern(name=None), "Mcp-Name"),
        (call(), [*modern(), ("mcp-name", "read_doc")], "more than once"),
        (call(), [("mcp-protocol-version", "2026-07-28"), ("mcp-name", "read_doc")], "Mcp-Method"),
        (call(_meta={**META, VERSION_KEY: "2025-11-25"}), modern(), "MCP-Protocol-Version"),
    ],
    ids=["method", "name", "name-missing", "duplicate", "method-missing", "envelope-version"],
)
def test_modern_mismatches(body: dict[str, Any], headers: list[tuple[str, str]], fragment: str) -> None:
    reason = check(body, headers)
    assert reason is not None
    assert fragment in reason


def test_legacy_requests_without_routing_headers_pass() -> None:
    assert check(call(), [("mcp-protocol-version", "2025-11-25")]) is None


def test_legacy_requests_with_inconsistent_headers_fail() -> None:
    assert check(call(), [("mcp-name", "send_email")]) is not None
    assert check(call(), [("mcp-method", "tools/list")]) is not None


def test_base64_sentinel_names_are_decoded() -> None:
    assert check(call(name="naïve"), modern(name="=?base64?bmHDr3Zl?=")) is None


def test_name_header_on_a_request_without_a_name_fails() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"_meta": META}}
    assert check(body, modern(method="resources/read", name="workspace://x")) is not None


def test_non_name_bearing_methods_ignore_mcp_name() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": META}}
    assert check(body, modern(method="tools/list", name="anything")) is None


def test_responses_are_not_routed() -> None:
    assert check({"jsonrpc": "2.0", "id": 1, "result": {}}, [("mcp-method", "x")]) is None


def test_protocol_version_sources() -> None:
    message = parse_message(json.dumps(call()).encode())
    assert protocol_version_of(message, {"mcp-protocol-version": "2025-06-18"}) == "2025-06-18"
    assert protocol_version_of(message, {}) == MODERN
    init = parse_message(
        b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}'
    )
    assert protocol_version_of(init, {}) == "2025-11-25"
    assert protocol_version_of(parse_message(b'{"jsonrpc":"2.0","method":"n"}'), {}) is None
    assert is_modern(MODERN)
    assert not is_modern("2025-11-25")
    assert not is_modern(None)
