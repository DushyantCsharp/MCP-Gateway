import json
from typing import Any

import pytest

from mcp_customs.jsonrpc import parse_message
from mcp_customs.policy.engine import TargetKind
from mcp_customs.policy.targets import MalformedTargetError, Target, target_of


def request(method: str, **params: Any) -> Any:
    return parse_message(json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())


@pytest.mark.parametrize(
    "method",
    ["initialize", "ping", "server/discover", "logging/setLevel", "tools/list", "resources/templates/list"],
)
def test_plumbing_and_listings_are_not_decided(method: str) -> None:
    assert target_of(request(method)) is None


@pytest.mark.parametrize(
    ("method", "params", "target"),
    [
        ("tools/call", {"name": "t", "arguments": {"a": 1}}, Target(TargetKind.TOOL, "t", {"a": 1})),
        ("tools/call", {"name": "t"}, Target(TargetKind.TOOL, "t", None)),
        ("prompts/get", {"name": "p", "arguments": {"x": "y"}}, Target(TargetKind.PROMPT, "p", {"x": "y"})),
        ("resources/read", {"uri": "docs://a"}, Target(TargetKind.RESOURCE, "docs://a")),
        ("resources/subscribe", {"uri": "docs://a"}, Target(TargetKind.RESOURCE, "docs://a")),
        (
            "completion/complete",
            {"ref": {"type": "ref/prompt", "name": "p"}},
            Target(TargetKind.PROMPT, "p", {}),
        ),
        (
            "completion/complete",
            {"ref": {"type": "ref/resource", "uri": "r://x"}},
            Target(TargetKind.RESOURCE, "r://x"),
        ),
        ("subscriptions/listen", {}, Target(TargetKind.METHOD, "subscriptions/listen")),
        ("vendor/custom", {}, Target(TargetKind.METHOD, "vendor/custom")),
    ],
)
def test_governed_requests_name_their_target(method: str, params: dict[str, Any], target: Target) -> None:
    assert target_of(request(method, **params)) == target


@pytest.mark.parametrize(
    ("method", "params"),
    [
        ("tools/call", {}),
        ("tools/call", {"name": ""}),
        ("tools/call", {"name": ["t"]}),
        ("resources/read", {"uri": 5}),
        ("completion/complete", {"ref": {"type": "ref/prompt"}}),
        ("completion/complete", {}),
    ],
)
def test_governed_requests_without_a_target_are_malformed(method: str, params: dict[str, Any]) -> None:
    with pytest.raises(MalformedTargetError):
        target_of(request(method, **params))
