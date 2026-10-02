"""Which JSON-RPC requests the policy governs, and what each one targets.

* Protocol plumbing (``initialize``, ``ping``, ``server/discover``,
  ``logging/setLevel``) is always allowed: it reads or changes nothing on the
  server's side of the boundary.
* Listings (``tools/list``, ``prompts/list``, ``resources/list``) are allowed,
  and their results are filtered to what the caller may use.
* Calls that name a tool, prompt or resource are decided by the policy.
* Every other method is decided by the policy too, by method name, so a
  method the gateway has never heard of is denied unless a rule allows it.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from mcp_customs.jsonrpc import Message
from mcp_customs.policy.engine import TargetKind

PLUMBING_METHODS: Final = frozenset({"initialize", "ping", "server/discover", "logging/setLevel"})

LISTINGS: Final[Mapping[str, tuple[TargetKind, str, str]]] = {
    "tools/list": (TargetKind.TOOL, "tools", "name"),
    "prompts/list": (TargetKind.PROMPT, "prompts", "name"),
    "resources/list": (TargetKind.RESOURCE, "resources", "uri"),
}
"""Listing method -> (target kind, result key holding the items, item key holding the name)."""

UNFILTERED_LISTINGS: Final = frozenset({"resources/templates/list"})
"""Allowed but not filtered: a URI template cannot be matched against resource globs reliably."""

_NAMED: Final[Mapping[str, tuple[TargetKind, str]]] = {
    "tools/call": (TargetKind.TOOL, "name"),
    "prompts/get": (TargetKind.PROMPT, "name"),
    "resources/read": (TargetKind.RESOURCE, "uri"),
    "resources/subscribe": (TargetKind.RESOURCE, "uri"),
    "resources/unsubscribe": (TargetKind.RESOURCE, "uri"),
}


@dataclass(frozen=True, slots=True)
class Target:
    kind: TargetKind
    name: str
    arguments: Any = None


class MalformedTargetError(ValueError):
    """A governed request that does not say what it targets."""


def target_of(message: Message) -> Target | None:
    """What a client request targets, or ``None`` if the policy does not govern it."""
    method = message.method
    if method is None or method in PLUMBING_METHODS or method in LISTINGS or method in UNFILTERED_LISTINGS:
        return None
    params = message.params
    if method in _NAMED:
        kind, key = _NAMED[method]
        name = params.get(key)
        if not isinstance(name, str) or not name:
            raise MalformedTargetError(f"{method} without a {key!r}")
        arguments = params.get("arguments") if kind in (TargetKind.TOOL, TargetKind.PROMPT) else None
        return Target(kind, name, arguments)
    if method == "completion/complete":
        return _completion_target(params.get("ref"))
    return Target(TargetKind.METHOD, method)


def _completion_target(ref: Any) -> Target:
    """Completing a prompt or resource argument is governed like using that prompt or resource."""
    if isinstance(ref, Mapping):
        if ref.get("type") == "ref/prompt" and isinstance(name := ref.get("name"), str) and name:
            return Target(TargetKind.PROMPT, name, {})
        if ref.get("type") == "ref/resource" and isinstance(uri := ref.get("uri"), str) and uri:
            return Target(TargetKind.RESOURCE, uri)
    raise MalformedTargetError("completion/complete without a prompt or resource reference")
