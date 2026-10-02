"""Deciding whether a call is allowed.

The rules engine combines rules the way Cedar does, so the order of rules
never matters:

1. A call is **denied** if any matching deny rule's constraints hold.
2. Otherwise it is **allowed** if any matching allow rule's constraints hold.
3. Otherwise it is **denied**: nothing is allowed by default.

Constraints are evaluated in three-valued logic. An argument of the wrong type
(a list where a string was expected), a missing argument, or a string too long
to check is *unknown*, not false. Unknown never satisfies an allow rule and
always triggers a deny rule, so what the gateway cannot check, it does not let
through.

When the token carries ``mcp:`` scope grants, a call outside them is denied
before any rule is consulted: a task-scoped token can only narrow what the
agent's policy allows.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from fnmatch import fnmatchcase
from functools import cache
from pathlib import Path
from typing import Any, Final, Protocol

from mcp_customs.auth.identity import Identity
from mcp_customs.policy.model import Constraint, PolicyDocument, Rule, load_policy_document

MAX_CHECKED_STRING: Final = 8192
"""Longer strings are not matched against policy patterns: they count as unknown.

Policy regexes run on attacker-controlled input with Python's backtracking
engine, so the length cap bounds the cost of a badly written pattern.
"""

_DECIMAL: Final = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?")

type Tri = bool | None
"""Three-valued truth: ``None`` is unknown."""


class TargetKind(StrEnum):
    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"
    METHOD = "method"


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    identity: Identity | None
    upstream: str
    kind: TargetKind
    name: str
    """Tool or prompt name, resource URI, or method name."""
    arguments: Any = None
    """The call's arguments as sent; ``None`` when absent."""


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str
    """Safe to show the caller: names the deciding rule, not how to get around it."""
    rule: str | None = None
    details: tuple[str, ...] = field(default=(), compare=False)
    """Per-argument findings, for logs and ``customs check-policy``; not sent to the caller."""


class PolicyEngine(Protocol):
    """What the policy stage needs. The rules engine implements it; OPA or Cedar adapters could too."""

    def decide(self, request: PolicyRequest) -> Decision: ...

    def visible(self, identity: Identity | None, upstream: str, kind: TargetKind, name: str) -> bool:
        """Whether to list a target to this caller at all."""
        ...


# -- constraint evaluation ------------------------------------------------------------------------


def _and(values: Sequence[Tri]) -> Tri:
    if any(value is False for value in values):
        return False
    return None if any(value is None for value in values) else True


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | bool | int | float)


def _json_equal(left: Any, right: Any) -> bool:
    """JSON equality: ``true`` is not ``1``, and ``1`` equals ``1.0``."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, int | float) and isinstance(right, int | float):
        return Decimal(str(left)) == Decimal(str(right))
    return type(left) is type(right) and bool(left == right)


def _number(value: Any) -> Decimal | None:
    """A JSON number, or a plain decimal string such as ``"18450.00"``. No exponents, no ``NaN``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return Decimal(str(value))
    if isinstance(value, str) and len(value) <= 64 and _DECIMAL.fullmatch(value):
        try:
            return Decimal(value)
        except InvalidOperation:  # pragma: no cover - the pattern admits only valid decimals
            return None
    return None


@cache
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _check(constraint: Constraint, value: Any) -> tuple[Tri, list[str]]:
    results: list[Tri] = []
    notes: list[str] = []

    def record(result: Tri, what: str) -> None:
        results.append(result)
        if result is not True:
            notes.append(f"{what} {'failed' if result is False else 'could not be checked'}")

    if constraint.has_equals or constraint.in_ is not None or constraint.not_in is not None:
        scalar = _is_scalar(value)
        if constraint.has_equals:
            record(_json_equal(value, constraint.equals) if scalar else None, "equals")
        if constraint.in_ is not None:
            record(any(_json_equal(value, item) for item in constraint.in_) if scalar else None, "in")
        if constraint.not_in is not None:
            outside = not any(_json_equal(value, item) for item in constraint.not_in)
            record(outside if scalar else None, "not_in")

    for pattern, expected, label in (
        (constraint.matches, True, "matches"),
        (constraint.not_matches, False, "not_matches"),
    ):
        if pattern is not None:
            checkable = isinstance(value, str) and len(value) <= MAX_CHECKED_STRING
            matched = checkable and _regex(pattern).fullmatch(value) is not None
            record((matched is expected) if checkable else None, label)

    if constraint.min is not None or constraint.max is not None:
        number = _number(value)
        if constraint.min is not None:
            record(None if number is None else number >= constraint.min, "min")
        if constraint.max is not None:
            record(None if number is None else number <= constraint.max, "max")

    if constraint.min_length is not None or constraint.max_length is not None:
        length = len(value) if isinstance(value, str) else None
        if constraint.min_length is not None:
            record(None if length is None else length >= constraint.min_length, "min_length")
        if constraint.max_length is not None:
            record(None if length is None else length <= constraint.max_length, "max_length")

    return _and(results), notes


def _check_arguments(rule: Rule, arguments: Any) -> tuple[Tri, list[str]]:
    if not rule.arguments and rule.additional_arguments:
        return True, []
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        return None, ["arguments are not an object"]
    results: list[Tri] = []
    notes: list[str] = []
    for name, constraint in rule.arguments.items():
        if name not in arguments:
            # Optional means absence is harmless: it satisfies an allow rule and
            # never triggers a deny rule. Otherwise absence is unknown.
            results.append(rule.effect == "allow" if constraint.optional else None)
            if not constraint.optional:
                notes.append(f"argument {name!r} is missing")
            continue
        result, findings = _check(constraint, arguments[name])
        results.append(result)
        notes.extend(f"argument {name!r}: {finding}" for finding in findings)
    if not rule.additional_arguments and (extra := sorted(set(arguments) - set(rule.arguments))):
        results.append(False)
        notes.append(f"argument(s) not permitted: {', '.join(map(str, extra))}")
    return _and(results), notes


# -- rule matching --------------------------------------------------------------------------------


def _any_match(value: str, patterns: Sequence[str] | None) -> bool:
    return patterns is None or any(fnmatchcase(value, pattern) for pattern in patterns)


def _targets(rule: Rule, kind: TargetKind) -> Sequence[str] | None:
    match kind:
        case TargetKind.TOOL:
            return rule.tools
        case TargetKind.PROMPT:
            return rule.prompts
        case TargetKind.RESOURCE:
            return rule.resources
        case TargetKind.METHOD:
            return rule.methods


def _applies(rule: Rule, identity: Identity | None, upstream: str, kind: TargetKind, name: str) -> bool:
    """Whether the rule covers this caller, upstream and target, ignoring argument constraints."""
    if rule.agents is not None and (identity is None or not _any_match(identity.agent, rule.agents)):
        return False
    if rule.roles is not None:
        roles = identity.roles if identity is not None else frozenset()
        if not any(_any_match(role, rule.roles) for role in roles):
            return False
    targets = _targets(rule, kind)
    return targets is not None and _any_match(upstream, rule.upstreams) and _any_match(name, targets)


class RulePolicy:
    """The YAML rules engine."""

    def __init__(self, document: PolicyDocument) -> None:
        self.document = document
        self._allow = [rule for rule in document.rules if rule.effect == "allow"]
        self._deny = [rule for rule in document.rules if rule.effect == "deny"]

    @classmethod
    def load(cls, path: Path) -> "RulePolicy":
        return cls(load_policy_document(path))

    def decide(self, request: PolicyRequest) -> Decision:
        identity, upstream, kind, name = request.identity, request.upstream, request.kind, request.name
        if identity is not None and not identity.permits(upstream, name):
            return Decision(False, "outside the scope of the caller's token")

        for rule in self._deny:
            if _applies(rule, identity, upstream, kind, name):
                result, notes = _check_arguments(rule, request.arguments)
                if result is not False:
                    why = "" if result else " (arguments could not be checked)"
                    return Decision(False, f"denied by rule {rule.id!r}{why}", rule.id, tuple(notes))

        near_misses: list[str] = []
        details: list[str] = []
        for rule in self._allow:
            if _applies(rule, identity, upstream, kind, name):
                result, notes = _check_arguments(rule, request.arguments)
                if result is True:
                    return Decision(True, f"allowed by rule {rule.id!r}", rule.id)
                near_misses.append(rule.id)
                details.extend(f"{rule.id}: {note}" for note in notes)
        if near_misses:
            rules = ", ".join(repr(rule) for rule in near_misses)
            return Decision(False, f"arguments not permitted by rule {rules}", near_misses[0], tuple(details))
        return Decision(False, f"no rule allows this {kind.value}")

    def visible(self, identity: Identity | None, upstream: str, kind: TargetKind, name: str) -> bool:
        if identity is not None and not identity.permits(upstream, name):
            return False
        for rule in self._deny:
            unconditional = not rule.arguments
            if unconditional and _applies(rule, identity, upstream, kind, name):
                return False
        return any(_applies(rule, identity, upstream, kind, name) for rule in self._allow)
