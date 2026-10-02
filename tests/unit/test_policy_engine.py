from typing import Any

import pytest

from mcp_customs.auth import Identity, parse_grants
from mcp_customs.policy import PolicyDocument, PolicyRequest, RulePolicy, TargetKind
from mcp_customs.policy.engine import MAX_CHECKED_STRING

AGENT = Identity("agent-1", frozenset({"staff"}))
TOOL = TargetKind.TOOL


def policy(*rules: dict[str, Any]) -> RulePolicy:
    return RulePolicy(PolicyDocument.model_validate({"version": 1, "rules": list(rules)}))


def call(engine: RulePolicy, name: str = "t", arguments: Any = None, **overrides: Any) -> bool:
    request = PolicyRequest(
        identity=overrides.get("identity", AGENT),
        upstream=overrides.get("upstream", "up"),
        kind=overrides.get("kind", TOOL),
        name=name,
        arguments=arguments,
    )
    return engine.decide(request).allowed


# -- combining rules ------------------------------------------------------------------------------


def test_nothing_is_allowed_by_default() -> None:
    engine = policy()
    decision = engine.decide(PolicyRequest(AGENT, "up", TOOL, "t"))
    assert not decision.allowed
    assert decision.reason == "no rule allows this tool"


def test_deny_beats_allow_whatever_the_order() -> None:
    allow_rule = {"id": "a", "effect": "allow", "tools": ["*"]}
    deny_rule = {"id": "d", "effect": "deny", "tools": ["t"]}
    for rules in ((allow_rule, deny_rule), (deny_rule, allow_rule)):
        engine = policy(*rules)
        decision = engine.decide(PolicyRequest(AGENT, "up", TOOL, "t"))
        assert (decision.allowed, decision.rule) == (False, "d")
        assert call(engine, "other")


@pytest.mark.parametrize(
    ("rule", "identity", "allowed"),
    [
        ({"agents": ["agent-1"]}, AGENT, True),
        ({"agents": ["agent-*"]}, AGENT, True),
        ({"agents": ["Agent-1"]}, AGENT, False),
        ({"agents": ["agent-1"]}, None, False),
        ({"roles": ["staff"]}, AGENT, True),
        ({"roles": ["admin"]}, AGENT, False),
        ({"roles": ["staff"]}, None, False),
        ({"agents": ["agent-1"], "roles": ["admin"]}, AGENT, False),
        ({}, None, True),
    ],
    ids=[
        "exact",
        "glob",
        "case-sensitive",
        "anonymous",
        "role",
        "other-role",
        "anonymous-role",
        "both",
        "anyone",
    ],
)
def test_subjects(rule: dict[str, Any], identity: Identity | None, allowed: bool) -> None:
    engine = policy({"id": "r", "effect": "allow", "tools": ["t"], **rule})
    assert call(engine, identity=identity) is allowed


def test_upstreams_and_target_kinds_are_separate() -> None:
    engine = policy({"id": "r", "effect": "allow", "upstreams": ["fin*"], "tools": ["get"], "prompts": ["p"]})
    assert call(engine, "get", upstream="finance")
    assert not call(engine, "get", upstream="workspace")
    assert call(engine, "p", upstream="finance", kind=TargetKind.PROMPT)
    assert not call(engine, "get", upstream="finance", kind=TargetKind.PROMPT)
    assert not call(engine, "p", upstream="finance", kind=TargetKind.RESOURCE)


def test_resource_and_method_targets() -> None:
    engine = policy(
        {"id": "r", "effect": "allow", "resources": ["docs://public/*"]},
        {"id": "m", "effect": "allow", "methods": ["subscriptions/listen"]},
    )
    assert call(engine, "docs://public/a/b", kind=TargetKind.RESOURCE)
    assert not call(engine, "docs://private/a", kind=TargetKind.RESOURCE)
    assert call(engine, "subscriptions/listen", kind=TargetKind.METHOD)
    assert not call(engine, "tasks/list", kind=TargetKind.METHOD)


def test_token_grants_narrow_but_never_widen() -> None:
    engine = policy({"id": "r", "effect": "allow", "tools": ["read", "write"]})
    narrowed = Identity("agent-1", grants=parse_grants(["mcp:up:read", "mcp:up:delete"]))
    assert call(engine, "read", identity=narrowed)
    assert not call(engine, "write", identity=narrowed)
    assert not call(engine, "delete", identity=narrowed)
    decision = engine.decide(PolicyRequest(narrowed, "up", TOOL, "write"))
    assert decision.reason == "outside the scope of the caller's token"


# -- argument constraints -------------------------------------------------------------------------


def constrained(effect: str = "allow", **constraints: Any) -> RulePolicy:
    rules: list[dict[str, Any]] = [{"id": "r", "effect": effect, "tools": ["t"], "arguments": constraints}]
    if effect == "deny":
        rules.append({"id": "base", "effect": "allow", "tools": ["t"]})
    return policy(*rules)


@pytest.mark.parametrize(
    ("constraint", "value", "allowed"),
    [
        ({"equals": "x"}, "x", True),
        ({"equals": "x"}, "X", False),
        ({"equals": 1}, 1.0, True),
        ({"equals": 1}, True, False),
        ({"equals": True}, 1, False),
        ({"equals": None}, None, True),
        ({"equals": "x"}, ["x"], False),
        ({"in": ["a", "b"]}, "b", True),
        ({"in": ["a", "b"]}, "c", False),
        ({"in": ["a"]}, {"a": 1}, False),
        ({"not_in": ["a"]}, "b", True),
        ({"not_in": ["a"]}, "a", False),
        ({"not_in": ["a"]}, ["b"], False),
        ({"matches": "[a-z]+"}, "abc", True),
        ({"matches": "[a-z]+"}, "abc1", False),
        ({"matches": "[a-z]+"}, 7, False),
        ({"matches": "a*"}, "a" * (MAX_CHECKED_STRING + 1), False),
        ({"not_matches": ".*secret.*"}, "fine", True),
        ({"not_matches": ".*secret.*"}, "top secret", False),
        ({"min": 1, "max": 10}, 10, True),
        ({"min": 1, "max": 10}, 10.5, False),
        ({"min": 1, "max": 10}, "7.25", True),
        ({"min": 1, "max": 10}, "1e1", False),
        ({"min": 1, "max": 10}, "07", False),
        ({"min": 1, "max": 10}, " 7", False),
        ({"min": 1, "max": 10}, True, False),
        ({"min": 1, "max": 10}, None, False),
        ({"min": 0.01}, 0.01, True),
        ({"min": 0.01}, 0.009, False),
        ({"max_length": 3}, "abc", True),
        ({"max_length": 3}, "abcd", False),
        ({"max_length": 2}, ["a", "b"], False),
        ({"min_length": 1}, "", False),
        ({"max_length": 3}, 123, False),
    ],
)
def test_constraints_on_allow_rules(constraint: dict[str, Any], value: Any, allowed: bool) -> None:
    assert call(constrained(v=constraint), arguments={"v": value}) is allowed


@pytest.mark.parametrize(
    ("value", "allowed"),
    [("ACC-SAFE", True), ("ACC-PAYROLL", False), (["ACC-PAYROLL"], False), (7, True), ({"x": 1}, False)],
    ids=["other", "matching", "wrong-type-list", "different-scalar", "wrong-type-object"],
)
def test_deny_rules_fire_on_what_they_cannot_check(value: Any, allowed: bool) -> None:
    """Unknown triggers a deny rule: wrapping a value in a list does not slip past it."""
    engine = constrained("deny", account={"equals": "ACC-PAYROLL"})
    assert call(engine, arguments={"account": value}) is allowed


def test_a_definitely_false_condition_outweighs_an_unknown_one() -> None:
    engine = constrained("deny", account={"equals": "ACC-PAYROLL"}, amount={"min": 1})
    assert call(engine, arguments={"account": "ACC-SAFE", "amount": ["x"]})
    assert not call(engine, arguments={"account": "ACC-PAYROLL", "amount": ["x"]})


def test_missing_arguments_are_unknown_unless_optional() -> None:
    required = constrained(limit={"max": 10})
    assert not call(required, arguments={})
    optional = constrained(limit={"max": 10, "optional": True})
    assert call(optional, arguments={})
    assert call(optional, arguments=None)
    assert not call(optional, arguments={"limit": 11})
    deny_missing = constrained("deny", to={"matches": ".*@evil"})
    assert not call(deny_missing, arguments={})
    deny_optional = constrained("deny", limit={"min": 51, "optional": True})
    assert call(deny_optional, arguments={})
    assert not call(deny_optional, arguments={"limit": 51})
    assert not call(deny_optional, arguments={"limit": [51]})


def test_arguments_that_are_not_an_object_are_unknown() -> None:
    assert not call(constrained(v={"equals": 1}), arguments=[1])
    assert not call(constrained("deny", v={"equals": 1}), arguments="v=1")


def test_additional_arguments_can_be_refused() -> None:
    engine = policy(
        {
            "id": "r",
            "effect": "allow",
            "tools": ["t"],
            "arguments": {"a": {"max": 1}},
            "additional_arguments": False,
        }
    )
    assert call(engine, arguments={"a": 1})
    decision = engine.decide(PolicyRequest(AGENT, "up", TOOL, "t", {"a": 1, "cc": "evil@example.com"}))
    assert not decision.allowed
    assert decision.reason == "arguments not permitted by rule 'r'"
    assert decision.details == ("r: argument(s) not permitted: cc",)


def test_rules_without_constraints_ignore_arguments() -> None:
    assert call(policy({"id": "r", "effect": "allow", "tools": ["t"]}), arguments="anything")


def test_decision_details_explain_without_leaking_into_the_reason() -> None:
    engine = constrained(amount={"max": 10})
    decision = engine.decide(PolicyRequest(AGENT, "up", TOOL, "t", {"amount": 11}))
    assert decision.reason == "arguments not permitted by rule 'r'"
    assert decision.details == ("r: argument 'amount': max failed",)


# -- visibility -----------------------------------------------------------------------------------


def test_visibility_follows_what_could_be_allowed() -> None:
    engine = policy(
        {"id": "a", "effect": "allow", "agents": ["agent-1"], "tools": ["read", "pay", "wipe"]},
        {"id": "limit", "effect": "deny", "tools": ["pay"], "arguments": {"amount": {"min": 100}}},
        {"id": "never", "effect": "deny", "tools": ["wipe"]},
    )
    assert engine.visible(AGENT, "up", TOOL, "read")
    assert engine.visible(AGENT, "up", TOOL, "pay")  # some payments are allowed
    assert not engine.visible(AGENT, "up", TOOL, "wipe")
    assert not engine.visible(AGENT, "up", TOOL, "other")
    assert not engine.visible(Identity("someone-else"), "up", TOOL, "read")
    narrowed = Identity("agent-1", grants=parse_grants(["mcp:up:pay"]))
    assert not engine.visible(narrowed, "up", TOOL, "read")
