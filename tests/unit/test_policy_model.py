from pathlib import Path
from typing import Any

import pytest

from mcp_customs.policy import PolicyError, load_policy_document
from mcp_customs.policy.model import PolicyDocument

EXAMPLES = sorted((Path(__file__).parents[2] / "policies" / "examples").glob("*.yaml"))


def rule(**fields: Any) -> dict[str, Any]:
    return {"id": "r", "effect": "allow", "tools": ["t"], **fields}


@pytest.mark.parametrize("path", EXAMPLES, ids=[path.stem for path in EXAMPLES])
def test_example_policies_load(path: Path) -> None:
    assert load_policy_document(path).rules


def test_there_are_three_examples() -> None:
    assert [path.stem for path in EXAMPLES] == ["coding-agent", "finance-agent", "read-only-agent"]


@pytest.mark.parametrize(
    "rules",
    [
        [rule(), rule()],
        [{"id": "r", "effect": "allow"}],
        [rule(effect="maybe")],
        [rule(id="has space")],
        [rule(tools=[])],
        [rule(agents=[""])],
        [rule(arguments={"a": {}})],
        [rule(arguments={"a": {"optional": True}})],
        [rule(arguments={"a": {"matches": "("}})],
        [rule(arguments={"a": {"min": 5, "max": 1}})],
        [rule(arguments={"a": {"in": []}})],
        [rule(arguments={"a": {"equals": [1]}})],
        [rule(arguments={"a": {"unknown_op": 1}})],
        [{"id": "r", "effect": "allow", "resources": ["*"], "arguments": {"a": {"max": 1}}}],
        [rule(effect="deny", additional_arguments=False)],
        [rule(unexpected=True)],
    ],
    ids=[
        "duplicate-id",
        "no-targets",
        "bad-effect",
        "bad-id",
        "empty-list",
        "empty-pattern",
        "no-operator",
        "only-optional",
        "bad-regex",
        "min-over-max",
        "empty-in",
        "non-scalar-equals",
        "unknown-operator",
        "arguments-on-resources",
        "closed-deny",
        "unknown-field",
    ],
)
def test_invalid_policies_are_rejected(rules: list[dict[str, Any]]) -> None:
    with pytest.raises(ValueError, match="validation error"):
        PolicyDocument.model_validate({"version": 1, "rules": rules})


def test_the_version_is_required() -> None:
    with pytest.raises(ValueError, match="validation error"):
        PolicyDocument.model_validate({"rules": []})


def test_equals_null_is_distinct_from_no_equals() -> None:
    document = PolicyDocument.model_validate(
        {"version": 1, "rules": [rule(arguments={"a": {"equals": None}, "b": {"max": 1}})]}
    )
    constraints = document.rules[0].arguments
    assert constraints["a"].has_equals
    assert not constraints["b"].has_equals


@pytest.mark.parametrize(
    ("content", "message"), [("rules: [", "not valid YAML"), ("version: 2\n", "invalid")]
)
def test_file_errors_name_the_file(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(content)
    with pytest.raises(PolicyError, match=message):
        load_policy_document(path)
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy_document(tmp_path / "absent.yaml")
