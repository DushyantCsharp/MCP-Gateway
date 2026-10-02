"""The policy file format.

A policy is a list of rules. Each rule allows or denies a set of targets
(tools, prompts, resources or other methods) on a set of upstreams, for a set
of callers, optionally only when the call's arguments meet constraints.
:mod:`mcp_customs.policy.engine` defines how rules combine; this module only
says what a valid file looks like. See ``docs/policy-reference.md``.
"""

import re
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

type Scalar = StrictStr | StrictBool | StrictInt | StrictFloat | None
type Patterns = Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1)]

_OPERATORS = (
    "equals",
    "in_",
    "not_in",
    "matches",
    "not_matches",
    "min",
    "max",
    "min_length",
    "max_length",
)


class PolicyError(ValueError):
    """A policy file that cannot be used."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Constraint(_Model):
    """Conditions on one argument. Every operator given must hold."""

    optional: bool = False
    """Absence is harmless: an absent argument satisfies an allow rule and never triggers a deny
    rule. Without it, absence is unknown, which fails an allow rule and triggers a deny rule."""
    equals: Scalar = None
    in_: list[Scalar] | None = Field(default=None, alias="in")
    not_in: list[Scalar] | None = None
    matches: str | None = None
    """A regular expression the whole string value must match."""
    not_matches: str | None = None
    min: Decimal | None = None
    max: Decimal | None = None
    min_length: Annotated[int, Field(ge=0)] | None = None
    """String length in characters. Any non-string value is unknown."""
    max_length: Annotated[int, Field(ge=0)] | None = None

    @field_validator("matches", "not_matches")
    @classmethod
    def _compiles(cls, pattern: str | None) -> str | None:
        if pattern is not None:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regular expression {pattern!r}: {exc}") from exc
        return pattern

    @model_validator(mode="after")
    def _has_an_operator(self) -> Self:
        if not any(name in self.model_fields_set for name in _OPERATORS):
            raise ValueError("a constraint needs at least one operator besides 'optional'")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError("min is greater than max")
        if self.in_ == [] or self.not_in == []:
            raise ValueError("'in' and 'not_in' need at least one value")
        return self

    @property
    def has_equals(self) -> bool:
        return "equals" in self.model_fields_set


class Rule(_Model):
    id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
    effect: Literal["allow", "deny"]
    description: str | None = None

    agents: Patterns | None = None
    """Agent ids (globs). Omitted: any caller, including anonymous ones."""
    roles: Patterns | None = None
    """The caller must hold at least one of these roles (globs)."""
    upstreams: Patterns | None = None
    """Upstream names (globs). Omitted: every upstream."""

    tools: Patterns | None = None
    prompts: Patterns | None = None
    resources: Patterns | None = None
    """Resource URIs (globs)."""
    methods: Patterns | None = None
    """Other JSON-RPC methods by name (globs), such as ``subscriptions/listen``."""

    arguments: dict[str, Constraint] = Field(default_factory=dict)
    """Constraints on top-level tool or prompt arguments."""
    additional_arguments: bool = True
    """``False`` on an allow rule: any argument not listed under ``arguments`` fails the rule."""

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        if not any((self.tools, self.prompts, self.resources, self.methods)):
            raise ValueError("a rule must name tools, prompts, resources or methods")
        if (self.arguments or not self.additional_arguments) and not (self.tools or self.prompts):
            raise ValueError("argument constraints apply only to tools and prompts")
        if not self.additional_arguments and self.effect == "deny":
            raise ValueError("additional_arguments: false only makes sense on an allow rule")
        return self


class PolicyDocument(_Model):
    version: Literal[1]
    description: str | None = None
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
        return self


def load_policy_document(path: Path) -> PolicyDocument:
    try:
        data = yaml.safe_load(path.read_text())
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy {path} is not valid YAML: {exc}") from exc
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"policy {path} is invalid: {exc}") from exc
