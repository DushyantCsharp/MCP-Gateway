"""Who is calling, and what their token lets them attempt.

An :class:`Identity` comes from a verified token. ``agent`` names the caller;
``roles`` group callers for policy; ``task`` labels the work for audit; and
``grants``, when present, narrow the agent to the tools a single task needs.

Grants use the token's OAuth ``scope`` claim. Each ``mcp:<upstream>:<name>``
entry allows one upstream and a tool, prompt or resource name, either of
which may be a glob. Scope values without the ``mcp:`` prefix belong to other
systems and are ignored. A token with no ``mcp:`` entries is not narrowed;
the policy alone decides.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Final

SCOPE_PREFIX: Final = "mcp:"


@dataclass(frozen=True, slots=True)
class Grant:
    upstream: str
    name: str

    def covers(self, upstream: str, name: str) -> bool:
        return fnmatchcase(upstream, self.upstream) and fnmatchcase(name, self.name)

    def __str__(self) -> str:
        return f"{SCOPE_PREFIX}{self.upstream}:{self.name}"


def parse_grants(scopes: Iterable[str]) -> tuple[Grant, ...] | None:
    """The ``mcp:`` grants among ``scopes``, or ``None`` when there are none.

    Raises ``ValueError`` for an ``mcp:`` entry that names no upstream or no
    target, rather than silently ignoring a grant the issuer meant to set.
    """
    grants: list[Grant] = []
    for scope in scopes:
        if not scope.startswith(SCOPE_PREFIX):
            continue
        upstream, sep, name = scope.removeprefix(SCOPE_PREFIX).partition(":")
        if not sep or not upstream or not name:
            raise ValueError(f"malformed scope {scope!r}; expected mcp:<upstream>:<name>")
        grants.append(Grant(upstream, name))
    return tuple(grants) or None


@dataclass(frozen=True, slots=True)
class Identity:
    agent: str
    roles: frozenset[str] = frozenset()
    task: str | None = None
    grants: tuple[Grant, ...] | None = None
    """``None``: the token does not narrow the agent. Otherwise: only these targets."""
    issuer: str | None = field(default=None, compare=False)

    def permits(self, upstream: str, name: str) -> bool:
        """Whether the token's grants (if any) cover this target."""
        return self.grants is None or any(grant.covers(upstream, name) for grant in self.grants)
