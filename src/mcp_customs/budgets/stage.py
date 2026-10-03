"""The budget stage: per-agent rate and cost limits on tool calls, across calls.

A per-call policy limit cannot stop an agent that splits one large payment
into several small ones; a budget can. Each limit counts calls, adds up an
argument (``sum: amount``) or charges a fixed ``cost``, per agent, over a
rolling window. A call that would take any applicable limit past its total is
refused, or held for a human when the limit says ``over: approve``. An
approved call is charged even though it goes over (its total then shows
what was spent), so the next call over that limit needs a human too.

A call is charged when this stage admits it, all its limits at once or none.
It stays charged if a later stage refuses it or the upstream fails: budgets
err on the side of stopping. The stage must come after the policy stage, so a
call is never charged before policy holds it and again when it is approved.
"""

import hashlib
import logging
import math
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from fnmatch import fnmatchcase
from typing import Any, Literal

from mcp_customs.auth import Identity
from mcp_customs.budgets.store import MAX_AMOUNT, MICRO, BudgetStore, BudgetStoreError, Charge, ChargeResult
from mcp_customs.config import BudgetLimitConfig
from mcp_customs.pipeline.base import CONTINUE, ClientMessageContext, ClientOutcome, Hold, Stage
from mcp_customs.pipeline.replies import tool_error_reply
from mcp_customs.policy.engine import parse_decimal

logger = logging.getLogger(__name__)

BLOCK_PREFIX = "Blocked by gateway budget"


def _matches(value: str, patterns: Sequence[str] | None) -> bool:
    return patterns is None or any(fnmatchcase(value, pattern) for pattern in patterns)


def _micros(value: Decimal) -> int:
    return min(math.ceil(value * MICRO), MAX_AMOUNT)


def _units(micros: int) -> str:
    value = Decimal(micros) / MICRO
    return f"{value.normalize():f}" if value != value.to_integral() else str(int(value))


@dataclass(frozen=True, slots=True)
class Limit:
    config: BudgetLimitConfig

    @property
    def id(self) -> str:
        return self.config.id

    @property
    def over(self) -> Literal["deny", "approve"]:
        return self.config.over

    def applies(self, identity: Identity | None, upstream: str, tool: str) -> bool:
        config = self.config
        if config.agents is not None and (identity is None or not _matches(identity.agent, config.agents)):
            return False
        if config.roles is not None:
            roles = identity.roles if identity is not None else frozenset()
            if not any(_matches(role, config.roles) for role in roles):
                return False
        return _matches(upstream, config.upstreams) and _matches(tool, config.tools)

    def measure(self, arguments: Any) -> Decimal | None:
        """What this call adds, or ``None`` when it cannot be measured."""
        if self.config.cost is not None:
            return self.config.cost
        if self.config.sum is None:
            return Decimal(1)
        value = arguments.get(self.config.sum) if isinstance(arguments, dict) else None
        amount = parse_decimal(value)
        return amount if amount is not None and amount >= 0 else None

    def what(self) -> str:
        if self.config.sum is not None:
            return f"in {self.config.sum!r}"
        return "in cost" if self.config.cost is not None else "calls"

    def describe(self, used: int, adding: int) -> str:
        return (
            f"limit {self.id!r} allows {_units(_micros(self.config.limit))} {self.what()} per "
            f"{self.config.per}; {_units(used)} used, this call adds {_units(adding)}"
        )


def _counter_key(identity: Identity | None, limit: Limit) -> str:
    """One counter per agent and limit. The hash tag keeps an agent's counters in one Redis Cluster slot."""
    agent = identity.agent if identity is not None else ""
    tag = hashlib.sha256(agent.encode("utf-8")).hexdigest()[:16]
    return f"{{{tag}}}:{limit.id}"


class BudgetStage(Stage):
    name = "budget"

    def __init__(
        self, limits: Sequence[BudgetLimitConfig], store: BudgetStore, *, backend: str = "memory"
    ) -> None:
        self.limits = [Limit(config) for config in limits]
        self.store = store
        self.backend = backend

    @property
    def needs_approvals(self) -> bool:
        return any(limit.over == "approve" for limit in self.limits)

    async def start(self) -> None:
        await self.store.open()

    async def close(self) -> None:
        await self.store.close()

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        message = ctx.message
        tool = message.params.get("name") if message.method == "tools/call" else None
        if not message.is_request or not isinstance(tool, str):
            return CONTINUE
        identity = ctx.exchange.identity
        applicable = [limit for limit in self.limits if limit.applies(identity, ctx.exchange.upstream, tool)]
        if not applicable:
            return CONTINUE
        arguments = message.params.get("arguments")
        charges: list[Charge] = []
        for limit in applicable:
            amount = limit.measure(arguments)
            if amount is None:
                why = f"argument {limit.config.sum!r} is missing, not a number, or negative"
                ctx.annotations[self.name] = {"limits": limit.id, "charged": False, "reason": why}
                return tool_error_reply(
                    ctx, f"{BLOCK_PREFIX}: limit {limit.id!r} cannot measure this call ({why})."
                )
            approved = ctx.approval is not None and limit.over == "approve"
            charges.append(
                Charge(
                    _counter_key(identity, limit),
                    _micros(amount),
                    _micros(limit.config.limit),
                    limit.config.window_s * 1000,
                    force=approved,
                )
            )
        try:
            result = await self.store.charge(charges, ctx.call_id or uuid.uuid4().hex)
        except BudgetStoreError:
            logger.exception("budget store unavailable; refused %s", tool)
            ctx.annotations[self.name] = {
                "limits": ",".join(limit.id for limit in applicable),
                "charged": False,
            }
            return tool_error_reply(
                ctx, f"{BLOCK_PREFIX}: the budget store is unavailable, so the call was refused."
            )
        return self._outcome(ctx, applicable, charges, result)

    def _outcome(
        self, ctx: ClientMessageContext, limits: list[Limit], charges: list[Charge], result: ChargeResult
    ) -> ClientOutcome:
        notes: dict[str, Any] = {"limits": ",".join(limit.id for limit in limits), "charged": result.charged}
        ctx.annotations[self.name] = notes
        if result.charged:
            return CONTINUE
        over = [(limits[i], charges[i], result.used[i], result.retry_after_ms[i]) for i in result.over]
        notes["over"] = ",".join(limit.id for limit, *_ in over)
        denying = [entry for entry in over if entry[0].over == "deny"]
        agent = ctx.exchange.identity.agent if ctx.exchange.identity else "anonymous"
        if denying:
            limit, charge, used, retry_ms = denying[0]
            wait = f" Try again in about {math.ceil(retry_ms / 1000)}s." if retry_ms else ""
            logger.info("budget refused a call by %s: %s", agent, limit.id)
            return tool_error_reply(ctx, f"{BLOCK_PREFIX}: {limit.describe(used, charge.amount)}.{wait}")
        limit, charge, used, _ = over[0]
        logger.info("budget held a call by %s for approval: %s", agent, limit.id)
        return Hold(f"over budget: {limit.describe(used, charge.amount)}", limit.id)
