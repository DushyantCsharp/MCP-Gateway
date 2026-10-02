"""The policy stage: decide every governed call, and hide what a caller may not use.

A denied ``tools/call`` is answered with a tool error (``isError: true``)
carrying the reason, so the model reads it and can change course; any other
denied request gets a JSON-RPC error. Either way the upstream never sees the
call. Listing results are filtered to the targets the policy could allow this
caller, and marked ``cacheScope: private`` because they now differ per caller.
"""

import logging
from typing import Any

from mcp_customs.jsonrpc import INVALID_PARAMS, POLICY_DENIED, MessageKind
from mcp_customs.pipeline.base import (
    CONTINUE,
    ClientMessageContext,
    ClientOutcome,
    Replace,
    ServerMessageContext,
    ServerOutcome,
    Stage,
)
from mcp_customs.pipeline.replies import error_reply, tool_error_reply
from mcp_customs.policy.engine import PolicyEngine, PolicyRequest
from mcp_customs.policy.targets import LISTINGS, MalformedTargetError, target_of

logger = logging.getLogger(__name__)


class PolicyStage(Stage):
    name = "policy"

    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        message = ctx.message
        if not message.is_request:
            return CONTINUE  # notifications, and answers to the server's own requests
        try:
            target = target_of(message)
        except MalformedTargetError as exc:
            ctx.annotations[self.name] = {"decision": "deny", "reason": str(exc)}
            return error_reply(ctx, INVALID_PARAMS, str(exc))
        if target is None:
            return CONTINUE

        identity = ctx.exchange.identity
        decision = self.engine.decide(
            PolicyRequest(identity, ctx.exchange.upstream, target.kind, target.name, target.arguments)
        )
        ctx.annotations[self.name] = {
            "decision": "allow" if decision.allowed else "deny",
            "rule": decision.rule,
            "reason": decision.reason,
        }
        if decision.allowed:
            return CONTINUE
        logger.info(
            "policy denied %s %r on %s for %s: %s %s",
            target.kind.value,
            target.name,
            ctx.exchange.upstream,
            identity.agent if identity else "anonymous",
            decision.reason,
            "; ".join(decision.details),
        )
        reason = f"Blocked by gateway policy: {decision.reason}."
        if message.method == "tools/call":
            return tool_error_reply(ctx, reason)
        return error_reply(ctx, POLICY_DENIED, reason, {"rule": decision.rule} if decision.rule else None)

    async def on_server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        request = ctx.request
        method = request.method if request is not None else None
        if method is None or method not in LISTINGS or ctx.message.kind is not MessageKind.RESPONSE:
            return CONTINUE
        kind, items_key, name_key = LISTINGS[method]
        result = ctx.message.raw.get("result")
        if not isinstance(result, dict) or not isinstance(items := result.get(items_key), list):
            return CONTINUE

        identity, upstream = ctx.exchange.identity, ctx.exchange.upstream

        def shown(item: Any) -> bool:
            name = item.get(name_key) if isinstance(item, dict) else None
            return isinstance(name, str) and self.engine.visible(identity, upstream, kind, name)

        kept = [item for item in items if shown(item)]
        ctx.annotations[self.name] = {"listed": len(kept), "hidden": len(items) - len(kept)}
        shared = result.get("cacheScope", "private") != "private"
        if len(kept) == len(items) and not shared:
            return CONTINUE
        filtered = {**result, items_key: kept}
        if shared:
            # What a caller sees now depends on who they are; it must not be shared.
            filtered["cacheScope"] = "private"
        return Replace({**ctx.message.raw, "result": filtered})
