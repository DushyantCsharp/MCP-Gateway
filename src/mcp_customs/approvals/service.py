"""Holding calls for a human, and resuming them.

The proxy parks a call with :meth:`ApprovalService.hold`, which records it and
returns a resume token. The token is the SSE event id the client's stream
opens with: when the stream ends, or the gateway restarts, the client
reconnects with ``Last-Event-ID`` set to it (SEP-1699 stream resumption), and
the gateway picks the call up from the store.

Decisions arrive through :meth:`decide`, from the approvals page, its JSON API
(the resume webhook) or the CLI. Waiting connections wake at once when the
decision is made in the same process, and within ``poll_s`` otherwise.
"""

import hashlib
import logging
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable, Collection
from datetime import UTC, datetime, timedelta
from typing import Final

import anyio
from anyio.abc import TaskStatus

from mcp_customs.approvals.store import ApprovalStore, ApprovalStoreError, HeldCall, Status
from mcp_customs.jsonrpc import (
    APPROVAL_DENIED,
    OUTCOME_UNKNOWN,
    JSONObject,
    Message,
    error_object,
)
from mcp_customs.proxy.routing import is_modern, name_param

logger = logging.getLogger(__name__)

TOKEN_PREFIX: Final = "customs-held-"  # noqa: S105 - a prefix, not a secret
"""Resume tokens start with this, so the proxy can tell its own event ids from an upstream's."""

DENIED_PREFIX: Final = "Denied at approval"
"""How the answer to a held call that was not made begins, so agents can tell it from other errors."""

type DecisionListener = Callable[[HeldCall], Awaitable[None]]


class TooManyHeldError(RuntimeError):
    """The agent already has as many calls waiting as it may."""


class NotPendingError(RuntimeError):
    """The call was already decided, has expired, or does not exist."""


class SelfApprovalError(RuntimeError):
    """An approver tried to approve a call they made themselves."""


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def now_utc() -> datetime:
    return datetime.now(UTC)


def closing_reply(call: HeldCall, text: str, code: int) -> JSONObject:
    """The answer a held call ends with when it is not made: a tool error, or a JSON-RPC error."""
    if call.method != "tools/call":
        return error_object(call.request_id, code, text, {"held": call.id})
    result: JSONObject = {"content": [{"type": "text", "text": text}], "isError": True}
    if is_modern(call.protocol_version):
        result["resultType"] = "complete"
    return {"jsonrpc": "2.0", "id": call.request_id, "result": result}


class ApprovalService:
    def __init__(
        self,
        store: ApprovalStore,
        *,
        ttl_s: float = 3600.0,
        retry_ms: int = 5000,
        stream_s: float = 25.0,
        poll_s: float = 1.0,
        max_pending_per_agent: int = 20,
        execution_timeout_s: float = 330.0,
        retention_s: float = 30 * 86400.0,
        on_decision: DecisionListener | None = None,
    ) -> None:
        self.store = store
        self.ttl_s = ttl_s
        self.retry_ms = retry_ms
        self.stream_s = stream_s
        self.poll_s = poll_s
        self.max_pending_per_agent = max_pending_per_agent
        self.execution_timeout_s = execution_timeout_s
        self.retention_s = retention_s
        self.on_decision = on_decision
        self._wakeups: dict[str, anyio.Event] = {}
        self._executing: set[str] = set()

    # -- holding ----------------------------------------------------------------------------------

    async def hold(
        self,
        *,
        agent: str | None,
        upstream: str,
        session_id: str | None,
        protocol_version: str | None,
        message: Message,
        headers: list[tuple[str, str]],
        reason: str,
        stage: str,
        rule: str | None,
    ) -> tuple[HeldCall, str]:
        """Record a call for a human to decide. Returns the call and its resume token."""
        if await self.store.count_pending(agent) >= self.max_pending_per_agent:
            limit = self.max_pending_per_agent
            raise TooManyHeldError(
                f"too many of this agent's calls are already waiting (the limit is {limit})"
            )
        token = TOKEN_PREFIX + secrets.token_urlsafe(24)
        created = now_utc()
        target = name_param(message)
        call = HeldCall(
            id=uuid.uuid4().hex,
            token_sha256=token_digest(token),
            status=Status.PENDING,
            agent=agent,
            upstream=upstream,
            session_id=session_id,
            protocol_version=protocol_version,
            method=message.method or "",
            target=target if isinstance(target, str) else None,
            arguments=message.params.get("arguments"),
            request=message.raw,
            headers=headers,
            reason=reason,
            stage=stage,
            rule=rule,
            created_at=created,
            expires_at=created + timedelta(seconds=self.ttl_s),
        )
        await self.store.create(call)
        logger.info("held %s %r for %s on %s: %s", call.method, call.target, agent, upstream, reason)
        return call, token

    async def find(self, token: str) -> HeldCall | None:
        return await self.store.find(token_digest(token))

    async def get(self, held_id: str) -> HeldCall | None:
        return await self.store.get(held_id)

    async def recent(self, statuses: Collection[Status] | None = None, limit: int = 100) -> list[HeldCall]:
        return await self.store.recent(statuses, limit)

    # -- deciding ---------------------------------------------------------------------------------

    async def decide(self, held_id: str, *, approve: bool, approver: str, reason: str | None) -> HeldCall:
        """Approve or deny a pending call. The approver must not be the agent that made it."""
        call = await self.store.get(held_id)
        if call is None or call.status is not Status.PENDING:
            raise NotPendingError(held_id)
        if call.agent is not None and approver == call.agent:
            raise SelfApprovalError(held_id)
        if call.expires_at <= now_utc():
            await self._expire(call)
            raise NotPendingError(held_id)
        if approve:
            status, response = Status.APPROVED, None
        else:
            why = f": {reason}" if reason else ""
            status = Status.DENIED
            response = closing_reply(call, f"{DENIED_PREFIX} by {approver}{why}.", APPROVAL_DENIED)
        decided = await self.store.decide(held_id, status, approver, reason, response, now_utc())
        if decided is None:
            raise NotPendingError(held_id)
        logger.info("%s %s by %s", "approved" if approve else "denied", held_id, approver)
        await self._decided(decided)
        return decided

    async def _expire(self, call: HeldCall) -> None:
        text = (
            f"{DENIED_PREFIX}: nobody decided this call before its approval window closed; it was not made."
        )
        response = closing_reply(call, text, APPROVAL_DENIED)
        expired = await self.store.decide(call.id, Status.EXPIRED, None, "expired", response, now_utc())
        if expired is not None:
            logger.info("held call %s expired", call.id)
            await self._decided(expired)

    async def _decided(self, call: HeldCall) -> None:
        self._wake(call.id)
        if self.on_decision is not None:
            try:
                await self.on_decision(call)
            except Exception:
                logger.exception("recording the decision on %s failed", call.id)

    def _wake(self, held_id: str) -> None:
        if (event := self._wakeups.pop(held_id, None)) is not None:
            event.set()

    # -- waiting and making the call ----------------------------------------------------------------

    async def wait(self, held_id: str, timeout_s: float) -> HeldCall:
        """The call once a human has decided it (or it is made, or lost), or as it stands at the timeout."""
        deadline = time.monotonic() + timeout_s
        while True:
            call = await self.store.get(held_id)
            if call is None:
                raise NotPendingError(held_id)
            if call.status is Status.PENDING and call.expires_at <= now_utc():
                await self._expire(call)
                continue
            if call.status is Status.EXECUTING and self._lost(call):
                await self.finish(call, self._lost_reply(call), lost=True)
                continue
            remaining = deadline - time.monotonic()
            if call.status not in (Status.PENDING, Status.EXECUTING) or remaining <= 0:
                return call
            event = self._wakeups.setdefault(held_id, anyio.Event())
            with anyio.move_on_after(min(self.poll_s, remaining)):
                await event.wait()

    def _lost(self, call: HeldCall) -> bool:
        """Executing, but not here, and for longer than any upstream answer can take."""
        if call.id in self._executing or call.executing_since is None:
            return False
        return now_utc() - call.executing_since > timedelta(seconds=self.execution_timeout_s)

    @staticmethod
    def _lost_reply(call: HeldCall) -> JSONObject:
        text = (
            "This approved call was sent to the server, but the gateway stopped before the answer "
            "arrived, so its outcome is unknown. It was not retried; check the server before trying again."
        )
        return closing_reply(call, text, OUTCOME_UNKNOWN)

    async def claim(self, call: HeldCall) -> HeldCall | None:
        """Take an approved call to make it. Exactly one caller gets it."""
        claimed = await self.store.claim(call.id, now_utc())
        if claimed is not None:
            self._executing.add(call.id)
        return claimed

    async def finish(self, call: HeldCall, response: JSONObject, *, lost: bool = False) -> None:
        self._executing.discard(call.id)
        try:
            await self.store.finish(
                call.id, Status.UNKNOWN if lost else Status.COMPLETED, response, now_utc()
            )
        finally:
            self._wake(call.id)

    # -- housekeeping -------------------------------------------------------------------------------

    async def run(
        self, *, interval_s: float = 30.0, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED
    ) -> None:
        """Expire calls nobody decided, and prune old finished ones, until cancelled."""
        task_status.started()
        while True:
            try:
                await self.sweep()
            except ApprovalStoreError:
                logger.exception("approval housekeeping failed; retrying")
            await anyio.sleep(interval_s)

    async def sweep(self) -> None:
        now = now_utc()
        for call in await self.store.due(now):
            await self._expire(call)
        if pruned := await self.store.prune(now - timedelta(seconds=self.retention_s)):
            logger.info("pruned %d finished held calls", pruned)
