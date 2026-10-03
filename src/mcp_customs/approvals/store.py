"""Where held calls live: Postgres in production, memory in tests.

A held call moves through these states, and only forward:

.. code-block:: text

    pending --approve--> approved --claim--> executing --> completed
       |                                         |
       +--deny--> denied                         +--> unknown (answer lost)
       +--timeout--> expired

Every transition is a conditional update from one expected state, so two
gateways (or two connections of one client) can never both approve, or both
make, the same call. The row keeps the original request, so the call survives
a gateway restart, and the final answer, so a client that reconnects after the
call was made gets the same answer instead of a second call.

The resume token a client holds is stored only as a SHA-256 digest: reading
the table does not let anyone collect another agent's result.
"""

import json
from collections.abc import Collection, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Protocol, cast

from mcp_customs.jsonrpc import JSONObject


class Status(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    EXECUTING = "executing"
    COMPLETED = "completed"
    UNKNOWN = "unknown"
    """Sent upstream, but the gateway lost the answer (it stopped mid-call). Never retried."""


TERMINAL: Final = frozenset({Status.DENIED, Status.EXPIRED, Status.COMPLETED, Status.UNKNOWN})
"""States with a final answer stored."""


@dataclass(frozen=True, slots=True)
class HeldCall:
    id: str
    token_sha256: str
    status: Status
    agent: str | None
    upstream: str
    session_id: str | None
    """The upstream's own session id (handshake era), so the call is made in the session it came from."""
    protocol_version: str | None
    method: str
    target: str | None
    arguments: Any
    request: JSONObject
    """The JSON-RPC request exactly as the client sent it."""
    headers: list[tuple[str, str]]
    """The client's end-to-end headers, replayed upstream. Never its credentials."""
    reason: str
    stage: str
    rule: str | None
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
    executing_since: datetime | None = None
    response: JSONObject | None = None
    """The final JSON-RPC answer, once the call reaches a terminal state."""

    @property
    def request_id(self) -> Any:
        return self.request.get("id")


class ApprovalStoreError(RuntimeError):
    """The approval store cannot be used."""


class ApprovalStore(Protocol):
    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def create(self, call: HeldCall) -> None: ...

    async def get(self, held_id: str) -> HeldCall | None: ...

    async def find(self, token_sha256: str) -> HeldCall | None: ...

    async def recent(self, statuses: Collection[Status] | None = None, limit: int = 100) -> list[HeldCall]:
        """Newest first."""
        ...

    async def count_pending(self, agent: str | None) -> int: ...

    async def decide(
        self,
        held_id: str,
        status: Status,
        by: str | None,
        reason: str | None,
        response: JSONObject | None,
        now: datetime,
    ) -> HeldCall | None:
        """Move a pending call to approved, denied or expired; ``None`` if it was not pending."""
        ...

    async def claim(self, held_id: str, now: datetime) -> HeldCall | None:
        """Move an approved call to executing; ``None`` if someone else already did."""
        ...

    async def finish(self, held_id: str, status: Status, response: JSONObject, now: datetime) -> None:
        """Record an executing call's final answer (completed) or its loss (unknown)."""
        ...

    async def due(self, now: datetime) -> list[HeldCall]:
        """Pending calls whose time is up."""
        ...

    async def prune(self, before: datetime) -> int:
        """Delete terminal calls that finished before ``before``; return how many."""
        ...


class MemoryApprovalStore:
    """For tests and single-process development: held calls do not survive a restart."""

    def __init__(self) -> None:
        self.calls: dict[str, HeldCall] = {}

    async def open(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def create(self, call: HeldCall) -> None:
        if call.id in self.calls or any(c.token_sha256 == call.token_sha256 for c in self.calls.values()):
            raise ApprovalStoreError("duplicate held call")
        self.calls[call.id] = call

    async def get(self, held_id: str) -> HeldCall | None:
        return self.calls.get(held_id)

    async def find(self, token_sha256: str) -> HeldCall | None:
        return next((c for c in self.calls.values() if c.token_sha256 == token_sha256), None)

    async def recent(self, statuses: Collection[Status] | None = None, limit: int = 100) -> list[HeldCall]:
        calls = [c for c in self.calls.values() if statuses is None or c.status in statuses]
        return sorted(calls, key=lambda c: c.created_at, reverse=True)[:limit]

    async def count_pending(self, agent: str | None) -> int:
        return sum(c.status is Status.PENDING and c.agent == agent for c in self.calls.values())

    def _move(self, held_id: str, expected: Status, **changes: Any) -> HeldCall | None:
        call = self.calls.get(held_id)
        if call is None or call.status is not expected:
            return None
        self.calls[held_id] = updated = replace(call, **changes)
        return updated

    async def decide(
        self,
        held_id: str,
        status: Status,
        by: str | None,
        reason: str | None,
        response: JSONObject | None,
        now: datetime,
    ) -> HeldCall | None:
        return self._move(
            held_id,
            Status.PENDING,
            status=status,
            decided_by=by,
            decision_reason=reason,
            decided_at=now,
            response=response,
        )

    async def claim(self, held_id: str, now: datetime) -> HeldCall | None:
        return self._move(held_id, Status.APPROVED, status=Status.EXECUTING, executing_since=now)

    async def finish(self, held_id: str, status: Status, response: JSONObject, now: datetime) -> None:
        self._move(held_id, Status.EXECUTING, status=status, response=response)

    async def due(self, now: datetime) -> list[HeldCall]:
        return [c for c in self.calls.values() if c.status is Status.PENDING and c.expires_at <= now]

    async def prune(self, before: datetime) -> int:
        old = [
            c.id
            for c in self.calls.values()
            if c.status in TERMINAL and (c.decided_at or c.created_at) < before
        ]
        for held_id in old:
            del self.calls[held_id]
        return len(old)


TABLE: Final = "customs_held_calls"

SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id               text        PRIMARY KEY,
    token_sha256     text        NOT NULL UNIQUE,
    status           text        NOT NULL CHECK (status IN
                         ('pending', 'approved', 'denied', 'expired', 'executing', 'completed', 'unknown')),
    agent            text,
    upstream         text        NOT NULL,
    session_id       text,
    protocol_version text,
    method           text        NOT NULL,
    target           text,
    arguments        jsonb,
    request          jsonb       NOT NULL,
    headers          jsonb       NOT NULL,
    reason           text        NOT NULL,
    stage            text        NOT NULL,
    rule             text,
    created_at       timestamptz NOT NULL,
    expires_at       timestamptz NOT NULL,
    decided_at       timestamptz,
    decided_by       text,
    decision_reason  text,
    executing_since  timestamptz,
    finished_at      timestamptz,
    response         jsonb
);
CREATE INDEX IF NOT EXISTS {TABLE}_status ON {TABLE} (status, created_at);
"""

_SCHEMA_LOCK: Final = 0x6D6370_686C64  # serialises concurrent schema creation
_COLUMNS: Final = (
    "id, token_sha256, status, agent, upstream, session_id, protocol_version, method, target, arguments, "
    "request, headers, reason, stage, rule, created_at, expires_at, decided_at, decided_by, "
    "decision_reason, executing_since, response"
)


def _json(value: Any) -> str | None:
    return None if value is None else json.dumps(value, separators=(",", ":"), allow_nan=False)


def _row(row: Sequence[Any]) -> HeldCall:
    (
        held_id,
        token_sha256,
        status,
        agent,
        upstream,
        session_id,
        protocol_version,
        method,
        target,
        arguments,
        request,
        headers,
        reason,
        stage,
        rule,
        created_at,
        expires_at,
        decided_at,
        decided_by,
        decision_reason,
        executing_since,
        response,
    ) = row
    return HeldCall(
        id=held_id,
        token_sha256=token_sha256,
        status=Status(status),
        agent=agent,
        upstream=upstream,
        session_id=session_id,
        protocol_version=protocol_version,
        method=method,
        target=target,
        arguments=arguments,
        request=cast(JSONObject, request),
        headers=[(str(name), str(value)) for name, value in headers],
        reason=reason,
        stage=stage,
        rule=rule,
        created_at=created_at,
        expires_at=expires_at,
        decided_at=decided_at,
        decided_by=decided_by,
        decision_reason=decision_reason,
        executing_since=executing_since,
        response=cast(JSONObject | None, response),
    )


class PostgresApprovalStore:
    def __init__(self, dsn: str, *, create_schema: bool = True, max_connections: int = 8) -> None:
        from psycopg_pool import AsyncConnectionPool

        self._create_schema = create_schema
        self._pool = AsyncConnectionPool(
            dsn, min_size=1, max_size=max_connections, open=False, kwargs={"autocommit": True}
        )

    async def open(self) -> None:
        import psycopg
        from psycopg_pool import PoolTimeout

        try:
            await self._pool.open(wait=True, timeout=10)
            if self._create_schema:
                async with self._pool.connection() as conn, conn.transaction():
                    await conn.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK,))
                    await conn.execute(SCHEMA)
        except (psycopg.Error, PoolTimeout) as exc:
            await self._pool.close()
            raise ApprovalStoreError(f"cannot open the approval store: {exc}") from exc

    async def close(self) -> None:
        await self._pool.close()

    async def _fetch(self, sql: str, params: Sequence[Any]) -> list[HeldCall]:
        import psycopg

        try:
            async with self._pool.connection() as conn:
                cursor = await conn.execute(sql, params)  # SQL built from constants
                return [_row(row) for row in await cursor.fetchall()]
        except psycopg.Error as exc:
            raise ApprovalStoreError(f"approval store query failed: {exc}") from exc

    async def _first(self, sql: str, params: Sequence[Any]) -> HeldCall | None:
        rows = await self._fetch(sql, params)
        return rows[0] if rows else None

    async def create(self, call: HeldCall) -> None:
        import psycopg

        sql = (
            f"INSERT INTO {TABLE} (id, token_sha256, status, agent, upstream, session_id, protocol_version, "  # noqa: S608
            "method, target, arguments, request, headers, reason, stage, rule, created_at, expires_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )
        params = (
            call.id,
            call.token_sha256,
            call.status.value,
            call.agent,
            call.upstream,
            call.session_id,
            call.protocol_version,
            call.method,
            call.target,
            _json(call.arguments),
            _json(call.request),
            _json([list(pair) for pair in call.headers]),
            call.reason,
            call.stage,
            call.rule,
            call.created_at,
            call.expires_at,
        )
        try:
            async with self._pool.connection() as conn:
                await conn.execute(sql, params)
        except psycopg.Error as exc:
            raise ApprovalStoreError(f"cannot record the held call: {exc}") from exc

    async def get(self, held_id: str) -> HeldCall | None:
        return await self._first(f"SELECT {_COLUMNS} FROM {TABLE} WHERE id = %s", (held_id,))  # noqa: S608

    async def find(self, token_sha256: str) -> HeldCall | None:
        return await self._first(f"SELECT {_COLUMNS} FROM {TABLE} WHERE token_sha256 = %s", (token_sha256,))  # noqa: S608

    async def recent(self, statuses: Collection[Status] | None = None, limit: int = 100) -> list[HeldCall]:
        if statuses is None:
            sql = f"SELECT {_COLUMNS} FROM {TABLE} ORDER BY created_at DESC LIMIT %s"  # noqa: S608
            return await self._fetch(sql, (limit,))
        sql = f"SELECT {_COLUMNS} FROM {TABLE} WHERE status = ANY(%s) ORDER BY created_at DESC LIMIT %s"  # noqa: S608
        return await self._fetch(sql, ([status.value for status in statuses], limit))

    async def count_pending(self, agent: str | None) -> int:
        import psycopg

        sql = f"SELECT count(*) FROM {TABLE} WHERE status = 'pending' AND agent IS NOT DISTINCT FROM %s"  # noqa: S608
        try:
            async with self._pool.connection() as conn:
                cursor = await conn.execute(sql, (agent,))
                row = await cursor.fetchone()
        except psycopg.Error as exc:
            raise ApprovalStoreError(f"approval store query failed: {exc}") from exc
        return int(row[0]) if row else 0

    async def decide(
        self,
        held_id: str,
        status: Status,
        by: str | None,
        reason: str | None,
        response: JSONObject | None,
        now: datetime,
    ) -> HeldCall | None:
        sql = (
            f"UPDATE {TABLE} SET status = %s, decided_by = %s, decision_reason = %s, decided_at = %s, "  # noqa: S608
            f"response = %s, finished_at = %s WHERE id = %s AND status = 'pending' RETURNING {_COLUMNS}"
        )
        finished = now if response is not None else None  # a denial or expiry is final; an approval is not
        params = (status.value, by, reason, now, _json(response), finished, held_id)
        return await self._first(sql, params)

    async def claim(self, held_id: str, now: datetime) -> HeldCall | None:
        sql = (
            f"UPDATE {TABLE} SET status = 'executing', executing_since = %s "  # noqa: S608
            f"WHERE id = %s AND status = 'approved' RETURNING {_COLUMNS}"
        )
        return await self._first(sql, (now, held_id))

    async def finish(self, held_id: str, status: Status, response: JSONObject, now: datetime) -> None:
        sql = (
            f"UPDATE {TABLE} SET status = %s, response = %s, finished_at = %s "  # noqa: S608
            f"WHERE id = %s AND status = 'executing' RETURNING {_COLUMNS}"
        )
        await self._fetch(sql, (status.value, _json(response), now, held_id))

    async def due(self, now: datetime) -> list[HeldCall]:
        sql = f"SELECT {_COLUMNS} FROM {TABLE} WHERE status = 'pending' AND expires_at <= %s"  # noqa: S608
        return await self._fetch(sql, (now,))

    async def prune(self, before: datetime) -> int:
        import psycopg

        terminal = [status.value for status in TERMINAL]
        finished = "coalesce(finished_at, decided_at, created_at)"
        sql = f"DELETE FROM {TABLE} WHERE status = ANY(%s) AND {finished} < %s"  # noqa: S608
        try:
            async with self._pool.connection() as conn:
                cursor = await conn.execute(sql, (terminal, before))
        except psycopg.Error as exc:
            raise ApprovalStoreError(f"approval store prune failed: {exc}") from exc
        return cursor.rowcount
