"""The audit log writer: one ordered chain, written in batches.

Requests hand events to a bounded queue; one writer task drains it, hashes
each event onto the chain and commits a whole batch in a single transaction
(group commit). Under load, many events share one commit, so durability
costs about one database round trip per batch rather than per call.

A durable caller waits for its batch to commit. If the database is down,
the writer keeps retrying with the same events and in the same order, so the
chain stays intact. Callers that cannot get a commit within
``commit_timeout_s`` get :class:`AuditUnavailableError`, and the gateway
refuses the call rather than run it unaudited. Their events are still written
once the database is back, so the log shows what was attempted.
"""

import logging
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Final

import anyio
from anyio.abc import TaskStatus

from mcp_customs.audit.chain import ChainHead, Hasher, canonical_json
from mcp_customs.audit.store import AuditStore, AuditStoreError

logger = logging.getLogger(__name__)

_MAX_BACKOFF_S: Final = 2.0


class AuditUnavailableError(RuntimeError):
    """An event could not be committed in time."""


@dataclass(slots=True)
class _Pending:
    body: str | None
    """``None`` marks a flush: done once everything queued before it is committed."""
    done: anyio.Event | None = field(default=None)


class AuditLog:
    def __init__(
        self,
        store: AuditStore,
        hasher: Hasher,
        chain: str,
        *,
        queue_size: int = 10_000,
        batch_size: int = 500,
        commit_timeout_s: float = 5.0,
    ) -> None:
        self.store = store
        self.hasher = hasher
        self.chain = chain
        self.head = ChainHead()
        self.healthy = False
        self.committed = 0
        self._batch_size = batch_size
        self._timeout = commit_timeout_s
        self._send, self._receive = anyio.create_memory_object_stream[_Pending](queue_size)
        self._scope = anyio.CancelScope()
        self._stopped = anyio.Event()

    async def run(self, *, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
        """Open the chain, then write batches until :meth:`close`. Start with ``TaskGroup.start``."""
        self.head = await self.store.open(self.chain)
        self.healthy = True
        logger.info("audit chain %r open at seq %d", self.chain, self.head.seq)
        task_status.started()
        try:
            with self._scope:
                await self._drain()
        finally:
            self._send.close()  # later callers get AuditUnavailableError, not a hang
            if lost := self._receive.statistics().current_buffer_used:
                logger.error("audit log stopped with %d events unwritten", lost)
            self._receive.close()
            with anyio.CancelScope(shield=True):
                await self.store.close()
            logger.info("audit chain %r closed at seq %d", self.chain, self.head.seq)
            self._stopped.set()

    async def _drain(self) -> None:
        async for first in self._receive:
            batch = [first]
            while len(batch) < self._batch_size:
                try:
                    batch.append(self._receive.receive_nowait())
                except anyio.WouldBlock:
                    break
            await self._commit(batch)

    async def _commit(self, batch: list[_Pending]) -> None:
        bodies = [item.body for item in batch if item.body is not None]
        backoff = 0.05
        while bodies:
            rows = self.hasher.extend(self.chain, self.head, bodies)
            try:
                await self.store.append(rows)
            except AuditStoreError:
                if self.healthy:
                    logger.exception("audit log unavailable; retrying")
                self.healthy = False
                await anyio.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF_S)
                with suppress(AuditStoreError):
                    self.head = await self.store.open(self.chain)  # reconnect; the head may have moved
                continue
            if not self.healthy:
                logger.warning("audit log recovered")
            self.healthy = True
            self.head = ChainHead(rows[-1].seq, rows[-1].hash)
            self.committed += len(rows)
            break
        for item in batch:
            if item.done is not None:
                item.done.set()

    async def record(self, event: Mapping[str, Any], *, durable: bool) -> None:
        """Queue an event; if ``durable``, return only once it is committed."""
        pending = _Pending(canonical_json(event), anyio.Event() if durable else None)
        try:
            with anyio.fail_after(self._timeout):
                await self._send.send(pending)
                if pending.done is not None:
                    await pending.done.wait()
        except TimeoutError as exc:
            raise AuditUnavailableError("the audit log could not record the call in time") from exc
        except anyio.ClosedResourceError as exc:
            raise AuditUnavailableError("the audit log is closed") from exc

    async def flush(self) -> None:
        """Wait until everything queued so far is committed."""
        done = anyio.Event()
        await self._send.send(_Pending(None, done))
        await done.wait()

    async def close(self) -> None:
        """Commit what is queued, waiting up to ``commit_timeout_s``, then stop the writer.

        If the store is still down when time runs out, the writer is stopped
        anyway, so shutdown cannot hang, and the unwritten count is logged.
        """
        with anyio.CancelScope(shield=True):
            with anyio.move_on_after(self._timeout):
                await self.flush()
            self._send.close()
            with anyio.move_on_after(self._timeout):
                await self._stopped.wait()
        self._scope.cancel()  # still retrying against a dead store: give up rather than hang
