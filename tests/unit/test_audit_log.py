from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import anyio
import pytest

from mcp_customs.audit import AuditLog, AuditUnavailableError, Hasher, MemoryAuditStore, verify_chain
from mcp_customs.audit.events import event

pytestmark = pytest.mark.anyio


def healthy(log: AuditLog) -> bool:
    """Read the flag fresh (the type checker would otherwise keep an earlier narrowing)."""
    return log.healthy


@asynccontextmanager
async def running(store: MemoryAuditStore, **options: float) -> AsyncIterator[AuditLog]:
    log = AuditLog(store, Hasher(b"k"), "gw-1", **options)  # type: ignore[arg-type]
    async with anyio.create_task_group() as tg:
        await tg.start(log.run)
        try:
            yield log
        finally:
            await log.close()


async def test_events_are_committed_in_order_on_one_chain() -> None:
    store = MemoryAuditStore()
    async with running(store) as log:
        for i in range(5):
            await log.record({"n": i}, durable=True)
    assert [row.event["n"] for row in store.rows] == [0, 1, 2, 3, 4]
    assert verify_chain("gw-1", store.rows, Hasher(b"k")).ok


async def test_concurrent_callers_share_commits() -> None:
    store = MemoryAuditStore()
    appends = 0
    original = store.append

    async def counting(rows: object) -> None:
        nonlocal appends
        appends += 1
        await anyio.sleep(0.01)
        await original(rows)  # type: ignore[arg-type]

    store.append = counting  # type: ignore[method-assign]

    async def record(log: AuditLog, n: int) -> None:
        await log.record({"n": n}, durable=True)

    async with running(store) as log, anyio.create_task_group() as tg:
        for i in range(100):
            tg.start_soon(record, log, i)
    assert len(store.rows) == 100
    assert appends < 20  # group commit: far fewer transactions than events
    assert verify_chain("gw-1", store.rows, Hasher(b"k")).ok


async def test_a_restarted_log_continues_its_chain() -> None:
    store = MemoryAuditStore()
    async with running(store) as log:
        await log.record({"run": 1}, durable=True)
    async with running(store) as log:
        assert log.head.seq == 1
        await log.record({"run": 2}, durable=True)
    assert verify_chain("gw-1", store.rows, Hasher(b"k")).rows == 2


async def test_an_outage_refuses_durable_callers_but_loses_nothing() -> None:
    store = MemoryAuditStore()
    async with running(store, commit_timeout_s=0.2) as log:
        await log.record({"before": True}, durable=True)
        store.fail_appends = 1_000_000
        with pytest.raises(AuditUnavailableError):
            await log.record({"during": True}, durable=True)
        assert healthy(log) is False
        store.fail_appends = 0
        await log.flush()
        assert healthy(log) is True
    assert [row.event for row in store.rows] == [{"before": True}, {"during": True}]
    assert verify_chain("gw-1", store.rows, Hasher(b"k")).ok


async def test_a_full_queue_refuses_rather_than_blocking_forever() -> None:
    store = MemoryAuditStore()
    store.fail_appends = 1_000_000
    log = AuditLog(store, Hasher(), "gw-1", queue_size=1, batch_size=1, commit_timeout_s=0.1)
    async with anyio.create_task_group() as tg:
        await tg.start(log.run)
        await log.record({"a": 1}, durable=False)  # taken by the writer, which keeps retrying
        await log.record({"b": 2}, durable=False)  # fills the one-slot queue
        with pytest.raises(AuditUnavailableError):
            await log.record({"c": 3}, durable=False)
        tg.cancel_scope.cancel()


async def test_events_carry_their_envelope() -> None:
    body = event("request", "finance", agent="ap-agent", rule=None)
    assert body["v"] == 1
    assert body["type"] == "request"
    assert body["upstream"] == "finance"
    assert body["agent"] == "ap-agent"
    assert "rule" not in body
    assert len(body["id"]) == 32
    assert body["ts"].endswith("Z")


async def test_shutdown_does_not_hang_on_a_dead_store() -> None:
    store = MemoryAuditStore()
    log = AuditLog(store, Hasher(), "gw-1", commit_timeout_s=0.1)
    with anyio.fail_after(2):
        async with anyio.create_task_group() as tg:
            await tg.start(log.run)
            store.fail_appends = 10**9
            await log.record({"stuck": True}, durable=False)
            await log.close()
    with pytest.raises(AuditUnavailableError, match="closed"):
        await log.record({"late": True}, durable=False)
