"""Both budget stores, held to the same contract; Redis also under contention from many clients."""

import uuid
from collections.abc import AsyncIterator

import anyio
import pytest

from mcp_customs.budgets import BudgetStore, BudgetStoreError, Charge, MemoryBudgetStore, RedisBudgetStore

pytestmark = [pytest.mark.anyio, pytest.mark.contract]


@pytest.fixture(params=["memory", "redis"])
async def store(request: pytest.FixtureRequest) -> AsyncIterator[BudgetStore]:
    if request.param == "memory":
        yield MemoryBudgetStore()
        return
    redis = RedisBudgetStore(request.getfixturevalue("redis_server"), prefix=f"test:{uuid.uuid4().hex}:")
    await redis.open()
    yield redis
    await redis.close()


def charge(key: str, amount: int = 1, limit: int = 3, window_ms: int = 60_000, force: bool = False) -> Charge:
    return Charge(key, amount, limit, window_ms, force)


async def test_counting_within_and_beyond_a_limit(store: BudgetStore) -> None:
    results = [await store.charge([charge("k")], f"call-{n}") for n in range(4)]
    assert [r.charged for r in results] == [True, True, True, False]
    assert results[3].used == [3]
    assert results[3].over == [0]
    assert 0 < results[3].retry_after_ms[0] <= 60_000


async def test_all_or_nothing_idempotent_and_forced(store: BudgetStore) -> None:
    await store.charge([charge("b", amount=3)], "fill")
    assert (await store.charge([charge("a"), charge("b")], "both")).over == [1]
    assert (await store.charge([charge("a", amount=3)], "a-only")).charged  # "a" was untouched
    assert (await store.charge([charge("a", amount=3)], "a-only")).charged  # the same call again: no-op
    assert (await store.charge([charge("b", amount=5, force=True)], "approved")).charged
    assert (await store.charge([charge("b", amount=0)], "peek")).used == [8]


async def test_entries_leave_the_window(store: BudgetStore) -> None:
    assert (await store.charge([charge("w", amount=2, limit=2, window_ms=1000)], "first")).charged
    assert not (await store.charge([charge("w", limit=2, window_ms=1000)], "second")).charged
    await anyio.sleep(1.1)
    result = await store.charge([charge("w", limit=2, window_ms=1000)], "third")
    assert (result.charged, result.used) == (True, [0])


async def test_large_amounts_stay_exact(store: BudgetStore) -> None:
    big = 999_999_999_999_999  # just under a billion units, in micro-units
    assert (await store.charge([charge("x", amount=big, limit=big)], "one")).charged
    result = await store.charge([charge("x", amount=1, limit=big)], "two")
    assert (result.charged, result.used) == (False, [big])


async def test_no_charge_slips_past_a_limit_under_contention(redis_server: str) -> None:
    """Budget accuracy: 200 concurrent calls from 20 connections against a limit of 50."""
    prefix = f"race:{uuid.uuid4().hex}:"
    stores = [RedisBudgetStore(redis_server, prefix=prefix) for _ in range(20)]
    admitted = 0

    async def caller(store: RedisBudgetStore, n: int) -> None:
        nonlocal admitted
        for i in range(10):
            if (await store.charge([charge("shared", limit=50)], f"{n}-{i}")).charged:
                admitted += 1

    async with anyio.create_task_group() as tasks:
        for n, store in enumerate(stores):
            await store.open()
            tasks.start_soon(caller, store, n)
    for store in stores:
        await store.close()
    assert admitted == 50


async def test_a_burst_waits_for_connections_rather_than_failing(redis_server: str) -> None:
    """More concurrent calls than pooled connections: they queue, and every one is decided."""
    store = RedisBudgetStore(redis_server, prefix=f"burst:{uuid.uuid4().hex}:", max_connections=2)
    await store.open()
    results = []

    async def one(n: int) -> None:
        results.append(await store.charge([charge("k", limit=40)], f"call-{n}"))

    async with anyio.create_task_group() as tasks:
        for n in range(100):
            tasks.start_soon(one, n)
    await store.close()
    assert sum(result.charged for result in results) == 40
    assert len(results) == 100


async def test_an_unreachable_redis_fails_loudly() -> None:
    store = RedisBudgetStore("redis://127.0.0.1:1/0")
    with pytest.raises(BudgetStoreError):
        await store.open()
    with pytest.raises(BudgetStoreError):
        await store.charge([charge("k")], "call")
    await store.close()
