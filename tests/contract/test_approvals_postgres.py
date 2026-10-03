"""The Postgres approval store: every transition is conditional, and everything round-trips."""

import uuid
from collections.abc import AsyncIterator
from datetime import timedelta

import anyio
import pytest

from mcp_customs.approvals import ApprovalStoreError, HeldCall, PostgresApprovalStore, Status
from mcp_customs.approvals.service import now_utc

pytestmark = [pytest.mark.anyio, pytest.mark.contract]


def held(agent: str = "ap-agent", **overrides: object) -> HeldCall:
    created = now_utc()
    fields: dict[str, object] = {
        "id": uuid.uuid4().hex,
        "token_sha256": uuid.uuid4().hex,
        "status": Status.PENDING,
        "agent": agent,
        "upstream": "finance",
        "session_id": None,
        "protocol_version": "2026-07-28",
        "method": "tools/call",
        "target": "transfer_funds",
        "arguments": {"amount": "18450.00", "memo": "Zahlung für Lösung", "lines": [1, 2.5, None, True]},
        "request": {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "transfer_funds"}},
        "headers": [("mcp-protocol-version", "2026-07-28"), ("x-trace", "a"), ("x-trace", "b")],
        "reason": "needs approval under rule 'large'",
        "stage": "policy",
        "rule": "large",
        "created_at": created,
        "expires_at": created + timedelta(hours=1),
    }
    fields.update(overrides)
    return HeldCall(**fields)  # type: ignore[arg-type]


@pytest.fixture
async def store(pg_dsn: str) -> AsyncIterator[PostgresApprovalStore]:
    store = PostgresApprovalStore(pg_dsn)
    await store.open()
    yield store
    await store.close()


async def test_a_held_call_round_trips(store: PostgresApprovalStore) -> None:
    call = held()
    await store.create(call)
    assert await store.get(call.id) == call
    assert await store.find(call.token_sha256) == call
    assert await store.get("missing") is None
    with pytest.raises(ApprovalStoreError):
        await store.create(call)  # ids and token digests are unique


async def test_transitions_happen_once_and_only_from_the_expected_state(store: PostgresApprovalStore) -> None:
    call = held()
    await store.create(call)
    now = now_utc()
    assert await store.claim(call.id, now) is None  # not approved yet
    approved = await store.decide(call.id, Status.APPROVED, "alice", "ok", None, now)
    assert approved is not None
    assert (approved.status, approved.decided_by, approved.response) == (Status.APPROVED, "alice", None)
    assert await store.decide(call.id, Status.DENIED, "bob", None, {"x": 1}, now) is None

    claims = []

    async def claim() -> None:
        claims.append(await store.claim(call.id, now_utc()))

    async with anyio.create_task_group() as tasks:  # racing connections: exactly one wins
        for _ in range(8):
            tasks.start_soon(claim)
    assert sum(result is not None for result in claims) == 1

    answer = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": False}}
    await store.finish(call.id, Status.COMPLETED, answer, now_utc())
    done = await store.get(call.id)
    assert done is not None
    assert (done.status, done.response) == (Status.COMPLETED, answer)
    await store.finish(call.id, Status.UNKNOWN, {"y": 2}, now_utc())  # already finished: no change
    assert (await store.get(call.id)).status is Status.COMPLETED  # type: ignore[union-attr]


async def test_listing_counting_expiry_and_pruning(store: PostgresApprovalStore) -> None:
    agent = f"agent-{uuid.uuid4().hex[:6]}"
    past = now_utc() - timedelta(hours=2)
    stale = held(agent, created_at=past, expires_at=past + timedelta(minutes=1))
    fresh = held(agent)
    for call in (stale, fresh):
        await store.create(call)
    assert await store.count_pending(agent) == 2
    assert {c.id for c in await store.due(now_utc())} >= {stale.id}
    assert fresh.id not in {c.id for c in await store.due(now_utc())}

    await store.decide(stale.id, Status.EXPIRED, None, "expired", {"error": "expired"}, now_utc())
    assert await store.count_pending(agent) == 1
    mine = [c.id for c in await store.recent([Status.PENDING, Status.EXPIRED], 500) if c.agent == agent]
    assert mine == [fresh.id, stale.id]  # newest first

    assert await store.prune(now_utc() + timedelta(seconds=1)) >= 1  # finished ones go
    assert await store.get(stale.id) is None
    assert await store.get(fresh.id) is not None  # pending ones stay


async def test_an_unreachable_database_fails_at_open() -> None:
    store = PostgresApprovalStore("postgresql://nobody:nothing@127.0.0.1:1/none")
    with pytest.raises(ApprovalStoreError):
        await store.open()
