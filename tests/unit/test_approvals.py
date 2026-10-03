from datetime import timedelta
from typing import Any

import anyio
import pytest

from mcp_customs import jsonrpc
from mcp_customs.approvals import (
    TOKEN_PREFIX,
    ApprovalService,
    HeldCall,
    MemoryApprovalStore,
    NotPendingError,
    SelfApprovalError,
    Status,
    TooManyHeldError,
)
from mcp_customs.approvals.service import now_utc, token_digest
from mcp_customs.jsonrpc import parse_message

pytestmark = pytest.mark.anyio

TRANSFER = (
    b'{"jsonrpc":"2.0","id":7,"method":"tools/call",'
    b'"params":{"name":"transfer_funds","arguments":{"amount":"18450.00"}}}'
)


def service(**options: Any) -> ApprovalService:
    return ApprovalService(MemoryApprovalStore(), **{"poll_s": 0.05, **options})


async def hold(
    approvals: ApprovalService,
    agent: str | None = "ap-agent",
    version: str = "2025-11-25",
    body: bytes = TRANSFER,
) -> tuple[HeldCall, str]:
    return await approvals.hold(
        agent=agent,
        upstream="finance",
        session_id="upstream-session",
        protocol_version=version,
        message=parse_message(body),
        headers=[("mcp-protocol-version", version)],
        reason="needs approval under rule 'large'",
        stage="policy",
        rule="large",
    )


async def test_a_held_call_keeps_what_it_needs_to_be_made_later() -> None:
    approvals = service()
    call, token = await hold(approvals)
    assert token.startswith(TOKEN_PREFIX)
    assert call.token_sha256 == token_digest(token) != token  # only the digest is stored
    assert (call.status, call.method, call.target, call.request_id) == (
        Status.PENDING,
        "tools/call",
        "transfer_funds",
        7,
    )
    assert call.arguments == {"amount": "18450.00"}
    assert await approvals.find(token) == call
    assert await approvals.find(TOKEN_PREFIX + "guess") is None


async def test_waiting_times_out_while_nobody_decides() -> None:
    approvals = service()
    call, _ = await hold(approvals)
    assert (await approvals.wait(call.id, 0.1)).status is Status.PENDING


async def test_an_approval_wakes_the_waiting_connection_at_once() -> None:
    approvals = service(poll_s=60)  # no polling: only the wakeup can end the wait in time
    call, _ = await hold(approvals)
    results: list[HeldCall] = []

    async def waiter() -> None:
        results.append(await approvals.wait(call.id, 30))

    with anyio.fail_after(5):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(waiter)
            await anyio.sleep(0.05)
            await approvals.decide(call.id, approve=True, approver="alice", reason=None)
    assert results[0].status is Status.APPROVED
    assert results[0].decided_by == "alice"


@pytest.mark.parametrize(("version", "tagged"), [("2026-07-28", True), ("2025-11-25", False)])
async def test_a_denial_is_stored_as_the_answer_the_agent_will_read(version: str, tagged: bool) -> None:
    approvals = service()
    call, _ = await hold(approvals, version=version)
    denied = await approvals.decide(call.id, approve=False, approver="alice", reason="not on file")
    assert denied.status is Status.DENIED
    assert denied.response is not None
    result = denied.response["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"] == "Denied at approval by alice: not on file."
    assert ("resultType" in result) is tagged
    assert denied.response["id"] == 7


async def test_other_requests_are_denied_with_an_error() -> None:
    approvals = service()
    body = b'{"jsonrpc":"2.0","id":"p","method":"prompts/get","params":{"name":"x"}}'
    call, _ = await hold(approvals, body=body)
    denied = await approvals.decide(call.id, approve=False, approver="alice", reason=None)
    assert denied.response is not None
    assert denied.response["error"]["code"] == jsonrpc.APPROVAL_DENIED
    assert denied.response["error"]["data"] == {"held": call.id}


async def test_a_call_is_decided_once() -> None:
    approvals = service()
    call, _ = await hold(approvals)
    await approvals.decide(call.id, approve=True, approver="alice", reason=None)
    with pytest.raises(NotPendingError):
        await approvals.decide(call.id, approve=False, approver="bob", reason=None)
    with pytest.raises(NotPendingError):
        await approvals.decide("no-such-call", approve=True, approver="alice", reason=None)


async def test_an_agent_cannot_approve_its_own_call() -> None:
    approvals = service()
    call, _ = await hold(approvals, agent="alice")
    with pytest.raises(SelfApprovalError):
        await approvals.decide(call.id, approve=True, approver="alice", reason=None)
    assert (await approvals.get(call.id)).status is Status.PENDING  # type: ignore[union-attr]


async def test_an_agent_can_only_have_so_many_calls_waiting() -> None:
    approvals = service(max_pending_per_agent=2)
    await hold(approvals)
    await hold(approvals)
    with pytest.raises(TooManyHeldError):
        await hold(approvals)
    await hold(approvals, agent="other-agent")  # the limit is per agent


async def test_undecided_calls_expire_into_a_denial() -> None:
    approvals = service(ttl_s=0.01)
    call, _ = await hold(approvals)
    await anyio.sleep(0.02)
    expired = await approvals.wait(call.id, 1)
    assert expired.status is Status.EXPIRED
    assert expired.response is not None
    assert "approval window closed" in expired.response["result"]["content"][0]["text"]
    with pytest.raises(NotPendingError):
        await approvals.decide(call.id, approve=True, approver="alice", reason=None)


async def test_the_sweep_expires_and_prunes() -> None:
    decisions: list[HeldCall] = []

    async def record(call: HeldCall) -> None:
        decisions.append(call)

    approvals = service(ttl_s=0.01, retention_s=0, on_decision=record)
    call, _ = await hold(approvals)
    await anyio.sleep(0.02)
    await approvals.sweep()  # expires the call: a decision, recorded
    assert [(c.id, c.status) for c in decisions] == [(call.id, Status.EXPIRED)]
    await approvals.sweep()  # and then prunes it
    assert await approvals.get(call.id) is None


async def test_only_one_connection_makes_an_approved_call() -> None:
    approvals = service()
    call, _ = await hold(approvals)
    approved = await approvals.decide(call.id, approve=True, approver="alice", reason=None)
    claims = [await approvals.claim(approved), await approvals.claim(approved)]
    assert [claim is not None for claim in claims] == [True, False]
    answer = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "isError": False}}
    await approvals.finish(approved, answer)
    done = await approvals.wait(call.id, 1)
    assert (done.status, done.response) == (Status.COMPLETED, answer)


async def test_a_call_lost_mid_flight_becomes_unknown_never_retried() -> None:
    store = MemoryApprovalStore()
    approvals = ApprovalService(store, poll_s=0.05, execution_timeout_s=60)
    call, _ = await hold(approvals)
    await approvals.decide(call.id, approve=True, approver="alice", reason=None)
    assert await store.claim(call.id, now_utc() - timedelta(seconds=61)) is not None  # another process
    lost = await approvals.wait(call.id, 1)
    assert lost.status is Status.UNKNOWN
    assert lost.response is not None
    assert lost.response["result"]["isError"] is True
    assert "outcome is unknown" in lost.response["result"]["content"][0]["text"]


async def test_a_call_executing_here_is_never_declared_lost() -> None:
    approvals = service(execution_timeout_s=0)
    call, _ = await hold(approvals)
    approved = await approvals.decide(call.id, approve=True, approver="alice", reason=None)
    await approvals.claim(approved)
    assert (await approvals.wait(call.id, 0.1)).status is Status.EXECUTING
