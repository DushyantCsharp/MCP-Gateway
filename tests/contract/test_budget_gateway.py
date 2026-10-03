"""Budgets through a running gateway, with counters in Redis.

The finance policy allows payments of up to 10,000 each; a daily budget of
10,000 per agent catches the agent that splits a larger payment in two. A call
counts as stopped only if the finance server never received it.
"""

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest

from customs_demo import finance_server
from customs_demo._serve import http_app
from mcp_customs.approvals import MemoryApprovalStore
from tests.contract.conftest import Gateway, make_config, running_gateway
from tests.support.clients import TEST_AUDIENCE, TEST_SECRET, RawSession, answer_of, mcp_client, mint
from tests.support.finance_cases import transfer
from tests.support.recorder import Recorder
from tests.support.servers import serve_in_thread

pytestmark = [pytest.mark.anyio, pytest.mark.contract]

POLICY = Path(__file__).parents[2] / "policies" / "examples" / "finance-agent.yaml"
APPROVER = mint("alice", roles=("approver",), ttl=3600)


@contextmanager
def budgeted(redis_url: str, limits: list[dict[str, Any]]) -> Iterator[tuple[Gateway, Recorder, str]]:
    finance = Recorder(http_app(finance_server.build_server(), json_response=True))
    with serve_in_thread(finance) as fin:
        config = make_config(
            {"finance": f"{fin}/mcp"},
            auth={"jwt": {"audience": TEST_AUDIENCE, "secret": TEST_SECRET}},
            stages=[
                {"type": "policy", "file": str(POLICY)},
                {"type": "budget", "redis": redis_url, "limits": limits},
            ],
            approvals={"dsn": "postgresql://unused", "stream_s": 1, "retry_ms": 300, "poll_s": 0.1},
        )
        with running_gateway(config, approval_store=MemoryApprovalStore()) as gateway:
            yield gateway, finance, fin


def unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"  # each test counts against fresh counters


async def made(finance_base: str, memo: str) -> int:
    async with httpx2.AsyncClient() as http:
        return sum(1 for p in (await http.get(f"{finance_base}/transfers")).json() if p["memo"] == memo)


async def test_a_split_payment_is_held_for_a_human(redis_server: str) -> None:
    daily = unique("daily")
    limits = [
        {
            "id": daily,
            "tools": ["transfer_funds"],
            "sum": "amount",
            "limit": 10000,
            "per": "24h",
            "over": "approve",
        }
    ]
    memo = unique("INV")
    with budgeted(redis_server, limits) as (gateway, _, finance_base):
        async with mcp_client(gateway.url("finance"), token=mint("ap-agent")) as client:
            await client.list_tools()
            first = await client.call_tool("transfer_funds", transfer(amount="9225.00", memo=memo))
            assert not first.is_error
            results: list[Any] = []

            async def second_half() -> None:
                results.append(
                    await client.call_tool("transfer_funds", transfer(amount="9225.00", memo=memo))
                )

            async with anyio.create_task_group() as tasks, httpx2.AsyncClient() as http:
                tasks.start_soon(second_half)
                headers = {"authorization": f"Bearer {APPROVER}"}
                pending: list[dict[str, Any]] = []
                with anyio.fail_after(10):
                    while not pending:
                        await anyio.sleep(0.05)
                        listing = await http.get(f"{gateway.base}/approvals/api/calls", headers=headers)
                        pending = listing.json()
                assert await made(finance_base, memo) == 1  # the second half is waiting
                (call,) = pending
                assert call["reason"] == (
                    f"over budget: limit '{daily}' allows 10000 in 'amount' per 24h; "
                    "9225 used, this call adds 9225"
                )
                assert call["stage"] == "budget"
                await http.post(
                    f"{gateway.base}/approvals/api/calls/{call['id']}/decision",
                    headers=headers,
                    json={"decision": "approve"},
                )
        assert not results[0].is_error
        assert await made(finance_base, memo) == 2


async def test_calls_past_a_rate_limit_never_reach_the_server(redis_server: str) -> None:
    rate = unique("rate")
    with budgeted(redis_server, [{"id": rate, "limit": 3, "per": "1m"}]) as (gateway, finance, _):
        async with httpx2.AsyncClient() as http:
            session = RawSession(http, gateway.url("finance"), mint("ap-agent"), modern=True)
            sent = []
            for _ in range(5):
                request_id, response = await session.request(
                    "tools/call",
                    {"name": "get_balance", "arguments": {"account_id": "ACC-OPERATING"}},
                    extra_headers={"mcp-param-account": "ACC-OPERATING"},
                )
                sent.append((request_id, answer_of(response)))
    assert [finance.saw(request_id) for request_id, _ in sent] == [True, True, True, False, False]
    refusal = sent[3][1]["result"]
    assert refusal["isError"] is True
    assert refusal["content"][0]["text"].startswith(
        f"Blocked by gateway budget: limit '{rate}' allows 3 calls per 1m; 3 used, this call adds 1. "
        "Try again in about"
    )


async def test_concurrent_calls_cannot_overrun_a_limit(redis_server: str) -> None:
    """Budget accuracy through the gateway: 30 simultaneous calls, a limit of 10, exactly 10 arrive."""
    rate = unique("burst")
    with budgeted(redis_server, [{"id": rate, "limit": 10, "per": "1m"}]) as (gateway, finance, _):
        ids: list[str] = []

        async def one(http: httpx2.AsyncClient) -> None:
            session = RawSession(http, gateway.url("finance"), mint("ap-agent"), modern=True)
            request_id, _ = await session.request(
                "tools/call",
                {"name": "get_balance", "arguments": {"account_id": "ACC-OPERATING"}},
                extra_headers={"mcp-param-account": "ACC-OPERATING"},
            )
            ids.append(request_id)

        async with (
            httpx2.AsyncClient(limits=httpx2.Limits(max_connections=30)) as http,
            anyio.create_task_group() as tasks,
        ):
            for _ in range(30):
                tasks.start_soon(one, http)
    assert len(ids) == 30
    assert sum(finance.saw(request_id) for request_id in ids) == 10
