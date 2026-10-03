import json
from typing import Any

import pytest
from starlette.datastructures import Headers

from mcp_customs.auth import Identity
from mcp_customs.budgets import BudgetStage, BudgetStoreError, Charge, ChargeResult, MemoryBudgetStore
from mcp_customs.budgets.store import MICRO
from mcp_customs.config import BudgetLimitConfig, ConfigError, parse_config
from mcp_customs.jsonrpc import parse_message
from mcp_customs.pipeline import CONTINUE, Approval, ClientMessageContext, Exchange, Hold, Respond

pytestmark = pytest.mark.anyio

AP = Identity("ap-agent")


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000

    def __call__(self) -> int:
        return self.now


def limit(**fields: Any) -> BudgetLimitConfig:
    return BudgetLimitConfig.model_validate({"id": "l", "limit": 3, "per": "1m", **fields})


def call(
    tool: str = "transfer_funds", identity: Identity | None = AP, **arguments: Any
) -> ClientMessageContext:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    exchange = Exchange("finance", "POST", Headers(), "2026-07-28", None, identity)
    return ClientMessageContext(exchange, parse_message(json.dumps(body).encode()))


def text(outcome: object) -> str:
    assert isinstance(outcome, Respond)
    result = outcome.message["result"]
    assert result["isError"] is True
    return str(result["content"][0]["text"])


# -- the store ------------------------------------------------------------------------------------


def charge(key: str = "k", amount: int = 1, limit_: int = 3, window_ms: int = 60_000, **kw: Any) -> Charge:
    return Charge(key, amount, limit_, window_ms, **kw)


async def test_a_counter_fills_then_frees_as_the_window_rolls() -> None:
    clock = Clock()
    store = MemoryBudgetStore(clock)
    results = [await store.charge([charge()], f"call-{n}") for n in range(4)]
    assert [r.charged for r in results] == [True, True, True, False]
    assert results[3].used == [3]
    clock.now += 30_000
    refused = await store.charge([charge()], "call-4")
    assert (refused.charged, refused.retry_after_ms) == (False, [30_000])  # the oldest leaves in 30s
    clock.now += 30_000
    assert (await store.charge([charge()], "call-5")).charged  # the first three have left the window


async def test_charges_are_all_or_nothing() -> None:
    store = MemoryBudgetStore(Clock())
    await store.charge([charge("b", amount=3)], "fill-b")
    result = await store.charge([charge("a"), charge("b")], "both")
    assert (result.charged, result.over) == (False, [1])
    assert (await store.charge([charge("a", amount=3)], "only-a")).charged  # "a" was not charged


async def test_charging_the_same_call_twice_counts_it_once() -> None:
    store = MemoryBudgetStore(Clock())
    await store.charge([charge(amount=2)], "same")
    again = await store.charge([charge(amount=2)], "same")
    assert (again.charged, again.used) == (True, [2])
    assert not (await store.charge([charge(amount=2)], "another")).charged


async def test_a_forced_charge_goes_over_and_is_counted() -> None:
    store = MemoryBudgetStore(Clock())
    assert (await store.charge([charge(amount=5, force=True)], "approved")).charged
    assert (await store.charge([charge(amount=0)], "zero")).used == [5]
    assert not (await store.charge([charge(amount=1)], "next")).charged


# -- the stage ------------------------------------------------------------------------------------


async def test_calls_beyond_a_rate_limit_are_refused_with_a_retry_hint() -> None:
    stage = BudgetStage([limit(id="rate", limit=2, per="1m")], MemoryBudgetStore(Clock()))
    assert await stage.on_client_message(call()) is CONTINUE
    assert await stage.on_client_message(call()) is CONTINUE
    ctx = call()
    refusal = text(await stage.on_client_message(ctx))
    assert refusal == (
        "Blocked by gateway budget: limit 'rate' allows 2 calls per 1m; 2 used, this call adds 1. "
        "Try again in about 60s."
    )
    assert ctx.annotations["budget"] == {"limits": "rate", "charged": False, "over": "rate"}


async def test_a_split_payment_is_caught_and_held_for_a_human() -> None:
    daily = limit(id="daily-payments", sum="amount", limit=10000, per="24h", over="approve")
    stage = BudgetStage([daily], MemoryBudgetStore(Clock()))
    assert stage.needs_approvals
    assert await stage.on_client_message(call(amount="9225.00")) is CONTINUE
    second = call(amount="9225.00")
    held = await stage.on_client_message(second)
    assert held == Hold(
        "over budget: limit 'daily-payments' allows 10000 in 'amount' per 24h; "
        "9225 used, this call adds 9225",
        "daily-payments",
    )
    approved = ClientMessageContext(
        second.exchange, second.message, approval=Approval("h1", "alice"), call_id="h1"
    )
    assert await stage.on_client_message(approved) is CONTINUE  # charged, though it goes over
    assert isinstance(
        await stage.on_client_message(call(amount="1")), Hold
    )  # so the next one needs a human too


async def test_a_deny_limit_still_refuses_an_approved_call() -> None:
    limits = [
        limit(id="needs-human", sum="amount", limit=10, per="1h", over="approve"),
        limit(id="hard-cap", sum="amount", limit=100, per="1h"),
    ]
    stage = BudgetStage(limits, MemoryBudgetStore(Clock()))
    ctx = call(amount=500)
    approved = ClientMessageContext(ctx.exchange, ctx.message, approval=Approval("h1", "alice"), call_id="h1")
    assert "limit 'hard-cap' allows 100" in text(await stage.on_client_message(approved))


@pytest.mark.parametrize("amount", [None, "lots", "1e3", True, [5], -1, "-0.01"])
async def test_what_cannot_be_measured_cannot_be_budgeted(amount: Any) -> None:
    stage = BudgetStage([limit(sum="amount", limit=10000)], MemoryBudgetStore(Clock()))
    arguments = {} if amount is None else {"amount": amount}
    refusal = text(await stage.on_client_message(call(**arguments)))
    assert "cannot measure this call (argument 'amount' is missing, not a number, or negative)" in refusal


async def test_fixed_costs_add_up_in_exact_decimals() -> None:
    stage = BudgetStage([limit(id="spend", cost="0.1", limit="0.3", per="1h")], MemoryBudgetStore(Clock()))
    outcomes = [await stage.on_client_message(call("search")) for _ in range(4)]
    assert outcomes[:3] == [CONTINUE] * 3  # 0.1 + 0.1 + 0.1 is exactly 0.3 here
    assert "allows 0.3 in cost per 1h; 0.3 used, this call adds 0.1" in text(outcomes[3])


@pytest.mark.parametrize(
    ("fields", "tool", "identity", "counted"),
    [
        ({"agents": ["ap-*"]}, "t", AP, True),
        ({"agents": ["ap-*"]}, "t", Identity("other"), False),
        ({"agents": ["ap-*"]}, "t", None, False),
        ({"roles": ["finance"]}, "t", Identity("x", frozenset({"finance"})), True),
        ({"roles": ["finance"]}, "t", AP, False),
        ({"tools": ["transfer_*"]}, "transfer_funds", AP, True),
        ({"tools": ["transfer_*"]}, "get_balance", AP, False),
        ({"upstreams": ["finance"]}, "t", AP, True),
        ({"upstreams": ["other"]}, "t", AP, False),
        ({}, "t", None, True),
    ],
)
async def test_limits_apply_to_whom_and_what_they_name(
    fields: dict[str, Any], tool: str, identity: Identity | None, counted: bool
) -> None:
    stage = BudgetStage([limit(limit=1, **fields)], MemoryBudgetStore(Clock()))
    await stage.on_client_message(call(tool, identity))
    second = await stage.on_client_message(call(tool, identity))
    assert isinstance(second, Respond) is counted


async def test_each_agent_has_its_own_counter() -> None:
    stage = BudgetStage([limit(limit=1)], MemoryBudgetStore(Clock()))
    assert await stage.on_client_message(call(identity=AP)) is CONTINUE
    assert await stage.on_client_message(call(identity=Identity("other"))) is CONTINUE
    assert isinstance(await stage.on_client_message(call(identity=AP)), Respond)


async def test_only_tool_calls_are_budgeted() -> None:
    stage = BudgetStage([limit(limit=1)], MemoryBudgetStore(Clock()))
    listing = parse_message(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    ctx = ClientMessageContext(call().exchange, listing)
    for _ in range(3):
        assert await stage.on_client_message(ctx) is CONTINUE


async def test_an_unavailable_store_fails_closed() -> None:
    class Broken(MemoryBudgetStore):
        async def charge(self, charges: Any, member: str) -> ChargeResult:
            raise BudgetStoreError("down")

    refusal = text(await BudgetStage([limit()], Broken()).on_client_message(call()))
    assert refusal == "Blocked by gateway budget: the budget store is unavailable, so the call was refused."


async def test_amounts_are_charged_in_micro_units_rounded_up() -> None:
    seen: list[Charge] = []

    class Spy(MemoryBudgetStore):
        async def charge(self, charges: Any, member: str) -> ChargeResult:
            seen.extend(charges)
            return await super().charge(charges, member)

    await BudgetStage([limit(sum="amount", limit=10)], Spy(Clock())).on_client_message(
        call(amount="0.0000001")
    )
    assert seen[0].amount == 1  # a ten-millionth still costs one micro-unit
    assert seen[0].limit == 10 * MICRO


# -- configuration --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"per": "1 week"}, "per must look like"),
        ({"per": "0s"}, "per must look like"),
        ({"per": "32d"}, "between 1 second and 31 days"),
        ({"sum": "amount", "cost": 1}, "at most one of sum and cost"),
        ({"limit": 0}, "greater than 0"),
    ],
)
def test_bad_limits_are_rejected(fields: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        limit(**fields)


def test_windows_are_parsed() -> None:
    assert [limit(per=per).window_s for per in ("90s", "15m", "24h", "7d")] == [90, 900, 86400, 604800]


@pytest.mark.parametrize(
    ("stages", "message"),
    [
        ([{"type": "budget", "limits": []}], "at least 1 item"),
        (
            [{"type": "budget", "limits": [{"id": "a", "limit": 1, "per": "1m"}] * 2}],
            "duplicate limit id",
        ),
        (
            [{"type": "budget", "limits": [{"id": "a", "limit": 1, "per": "1m"}]}] * 2,
            "one budget stage",
        ),
        (
            [
                {"type": "budget", "limits": [{"id": "a", "limit": 1, "per": "1m"}]},
                {"type": "policy", "file": "p.yaml"},
            ],
            "must come after the policy stage",
        ),
    ],
)
def test_budget_stages_are_checked(stages: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config({"stages": stages, "upstreams": {"f": {"url": "http://f/mcp"}}})
