"""Rolling-window counters: Redis in production, memory for one process.

A charge adds an amount to one counter, provided the counter's total over the
last ``window_ms`` stays within its limit. A call usually makes several
charges (one per limit that applies to it), and they are all-or-nothing: if
any would go over, none is made. In Redis this is one Lua script, so it is
atomic across every gateway sharing the server: concurrent calls cannot slip
past a limit between a check and an increment.

Amounts are integers in millionths (micro-units), so a cost of 0.000001 is
exact and sums never drift the way floating point does. Each entry is kept in
a sorted set scored by time, next to a running total: an expired entry is
subtracted when it leaves the window, so a charge costs O(log n), not a sum
over the window. Charges are idempotent per member (one call's id): charging
the same call twice counts it once.
"""

import asyncio
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

MICRO: Final = 1_000_000
MAX_AMOUNT: Final = 10**15
"""The largest single charge counted (a billion units), so one absurd amount cannot overflow Redis."""


@dataclass(frozen=True, slots=True)
class Charge:
    key: str
    amount: int
    """Micro-units this call adds."""
    limit: int
    """Micro-units the window may hold."""
    window_ms: int
    force: bool = False
    """Charge even if it goes over: a human approved going over this limit."""


@dataclass(frozen=True, slots=True)
class ChargeResult:
    charged: bool
    used: list[int]
    """Each counter's total before this call, in micro-units."""
    over: list[int] = field(default_factory=list)
    """Indexes of the charges that would have gone over (and were not forced)."""
    retry_after_ms: list[int] = field(default_factory=list)
    """Per counter: when its oldest entry leaves the window (0 when empty)."""


class BudgetStoreError(RuntimeError):
    """The budget store cannot be used."""


class BudgetStore(Protocol):
    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def charge(self, charges: Sequence[Charge], member: str) -> ChargeResult: ...


@dataclass(slots=True)
class _Counter:
    entries: deque[tuple[int, str, int]] = field(default_factory=deque)
    """(time in ms, member, amount), oldest first."""
    total: int = 0


class MemoryBudgetStore:
    """Counters in this process: right for one gateway, wrong for several (each would count alone)."""

    def __init__(self, clock_ms: Callable[[], int] | None = None) -> None:
        self._clock = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._counters: dict[str, _Counter] = {}
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def charge(self, charges: Sequence[Charge], member: str) -> ChargeResult:
        async with self._lock:
            now = self._clock()
            used: list[int] = []
            over: list[int] = []
            retry: list[int] = []
            amounts: list[int] = []
            for index, charge in enumerate(charges):
                counter = self._counters.setdefault(charge.key, _Counter())
                while counter.entries and counter.entries[0][0] <= now - charge.window_ms:
                    counter.total -= counter.entries.popleft()[2]
                amount = 0 if any(entry[1] == member for entry in counter.entries) else charge.amount
                amounts.append(amount)
                used.append(counter.total)
                retry.append(max(0, counter.entries[0][0] + charge.window_ms - now) if counter.entries else 0)
                if counter.total + amount > charge.limit and not charge.force:
                    over.append(index)
            if over:
                return ChargeResult(False, used, over, retry)
            for charge, amount in zip(charges, amounts, strict=True):
                if amount:
                    counter = self._counters[charge.key]
                    counter.entries.append((now, member, amount))
                    counter.total += amount
            return ChargeResult(True, used, [], retry)


_CHARGE: Final = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local member = ARGV[1]
local n = #KEYS / 2
local used, over, retry, amounts = {}, {}, {}, {}
for i = 1, n do
  local zkey, tkey = KEYS[2 * i - 1], KEYS[2 * i]
  local base = 1 + (i - 1) * 4
  local amount = tonumber(ARGV[base + 1])
  local limit = tonumber(ARGV[base + 2])
  local window = tonumber(ARGV[base + 3])
  local force = ARGV[base + 4] == '1'
  local cutoff = now - window
  local total = tonumber(redis.call('GET', tkey) or '0')
  local expired = redis.call('ZRANGEBYSCORE', zkey, '-inf', cutoff)
  if #expired > 0 then
    for _, entry in ipairs(expired) do
      total = total - tonumber(string.match(entry, ':(%d+)$'))
    end
    redis.call('ZREMRANGEBYSCORE', zkey, '-inf', cutoff)
    if total < 0 then total = 0 end
    redis.call('SET', tkey, string.format('%d', total), 'PX', window)
  end
  if redis.call('ZSCORE', zkey, member .. ':' .. ARGV[base + 1]) then amount = 0 end
  amounts[i] = amount
  used[i] = total
  local oldest = redis.call('ZRANGE', zkey, 0, 0, 'WITHSCORES')
  if #oldest > 0 then
    retry[i] = math.max(0, tonumber(oldest[2]) + window - now)
  else
    retry[i] = 0
  end
  if total + amount > limit and not force then over[#over + 1] = i - 1 end
end
if #over > 0 then return {0, used, over, retry} end
for i = 1, n do
  if amounts[i] > 0 then
    local zkey, tkey = KEYS[2 * i - 1], KEYS[2 * i]
    local base = 1 + (i - 1) * 4
    local window = tonumber(ARGV[base + 3])
    redis.call('ZADD', zkey, now, member .. ':' .. ARGV[base + 1])
    redis.call('INCRBY', tkey, ARGV[base + 1])
    redis.call('PEXPIRE', zkey, window)
    redis.call('PEXPIRE', tkey, window)
  end
end
return {1, used, over, retry}
"""


class RedisBudgetStore:
    """Counters shared by every gateway that uses the same Redis. Redis must not evict keys
    (``maxmemory-policy noeviction``): an evicted counter forgets what was spent."""

    def __init__(self, url: str, *, prefix: str = "customs:budget:") -> None:
        import redis.asyncio as redis

        self._client: Any = redis.Redis.from_url(url)
        self._script: Any = self._client.register_script(_CHARGE)
        self._prefix = prefix

    async def open(self) -> None:
        import redis

        try:
            await self._client.ping()
        except redis.RedisError as exc:
            raise BudgetStoreError(f"cannot reach the budget store: {exc}") from exc

    async def close(self) -> None:
        await self._client.aclose()

    async def charge(self, charges: Sequence[Charge], member: str) -> ChargeResult:
        import redis

        keys: list[str] = []
        args: list[str] = [member]
        for charge in charges:
            keys += [f"{self._prefix}{charge.key}", f"{self._prefix}{charge.key}:total"]
            args += [
                str(charge.amount),
                str(charge.limit),
                str(charge.window_ms),
                "1" if charge.force else "0",
            ]
        try:
            charged, used, over, retry = await self._script(keys=keys, args=args)
        except redis.RedisError as exc:
            raise BudgetStoreError(f"budget store failed: {exc}") from exc
        return ChargeResult(
            bool(charged), [int(value) for value in used], [int(i) for i in over], [int(ms) for ms in retry]
        )
