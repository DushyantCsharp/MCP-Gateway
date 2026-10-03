"""Budget accuracy: how many calls slip past a limit, under concurrency, with one gateway or two.

    uv run python bench/harness/budget.py                       # writes bench/results/budget-v1-<date>.*
    uv run python bench/harness/budget.py --redis redis://...   # an existing Redis, not a container

Each scenario gives every agent a limit, then fires far more calls than it
allows from many concurrent clients, spread round-robin over the gateways. The
upstream counts what actually arrives; the gateway's own report is not used.
A call that arrives past an agent's limit has *slipped*. The build plan's
target is zero.

* ``rate``: 50 calls per agent per hour; 8 agents send 250 calls each.
* ``spend``: 10,000 per agent per hour in the ``amount`` argument; 8 agents
  send 250 payments each, of 1 to 2,500 (seeded), so the limit is reached
  at different points.

Each runs against counters in each gateway process (``memory``) and in Redis,
with one gateway and with two. Two replicas with in-process counters each
admit an agent's full limit: the result shows why replicas must share Redis.
"""

import argparse
import asyncio
import json
import random
import sys
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx2
import jwt

sys.path.insert(0, str(Path(__file__).parent))
from latency import ROOT, environment
from mcp_customs.app import create_app
from mcp_customs.config import parse_config
from serving import serve

VERSION = 1
SECRET = "budget-bench-secret-0123456789abcdef"  # noqa: S105 - signs throwaway local tokens
PROTOCOL = "2026-07-28"
AGENTS = 8
CALLS_PER_AGENT = 250
CLIENTS_PER_AGENT = 25
RATE_LIMIT = 50
SPEND_LIMIT = Decimal(10000)


class Upstream:
    """A minimal MCP server that answers every tools/call and remembers who asked for what."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while (await receive())["type"] != "lifespan.shutdown":
                await send({"type": "lifespan.startup.complete"})
            await send({"type": "lifespan.shutdown.complete"})
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        request = json.loads(body)
        with self._lock:
            self.calls.append(request["params"]["arguments"])
        answer = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"content": [], "isError": False, "resultType": "complete"},
        }
        payload = json.dumps(answer).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": payload})


@contextmanager
def redis_server(url: str | None) -> Iterator[str]:
    if url:
        yield url
        return
    from testcontainers.community.redis import RedisContainer

    with RedisContainer("redis:7-alpine") as container:
        yield f"redis://{container.get_container_host_ip()}:{container.get_exposed_port(6379)}/0"


@dataclass
class Outcome:
    scenario: str
    store: str
    gateways: int
    limit: str
    sent: int
    arrived: int
    refused: int
    errors: int
    slipped: str
    """Calls (or amount) that arrived past an agent's limit, summed over agents."""
    worst_agent: str
    """The most any one agent got past its limit."""
    headroom: str
    """How far below its limit an agent was stopped, at most: the cost of stopping early under contention."""
    seconds: float
    error_samples: list[str]


def token(agent: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": agent, "aud": "mcp-customs", "iat": now, "exp": now + 3600}, SECRET, algorithm="HS256"
    )


async def fire(urls: list[str], calls: list[tuple[str, dict[str, Any]]]) -> tuple[int, int, list[str]]:
    """Send every call, CLIENTS_PER_AGENT at a time per agent; return (refused, errors, error samples)."""
    refused = errors = 0
    samples: list[str] = []
    tokens = {agent: token(agent) for agent, _ in calls}
    queues: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for agent, arguments in calls:
        queues[agent].append(arguments)

    async def client(http: httpx2.AsyncClient, agent: str, offset: int) -> None:
        nonlocal refused, errors
        queue = queues[agent]
        while queue:
            arguments = queue.pop()
            url = urls[offset % len(urls)]
            offset += 1
            body = {
                "jsonrpc": "2.0",
                "id": uuid.uuid4().hex,
                "method": "tools/call",
                "params": {
                    "name": "pay",
                    "arguments": arguments,
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": PROTOCOL,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                },
            }
            headers = {
                "accept": "application/json, text/event-stream",
                "authorization": f"Bearer {tokens[agent]}",
                "mcp-protocol-version": PROTOCOL,
                "mcp-method": "tools/call",
                "mcp-name": "pay",
            }
            try:
                answer = (await http.post(url, json=body, headers=headers)).json()
            except (httpx2.HTTPError, ValueError) as exc:
                errors += 1
                samples.append(f"{type(exc).__name__}: {exc}"[:200])
                continue
            result = answer.get("result", {})
            text = " ".join(block.get("text", "") for block in result.get("content", []))
            if result.get("isError") and "unavailable" in text:
                errors += 1  # refused because the budget store failed, not because of the limit
                samples.append(text[:200])
            elif result.get("isError"):
                refused += 1
            elif "error" in answer:
                errors += 1
                samples.append(json.dumps(answer["error"])[:200])

    limits = httpx2.Limits(max_connections=AGENTS * CLIENTS_PER_AGENT)
    async with httpx2.AsyncClient(limits=limits, timeout=60) as http:
        await asyncio.gather(*(client(http, agent, n) for agent in queues for n in range(CLIENTS_PER_AGENT)))
    return refused, errors, samples


def scenario_calls(scenario: str, run: str) -> list[tuple[str, dict[str, Any]]]:
    rng = random.Random(f"{scenario}-{VERSION}")  # noqa: S311 - reproducible amounts, not secrets
    calls = []
    for a in range(AGENTS):
        agent = f"agent-{run}-{a}"
        for n in range(CALLS_PER_AGENT):
            amount = f"{rng.randint(100, 250000) / 100:.2f}"
            calls.append((agent, {"agent": agent, "n": n, "amount": amount}))
    return calls


def limit_config(scenario: str, run: str) -> dict[str, Any]:
    if scenario == "rate":
        return {"id": f"rate-{run}", "limit": RATE_LIMIT, "per": "1h"}
    return {"id": f"spend-{run}", "sum": "amount", "limit": str(SPEND_LIMIT), "per": "1h"}


def measure(scenario: str, store: str, gateways: int, redis_url: str) -> Outcome:
    run = uuid.uuid4().hex[:8]
    upstream = Upstream()
    with ExitStack() as stack:
        upstream_url = stack.enter_context(serve(upstream))
        budget: dict[str, Any] = {"type": "budget", "limits": [limit_config(scenario, run)]}
        if store == "redis":
            budget["redis"] = redis_url
        config = parse_config(
            {
                "auth": {"jwt": {"audience": "mcp-customs", "secret": SECRET}},
                "stages": [budget],
                "upstreams": {"pay": {"url": f"{upstream_url}/mcp"}},
            }
        )
        urls = [f"{stack.enter_context(serve(create_app(config)))}/mcp/pay" for _ in range(gateways)]
        calls = scenario_calls(scenario, run)
        started = time.perf_counter()
        refused, errors, samples = asyncio.run(fire(urls, calls))
        seconds = time.perf_counter() - started

    by_agent: dict[str, list[Decimal]] = defaultdict(list)
    for arguments in upstream.calls:
        by_agent[arguments["agent"]].append(Decimal(arguments["amount"]))
    agents = sorted({agent for agent, _ in calls})
    if scenario == "rate":
        used = {agent: Decimal(len(by_agent[agent])) for agent in agents}
        limit = Decimal(RATE_LIMIT)
    else:
        used = {agent: sum(by_agent[agent], Decimal(0)) for agent in agents}
        limit = SPEND_LIMIT
    over = {agent: max(Decimal(0), value - limit) for agent, value in used.items()}
    under = {agent: max(Decimal(0), limit - value) for agent, value in used.items()}
    return Outcome(
        scenario=scenario,
        store=store,
        gateways=gateways,
        limit=f"{limit} per agent",
        sent=len(calls),
        arrived=len(upstream.calls),
        refused=refused,
        errors=errors,
        slipped=str(sum(over.values(), Decimal(0))),
        worst_agent=str(max(over.values())),
        headroom=str(max(under.values())),
        seconds=round(seconds, 2),
        error_samples=sorted(set(samples))[:5],
    )


def markdown(env: dict[str, Any], outcomes: list[Outcome]) -> str:
    failures = [(o, sample) for o in outcomes for sample in o.error_samples]
    errors = (
        "\n*Errors* (calls that got no budget decision):\n\n"
        + "\n".join(f"- {o.scenario}, {o.store} x{o.gateways}: `{sample}`" for o, sample in failures)
        + "\n"
        if failures
        else ""
    )
    rows = "\n".join(
        f"| {o.scenario} | {o.store} | {o.gateways} | {o.limit} | {o.sent} | {o.arrived} | {o.refused} | "
        f"{o.errors} | **{o.slipped}** | {o.worst_agent} | {o.headroom} |"
        for o in outcomes
    )
    where = f"commit `{env['commit']}` on {env['cpu']} ({env['cores']} cores), Python {env['python']}"
    header = (
        "| Scenario | Counters | Gateways | Limit | Sent | Arrived | Refused | Errors | Slipped "
        "| Worst agent | Headroom |"
    )
    return f"""# Budget accuracy

Measured {env["date"]} at {where}.
{AGENTS} agents, {CALLS_PER_AGENT} calls each, {CLIENTS_PER_AGENT} concurrent clients per agent,
spread round-robin over the gateways. Counted at the upstream.

{header}
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
{rows}

*Slipped*: what arrived past an agent's limit, summed over agents (calls for `rate`, amount for
`spend`). *Worst agent*: the most one agent got past its limit. *Headroom*: how far below its limit
an agent was stopped, at most. With amounts up to 2,500, a payment that would not fit is refused
even if a smaller one later would have: budgets stop early rather than late.
{errors}"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--redis", help="Redis URL; default: a throwaway container")
    parser.add_argument("--force", action="store_true", help="overwrite today's results")
    parser.add_argument(
        "--out", type=Path, default=ROOT / "bench" / "results", help="directory for the results"
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / f"budget-v{VERSION}-{datetime.now(UTC):%Y-%m-%d}"
    if out.with_suffix(".md").exists() and not args.force:
        raise SystemExit(f"{out}.md exists; pass --force to replace it")
    env = environment()  # before measuring: the commit recorded is the code that runs
    outcomes: list[Outcome] = []
    with redis_server(args.redis) as redis_url:
        for scenario in ("rate", "spend"):
            for store in ("memory", "redis"):
                for gateways in (1, 2):
                    outcome = measure(scenario, store, gateways, redis_url)
                    print(
                        f"{scenario:5} {store:6} x{gateways}: arrived {outcome.arrived}/{outcome.sent}, "
                        f"slipped {outcome.slipped}, headroom {outcome.headroom}, errors {outcome.errors}",
                        flush=True,
                    )
                    outcomes.append(outcome)
    out.with_suffix(".json").write_text(
        json.dumps(
            {"version": VERSION, "environment": env, "outcomes": [asdict(o) for o in outcomes]}, indent=2
        )
        + "\n"
    )
    out.with_suffix(".md").write_text(markdown(env, outcomes))
    print(f"wrote {out}.md")


if __name__ == "__main__":
    main()
