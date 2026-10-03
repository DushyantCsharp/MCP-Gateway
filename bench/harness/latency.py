"""Latency overhead of the gateway: p50 and p99 added per call, at 1, 10 and 50 concurrent clients.

    uv run python bench/harness/latency.py                  # full run, writes bench/results/
    uv run python bench/harness/latency.py --smoke --check  # quick CI run with thresholds

Every component runs in its own process: the load generator (this script),
the gateway, the upstream MCP server and, for the ``full`` variant, Postgres
in a container. Variants, each measured against the same upstream:

``direct``       client -> finance server (the baseline)
``passthrough``  client -> gateway -> server, nothing configured
``policy``       + JWT authentication and the example finance policy (its approve
                 rule removed: ``get_balance`` never needs a human, and this
                 variant has no approvals store)
``full``         + durable Postgres audit and OTLP tracing

The call is ``tools/call get_balance`` over the stateless 2026-07-28 protocol:
a real tool, cheap enough that the gateway's share of the latency shows.
Overhead is a variant's percentile minus the direct percentile at the same
concurrency. The generator is Python, so at high concurrency it adds latency
of its own; it adds the same to every variant, which is why the deltas are
the numbers to quote, not the absolutes.
"""

import argparse
import asyncio
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
from pathlib import Path
from typing import Any

import httpx2
import jwt
import yaml

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policies" / "examples" / "finance-agent.yaml"
SECRET = "benchmark-secret-for-hs256-tokens-only-0123456789"  # noqa: S105 - benchmark-only signing key
PROTOCOL = "2026-07-28"
VARIANTS = ("direct", "passthrough", "policy", "full")


@dataclass
class Stats:
    variant: str
    concurrency: int
    requests: int
    errors: int
    p50_ms: float
    p90_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float
    throughput_rps: float


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


def wait_ready(url: str, timeout_s: float = 30) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if httpx2.get(url, timeout=1).status_code == 200:
                return
        except httpx2.HTTPError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"{url} did not become ready")


@contextmanager
def process(args: list[str], log: Path, env: dict[str, str] | None = None) -> Iterator[None]:
    with log.open("w") as out:
        proc = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT, env={**os.environ, **(env or {})})  # noqa: S603
    try:
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


class _Sink(BaseHTTPRequestHandler):
    """Accepts OTLP exports and discards them, so tracing costs what it would against a collector."""

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self.send_response(200)
        self.send_header("content-type", "application/x-protobuf")
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


@contextmanager
def otlp_sink() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


@contextmanager
def postgres(dsn: str | None) -> Iterator[str]:
    if dsn:
        yield dsn
        return
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:17-alpine", driver=None) as container:
        yield container.get_connection_url()


def latency_policy(work: Path) -> Path:
    """The example finance policy without approve rules: the measured call is never held."""
    document = yaml.safe_load(POLICY.read_text())
    document["rules"] = [rule for rule in document["rules"] if rule["effect"] != "approve"]
    path = work / "latency-policy.yaml"  # not policy.yaml: that is the policy variant's gateway config
    path.write_text(yaml.safe_dump(document, sort_keys=False))
    return path


def gateway_config(
    variant: str, upstream: str, port: int, dsn: str | None, otlp: str | None, policy: Path
) -> str:
    lines = [f"server: {{host: 127.0.0.1, port: {port}}}", "upstreams:", f"  finance: {{url: '{upstream}'}}"]
    if variant in ("policy", "full"):
        lines += ["auth:", "  jwt: {audience: mcp-customs, secret: '" + SECRET + "'}"]
        lines += ["stages:", f"  - {{type: policy, file: '{policy}'}}"]
    if variant == "full":
        lines += ["audit:", f"  dsn: '{dsn}'", f"  chain: bench-{int(time.time())}", "  key: bench-key"]
        lines += ["telemetry:", f"  otlp_endpoint: '{otlp}'"]
    return "\n".join(lines) + "\n"


def token() -> str:
    now = int(time.time())
    claims = {"sub": "ap-agent", "aud": "mcp-customs", "iat": now, "exp": now + 3600}
    return jwt.encode(claims, SECRET, algorithm="HS256")


def call_body(n: int) -> bytes:
    meta = {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL,
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    params = {"name": "get_balance", "arguments": {"account_id": "ACC-OPERATING"}, "_meta": meta}
    return json.dumps({"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": params}).encode()


async def measure(url: str, variant: str, concurrency: int, requests: int, warmup: int) -> Stats:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-protocol-version": PROTOCOL,
        "mcp-method": "tools/call",
        "mcp-name": "get_balance",
        "mcp-param-account": "ACC-OPERATING",
    }
    if variant in ("policy", "full"):
        headers["authorization"] = f"Bearer {token()}"
    limits = httpx2.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    latencies: list[float] = []
    errors = 0
    async with httpx2.AsyncClient(limits=limits, headers=headers, timeout=30) as http:
        counter = iter(range(warmup + requests))
        lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal errors
            while True:
                async with lock:
                    n = next(counter, None)
                if n is None:
                    return
                started = time.perf_counter_ns()
                response = await http.post(url, content=call_body(n))
                elapsed = (time.perf_counter_ns() - started) / 1e6
                ok = response.status_code == 200 and '"isError":false' in response.text
                if n >= warmup:
                    latencies.append(elapsed)
                    errors += not ok

        began = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(concurrency)))
        wall = time.perf_counter() - began
    latencies.sort()
    quantiles = statistics.quantiles(latencies, n=100, method="inclusive")
    return Stats(
        variant=variant,
        concurrency=concurrency,
        requests=len(latencies),
        errors=errors,
        p50_ms=round(statistics.median(latencies), 3),
        p90_ms=round(quantiles[89], 3),
        p99_ms=round(quantiles[98], 3),
        max_ms=round(latencies[-1], 3),
        mean_ms=round(statistics.fmean(latencies), 3),
        throughput_rps=round((warmup + requests) / wall, 1),
    )


def environment() -> dict[str, Any]:
    cpu = platform.processor() or platform.machine()
    if sys.platform == "darwin":
        cpu = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
        ).stdout.strip()
    elif Path("/proc/cpuinfo").exists():
        names = [
            line.split(":", 1)[1].strip()
            for line in Path("/proc/cpuinfo").read_text().splitlines()
            if line.startswith("model name")
        ]
        cpu = names[0] if names else cpu
    memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") if hasattr(os, "sysconf") else 0
    git = shutil.which("git") or "git"
    commit = subprocess.run([git, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT)  # noqa: S603
    dirty = subprocess.run(  # noqa: S603 - fixed arguments
        [git, "status", "--porcelain", "--", "src", "demo"], capture_output=True, text=True, cwd=ROOT
    )
    commit_id = commit.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")
    return {
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "commit": commit_id,
        "cpu": cpu,
        "cores": os.cpu_count(),
        "memory_gb": round(memory / 2**30, 1),
        "os": platform.platform(),
        "load_average_1m": round(os.getloadavg()[0], 2) if hasattr(os, "getloadavg") else None,
        "python": platform.python_version(),
        "versions": {
            pkg: version(pkg) for pkg in ("mcp-customs", "mcp", "uvicorn", "httpx2", "fastapi", "psycopg")
        },
    }


def markdown(env: dict[str, Any], results: list[Stats], requests: int) -> str:
    base = {stats.concurrency: stats for stats in results if stats.variant == "direct"}
    lines = [
        "# Latency overhead",
        "",
        f"Measured {env['date']} at commit `{env['commit']}` on {env['cpu']} ({env['cores']} cores, "
        f"{env['memory_gb']} GB, 1-minute load {env['load_average_1m']} at the start), {env['os']}, "
        f"Python {env['python']}. "
        f"{requests} measured calls per cell after warm-up; `tools/call get_balance`, protocol {PROTOCOL}.",
        "",
        "Overhead is the gateway variant's percentile minus the direct percentile at the same concurrency.",
        "",
        "| Variant | Clients | p50 ms | p99 ms | p50 overhead ms | p99 overhead ms | calls/s | errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for stats in results:
        direct = base[stats.concurrency]
        overhead = (
            ("-", "-")
            if stats.variant == "direct"
            else (f"{stats.p50_ms - direct.p50_ms:+.2f}", f"{stats.p99_ms - direct.p99_ms:+.2f}")
        )
        lines.append(
            f"| {stats.variant} | {stats.concurrency} | {stats.p50_ms:.2f} | {stats.p99_ms:.2f} | "
            f"{overhead[0]} | {overhead[1]} | {stats.throughput_rps:.0f} | {stats.errors} |"
        )
    lines += ["", "Software: " + ", ".join(f"{k} {v}" for k, v in env["versions"].items()) + "."]
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> tuple[dict[str, Any], list[Stats]]:
    work = Path(tempfile.mkdtemp(prefix="customs-bench-"))
    finance_port = free_port()
    results: list[Stats] = []
    with ExitStack() as stack:
        server = shutil.which("customs-demo-finance") or "customs-demo-finance"
        stack.enter_context(process([server, "--port", str(finance_port)], work / "finance.log"))
        upstream = f"http://127.0.0.1:{finance_port}/mcp"
        wait_ready(f"http://127.0.0.1:{finance_port}/healthz")
        dsn = otlp = None
        if "full" in args.variants:
            dsn = stack.enter_context(postgres(args.postgres_dsn))
            otlp = stack.enter_context(otlp_sink())
        for variant in args.variants:
            url = upstream
            with ExitStack() as gateway:
                if variant != "direct":
                    port = free_port()
                    config = work / f"{variant}.yaml"
                    config.write_text(
                        gateway_config(variant, upstream, port, dsn, otlp, latency_policy(work))
                    )
                    customs = shutil.which("customs") or "customs"
                    gateway.enter_context(
                        process(
                            [customs, "run", "-c", str(config), "--log-level", "warning"],
                            work / f"{variant}.log",
                        )
                    )
                    wait_ready(f"http://127.0.0.1:{port}/readyz")
                    url = f"http://127.0.0.1:{port}/mcp/finance"
                for concurrency in args.concurrency:
                    stats = asyncio.run(measure(url, variant, concurrency, args.requests, args.warmup))
                    timing = f"p50 {stats.p50_ms:7.2f} ms  p99 {stats.p99_ms:7.2f} ms"
                    rate = f"{stats.throughput_rps:7.0f}/s  errors {stats.errors}"
                    print(f"{variant:12} c={concurrency:<3} {timing}  {rate}", flush=True)
                    results.append(stats)
    return environment(), results


def check(results: list[Stats], max_p50_overhead_ms: float) -> list[str]:
    base = {stats.concurrency: stats for stats in results if stats.variant == "direct"}
    failures = [f"{s.variant} c={s.concurrency}: {s.errors} errors" for s in results if s.errors]
    overheads = [(s, s.p50_ms - base[s.concurrency].p50_ms) for s in results if s.variant != "direct"]
    failures.extend(
        f"{s.variant} c={s.concurrency}: p50 overhead {overhead:.2f} ms > {max_p50_overhead_ms} ms"
        for s, overhead in overheads
        if overhead > max_p50_overhead_ms
    )
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--variants", nargs="+", choices=VARIANTS, default=list(VARIANTS))
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1, 10, 50])
    parser.add_argument("--requests", type=int, default=3000, help="measured calls per cell")
    parser.add_argument("--warmup", type=int, default=300)
    parser.add_argument("--postgres-dsn", help="use this Postgres instead of starting a container")
    parser.add_argument("--out", type=Path, default=ROOT / "bench" / "results")
    parser.add_argument("--smoke", action="store_true", help="short run: 500 calls per cell, 10 clients")
    parser.add_argument(
        "--check",
        type=float,
        nargs="?",
        const=15.0,
        metavar="MS",
        help="fail if any variant's p50 overhead exceeds MS (default 15) or any call errors",
    )
    args = parser.parse_args()
    if args.smoke:
        args.requests, args.warmup, args.concurrency = 500, 100, [10]

    env, results = run(args)
    if not args.smoke:
        args.out.mkdir(parents=True, exist_ok=True)
        stamp = env["date"][:10]
        (args.out / f"latency-{stamp}.json").write_text(
            json.dumps({"environment": env, "results": [asdict(r) for r in results]}, indent=2) + "\n"
        )
        (args.out / f"latency-{stamp}.md").write_text(markdown(env, results, args.requests))
        print(f"wrote {args.out}/latency-{stamp}.md")
    if args.check is not None and (failures := check(results, args.check)):
        sys.exit("latency check failed:\n  " + "\n  ".join(failures))


if __name__ == "__main__":
    main()
