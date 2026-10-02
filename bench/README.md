# Benchmarks

Numbers the gateway publishes about itself, how they are measured, and how to
reproduce them. Results are committed under `results/`, one file per run,
named by date, each stating the commit, hardware and software it ran on.

## Latency overhead

```bash
uv run python bench/harness/latency.py                  # full run (about 3 minutes), writes results/
uv run python bench/harness/latency.py --smoke --check  # 1 minute, fails on errors or a p50 overhead over 15 ms
```

`full` needs Postgres: the harness starts `postgres:17-alpine` with Docker, or
uses `--postgres-dsn`.

**What is measured.** The time a client waits for `tools/call get_balance`
(stateless 2026-07-28 protocol) to come back, measured at the client with
`perf_counter_ns`: 3,000 calls per cell after 300 warm-up calls, at 1, 10 and
50 concurrent clients, over keep-alive connections. Variants:

| Variant | Path |
| --- | --- |
| `direct` | client → finance server (the baseline) |
| `passthrough` | client → gateway → server, nothing configured |
| `policy` | + JWT authentication and the example finance policy |
| `full` | + durable Postgres audit (every call waits for its row to commit) and OTLP tracing |

**Overhead** is a variant's percentile minus `direct`'s at the same
concurrency. Quote the deltas, not the absolute numbers: the load generator is
Python too, and at high concurrency it adds latency of its own, but it adds
the same amount to every variant.

**Processes.** Load generator, gateway, upstream server and Postgres each
run in their own process (Postgres in a container), so they do not share a
GIL. The gateway is one uvicorn process with uvloop and httptools, as
`customs run` starts it.

**Caveats.**

- On macOS, Docker runs in a VM, so in `full` every audit commit crosses the
  VM boundary. Expect Linux with a local Postgres to do better.
- With 3,000 samples, p99 rests on 30 values. Single-client p99 especially
  moves with background noise; one negative p99 overhead in the first run
  is that noise, not the gateway speeding anything up.
- The CI smoke run uses shared runners. Its threshold catches gross
  regressions only; published numbers come from full runs on stated hardware.

## Reading the first results

See `results/` for the tables. The shape of the first run, and why:

- **One client shows the per-call cost:** under half a millisecond for
  pass-through and for authentication plus policy, and about 1.5 ms with
  durable audit and tracing (most of it the audit commit).
- **At 10 and 50 clients the gateway becomes the bottleneck.** One gateway
  process tops out at roughly 1,000 to 1,500 calls per second, while the MCP
  server behind it handles about 4,000, so queueing dominates the overhead.
  Profiling under load puts the cost in the pure-Python HTTP stack: the
  client's connection pool (`httpcore2` checks every idle socket for
  readability on each request), `h11` header handling and `anyio` socket
  bookkeeping. The gateway's own work (parsing, policy, routing checks) is
  a small share. Options, in order of effort: run several gateway workers
  (each needs its own audit chain), switch the upstream client to a
  C-accelerated one, or move the hot path to a compiled language.
