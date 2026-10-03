# Contributing

Thank you for helping. Issues and pull requests are welcome.

## Set up

```bash
uv sync --group bench          # the gateway, demo servers, dev tools and benchmark extras
uv run pre-commit install      # format, lint and type-check before each commit
uv run pytest                  # unit and contract tests (Docker for the Postgres and Redis ones)
```

## What a change needs

- **Tests.** Contract tests drive the official MCP SDK through a running
  gateway; a change to what crosses the gateway needs one. CI keeps coverage
  above 90% and runs on Python 3.12 and 3.13.
- **No silent security changes.** Anything that changes what is allowed,
  held, redacted or recorded says so in its description, and in the
  [architecture](docs/architecture.md) or [policy reference](docs/policy-reference.md).
- **Numbers from the harness.** A claim about detection, latency or budgets
  comes with a result produced by `bench/`, never overwriting a published one.

## Benchmark data

Attack samples come only from published, licensed benchmarks, pinned to a
commit and listed in [bench/datasets/SOURCES.md](bench/datasets/SOURCES.md);
they are rebuilt, not committed. Results list misses by id, never by text.

## Security issues

Please do not open public issues for vulnerabilities: see [SECURITY.md](SECURITY.md).
