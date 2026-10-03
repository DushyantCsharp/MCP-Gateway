# Changelog

## 0.1.0 (2026-10-03)

The first release: a security and governance gateway for MCP, built over
eight milestones. The [build notes](docs/build-notes.md) record what was found
along the way, milestone by milestone.

**The proxy**
- A transparent Streamable HTTP reverse proxy at `/mcp/<upstream>`, for both
  protocol eras: the session-based revisions (2024-11-05 to 2025-11-25) and
  the stateless 2026-07-28 revision.
- Strict JSON-RPC (duplicate keys, `NaN`, batches and routing-header
  mismatches refused), no token passthrough, and an SSE relay that keeps
  unchanged events byte for byte.
- Local (stdio) MCP servers as upstreams, one process per session, with no
  inherited secrets; `customs stdio` for clients that only launch local
  servers.

**Who and what**
- JWT identity (shared secret, public key or JWKS), task-scoped `mcp:` grants,
  and session ids bound to their agent.
- YAML policy, default deny: deny beats approve, approve beats allow, and an
  argument the gateway cannot check never lets a call through.

**Humans and limits**
- Approvals: held calls in Postgres that survive a gateway restart, decided at
  `/approvals`, through its JSON API or with `customs approvals`, and made at
  most once.
- Budgets: per-agent rate, sum and cost limits across calls, atomic in Redis.

**Data**
- Redaction of secrets and personal data, in both directions.
- Injection checks on tool results: hidden-text rules layered with an ONNX
  classifier, in `flag`, `strip` or `block` mode.

**The record**
- A hash-chained audit log in Postgres with `customs verify-audit`, durable by
  default.
- OpenTelemetry traces following the MCP and GenAI semantic conventions.

**Evidence**
- A detection benchmark built from InjecAgent, with a datasheet, a held-out
  test split and every miss listed by id; latency and budget-accuracy
  harnesses; and `bench/reproduce.py`, which reruns them from a fresh clone.
- Not included: an end-to-end evaluation of attack success against a live
  agent (see the Weekend 7 build notes).
