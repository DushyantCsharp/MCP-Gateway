# mcp-customs

A security and governance gateway for MCP. It sits between an agent and its
MCP servers and inspects every message in both directions: what goes out,
what comes back, and what should not cross at all.

> **Status: pre-release: identity, policy, audit and tracing.** With them
> configured, every request is authenticated, every tool call is checked
> against a policy and recorded in a hash-chained audit log before it runs,
> and every exchange is traced, in both MCP protocol eras. Injection
> detection, redaction, approvals and budgets land over the coming milestones
> (see the [roadmap](#roadmap)). Until then the gateway does not inspect tool
> results for injected instructions.
>
> Benchmark results (detection rate, false-positive rate, latency overhead,
> and attack success rate with the gateway off vs on) will lead this README
> once they exist. Nothing is claimed before it is measured.

## Quick start

Requires Docker.

```bash
docker compose -f demo/compose.yaml up --build --wait
docker compose -f demo/compose.yaml run --rm agent                            # TASK COMPLETE
docker compose -f demo/compose.yaml run --rm -e AGENT_TASK=pay-invoice agent  # TASK BLOCKED
docker compose -f demo/compose.yaml exec gateway customs verify-audit --key-env CUSTOMS_AUDIT_KEY
open http://localhost:16686                                                   # the traces, in Jaeger
```

This starts two sample MCP servers (`workspace`: documents and email;
`finance`: balances and transfers) with the gateway in front of them. The
gateway requires tokens and enforces the
[example finance policy](policies/examples/finance-agent.yaml). A stand-in
identity provider mints the agent's token, and a scripted agent then
summarises an invoice (allowed) and tries to pay it. The payment of 18,450 is
over the policy's 10,000 single-approver limit, so the gateway blocks it and
the agent reads why. To try other identities, add
`-e MCP_BEARER_TOKEN_FILE=/tokens/auditor.jwt` (read-only) or
`/tokens/intruder.jwt` (sees no tools at all).

Every call, including the blocked payment and the refused token, is in the
audit log, which `verify-audit` re-hashes end to end. Every call also has a
trace in Jaeger, with a span per pipeline stage.

If ports 8000 to 8002 or 16686 are taken, set `CUSTOMS_PORT`,
`WORKSPACE_PORT`, `FINANCE_PORT` or `JAEGER_PORT`.

## Drop-in

Point the client at the gateway instead of the server, and give it a token.
No agent code changes.

```diff
 {
   "mcpServers": {
     "workspace": {
-      "url": "http://workspace.internal:8001/mcp"
+      "url": "http://customs.internal:8000/mcp/workspace",
+      "headers": {"Authorization": "Bearer ${AGENT_TOKEN}"}
     }
   }
 }
```

```yaml
# customs.yaml
server:
  host: 0.0.0.0
  port: 8000
auth:
  jwt:
    audience: mcp-customs
    issuer: https://idp.example.com/
    jwks_url: https://idp.example.com/.well-known/jwks.json
stages:
  - type: policy
    file: policies/finance-agent.yaml
upstreams:
  workspace:
    url: http://workspace.internal:8001/mcp
  finance:
    url: http://finance.internal:8002/mcp
    headers:
      Authorization: Bearer ${FINANCE_MCP_TOKEN}  # the upstream's own credential, injected by the gateway
```

```bash
customs check-config -c customs.yaml        # validates the config and every policy it loads
customs check-policy policies/finance-agent.yaml --agent ap-agent --upstream finance \
  --tool transfer_funds --arguments '{"from_account": "ACC-OPERATING", "to_account": "ACC-NORTHWIND", "amount": "18450.00", "memo": "INV-2026-091"}'
customs run -c customs.yaml
customs token issue --agent ap-agent        # HS256 development tokens from $CUSTOMS_JWT_SECRET
```

Both MCP transport eras work through the same endpoint: the session-based
revisions (2024-11-05 to 2025-11-25) and the stateless 2026-07-28 revision.

## Identity and policy

- **Every request is authenticated** once `auth` is configured: a JWT verified against a shared
  secret, a public key or the issuer's JWKS, and issued for the gateway's
  audience. Streams and session ends need one too.
- **Sessions belong to their agent.** Session ids are HMAC-bound to the agent
  that opened them; another agent's token cannot reuse one.
- **Deny by default, deny beats allow.** Rules match agent, role, upstream,
  tool and argument constraints. An argument the gateway cannot check (wrong
  type, missing, too long) never satisfies an allow rule and always triggers a
  deny rule.
- **Task-scoped tokens.** `mcp:<upstream>:<tool>` scope entries narrow a
  token to what one task needs. They can only narrow the policy, never widen it.
- **Least visibility.** Tool, prompt and resource listings are filtered to
  what the caller may use.
- **Readable denials.** A blocked tool call returns a tool error the model
  can read and recover from. The upstream never sees the call.

The enforcement suite proves the last point at the upstream, not by
trusting the gateway's own report. A recorder wrapped around each real server
checks a 40-case decision table in both protocol eras (29 of 29 disallowed
calls blocked, 11 of 11 allowed calls delivered), plus 300 fuzzed transfers per
run, against an independent restatement of the policy. See the
[policy reference](docs/policy-reference.md).

## Audit and tracing

- **Recorded before it runs.** A call's audit row commits before the call is
  forwarded. If the log cannot be written, the call is refused (503), not
  run unaudited. Writes are batched into shared commits, so durability costs
  about one round trip per batch rather than per call.
- **Tamper-evident, not a ledger.** Each row hashes the previous one
  (HMAC-SHA256 with a key), triggers refuse `UPDATE`, `DELETE` and `TRUNCATE`,
  and `customs verify-audit` reports the first broken link. Someone with
  database access and the key can still rewrite history consistently;
  [architecture](docs/architecture.md#audit) says exactly what this does and
  does not protect against.
- **Private by default.** Arguments are recorded as a SHA-256 digest unless
  you opt in.
- **One trace per call** with MCP and GenAI semantic-convention attributes,
  a span per pipeline stage and one for the upstream, joined to the agent's
  trace through `_meta.traceparent`. Audit rows carry the trace id.
- **Loud about gaps.** At start-up the gateway logs what it enforces, and
  warns if authentication, policy or audit is off.

## Performance

What the gateway adds to a `tools/call` (Apple M4, one gateway process;
[full results and method](bench/README.md)):

| With one client | p50 added | p99 added |
| --- | ---: | ---: |
| pass-through | +0.40 ms | noise* |
| + JWT auth and policy | +0.47 ms | noise* |
| + durable audit and tracing | +1.57 ms | +7.1 ms |

\*Below the direct baseline's own p99 variation in this run.

One gateway process tops out at about 1,000 to 1,500 calls a second, below
the roughly 3,500 of the MCP server behind it, so at 10 or more concurrent
clients queueing in the gateway dominates. The cost is the pure-Python HTTP
client, not policy or parsing; scaling out, and a faster client, are on the
roadmap.

## What the gateway guarantees on the wire

With or without stages configured:

- **One strict JSON-RPC message per request.** Batches, duplicate keys and
  `NaN` are refused, so the gateway and the server cannot read the same body
  as two different calls.
- **Routing headers must match the body.** `Mcp-Method` and `Mcp-Name` are
  checked against the message.
- **Client credentials stop at the gateway.** No token passthrough.
  Credentials for each upstream are configured on the gateway.
- **Only valid JSON-RPC comes back.** Malformed or misaddressed upstream
  answers are withheld and reported as JSON-RPC errors.
- **Unchanged traffic is byte-identical.** Bodies and SSE events are relayed
  verbatim.

See [docs/architecture.md](docs/architecture.md) for the request path, failure
semantics, how to write a pipeline stage, and the known limitations.

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync                         # gateway, demo servers and dev tools
uv run pytest                   # unit and contract tests
uv run mypy                     # strict type-check
uv run ruff check . && uv run ruff format --check .
uv run pre-commit install       # run all of the above before each commit
```

The contract tests start the sample servers, a deliberately misbehaving
upstream and the gateway on real sockets. They drive the official MCP Python
SDK client through the gateway in both protocol eras, over both SSE and JSON
response framing.

| Path | What is there |
| --- | --- |
| `src/mcp_customs/proxy/` | Streamable HTTP reverse proxy, SSE relay, header and routing rules |
| `src/mcp_customs/auth/` | JWT verification, identities and scope grants, session binding |
| `src/mcp_customs/policy/` | policy file model, rules engine, request targets |
| `src/mcp_customs/pipeline/` | stage interface, pipeline, policy stage, version-aware replies |
| `src/mcp_customs/audit/` | hash chain, Postgres store, group-commit writer, verification |
| `src/mcp_customs/telemetry/` | OpenTelemetry set-up and trace-context handling |
| `src/mcp_customs/jsonrpc.py` | strict JSON-RPC parsing |
| `policies/examples/` | finance, read-only and coding agent policies |
| `demo/` | sample MCP servers, scripted agent, stand-in identity provider, Compose stack |
| `tests/contract/` | real-client tests through a running gateway: policy enforcement, audit, traces |
| `bench/` | latency harness, methodology and committed results |
| `docs/` | architecture, policy reference, build notes (what we found, milestone by milestone) |

## Roadmap

- [x] **Pass-through proxy:** both transport eras, contract tests, CI, Compose demo
- [x] **Identity and policy:** JWT identity and task scopes, bound sessions, YAML policy with argument constraints
- [x] **Audit and telemetry:** hash-chained audit log with `verify-audit`, OpenTelemetry spans, first latency numbers
- [ ] **Injection detection, layer one:** rules on tool output, attack and benign datasets, per-category results
- [ ] **Classifier and data protection:** open-source classifier layer, PII and secret redaction
- [ ] **Approvals and budgets:** held calls in Postgres, approve/deny page, per-agent rate and cost limits
- [ ] **End-to-end agent eval:** attack success rate with the gateway off vs on, stdio wrapper
- [ ] **v0.1:** threat model, policy reference, reproducible results

## License

Apache-2.0
