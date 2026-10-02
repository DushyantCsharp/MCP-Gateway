# mcp-customs

A security and governance gateway for MCP. It sits between an agent and its
MCP servers and inspects every message in both directions: what goes out,
what comes back, and what should not cross at all.

> **Status: v0.0.1, pass-through.** The proxy, its pipeline hooks, the demo
> stack and the contract tests are in place. Policy, detection, approvals,
> budgets and audit land over the coming milestones (see the
> [roadmap](#roadmap)). Until then, nothing is blocked; do not deploy this as
> a security control.
>
> Benchmark results (detection rate, false-positive rate, latency overhead,
> and attack success rate with the gateway off vs on) will lead this README
> once they exist. Nothing is claimed before it is measured.

## Quick start

Requires Docker.

```bash
docker compose -f demo/compose.yaml up --build --wait
docker compose -f demo/compose.yaml run --rm agent
```

This starts two sample MCP servers (`workspace`: documents and email;
`finance`: balances and transfers) with the gateway in front, then runs a
scripted agent that completes an accounts-payable task through the gateway.
If ports 8000 to 8002 are taken, set `CUSTOMS_PORT`, `WORKSPACE_PORT` or
`FINANCE_PORT`.

## Drop-in

Point the client at the gateway instead of the server. Nothing else changes.

```diff
 {
   "mcpServers": {
     "workspace": {
-      "url": "http://workspace.internal:8001/mcp"
+      "url": "http://customs.internal:8000/mcp/workspace"
     }
   }
 }
```

```yaml
# customs.yaml
server:
  host: 0.0.0.0
  port: 8000
upstreams:
  workspace:
    url: http://workspace.internal:8001/mcp
  finance:
    url: http://finance.internal:8002/mcp
    headers:
      Authorization: Bearer ${FINANCE_MCP_TOKEN}  # the upstream's credential, injected by the gateway
```

```bash
customs check-config -c customs.yaml
customs run -c customs.yaml
```

Both MCP transport eras work through the same endpoint: the session-based
revisions (2024-11-05 to 2025-11-25) and the stateless 2026-07-28 revision.

## What the gateway already guarantees

Even with no stages configured:

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
| `src/mcp_customs/pipeline/` | stage interface, pipeline, version-aware gateway replies |
| `src/mcp_customs/jsonrpc.py` | strict JSON-RPC parsing |
| `demo/` | sample MCP servers, scripted agent, Compose stack |
| `tests/contract/` | real-client tests through a running gateway |
| `docs/` | architecture |

## Roadmap

- [x] **Pass-through proxy:** both transport eras, contract tests, CI, Compose demo
- [ ] **Identity and policy:** agent identity from a token, YAML allow/deny by agent, tool and arguments
- [ ] **Audit and telemetry:** hash-chained audit log with `verify-audit`, OpenTelemetry spans, first latency numbers
- [ ] **Injection detection, layer one:** rules on tool output, attack and benign datasets, per-category results
- [ ] **Classifier and data protection:** open-source classifier layer, PII and secret redaction
- [ ] **Approvals and budgets:** held calls in Postgres, approve/deny page, per-agent rate and cost limits
- [ ] **End-to-end agent eval:** attack success rate with the gateway off vs on, stdio wrapper
- [ ] **v0.1:** threat model, policy reference, reproducible results

## License

Apache-2.0
