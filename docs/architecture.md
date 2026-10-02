# Architecture

mcp-customs is a reverse proxy for the MCP Streamable HTTP transport. Every
upstream MCP server is mounted at `/mcp/<name>`, and an agent moves behind the
gateway by changing one URL. Messages are parsed and passed through an
ordered pipeline of stages, but the transport is never terminated: what the
client sends is what the server receives, unless a stage changes it.

## Request path

```
 agent (any MCP client)
   │  POST/GET/DELETE /mcp/<upstream>
   ▼
┌──────────────────────────── gateway ────────────────────────────┐
│ 1. route        unknown upstream → 404                          │
│ 2. origin       foreign browser Origin → 403                    │
│ 3. read body    size limit → 413                                │
│ 4. parse        exactly one strict JSON-RPC message → else 400  │
│ 5. routing      Mcp-Method / Mcp-Name agree with body → else 400│
│ 6. pipeline     client stages: continue / replace / respond     │
│ 7. forward      filtered headers, original bytes                │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
                       upstream MCP server
                                │  application/json  or  text/event-stream
┌───────────────────────────────▼─────────────────────────────────┐
│ 8. relay        JSON body, or SSE event by event                │
│ 9. validate     strict JSON-RPC; answers match the request id   │
│10. pipeline     server stages: continue / replace               │
│11. return       original bytes unless replaced                  │
└─────────────────────────────────────────────────────────────────┘
```

The stages planned for the pipeline, in order, are authentication, policy,
request guards, approval and response guards. Weekend 1 ships the pipeline
with no stages configured; the hooks are exercised by test stages in
`tests/contract/test_pipeline_seam.py`.

## Two protocol eras, one proxy

| | Handshake era (2024-11-05 to 2025-11-25) | Stateless (2026-07-28) |
| --- | --- | --- |
| Connect | `initialize`, then `notifications/initialized` | none; optional `server/discover` probe |
| State | `Mcp-Session-Id` from the server | none; every request carries `_meta` |
| Server-initiated messages | GET opens an SSE stream | not on this wire; `subscriptions/listen` instead |
| End | DELETE with the session id | nothing to end |
| Routing headers | `MCP-Protocol-Version` | `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*` |

The proxy does not need to know which era a client is using to forward it
correctly: it forwards end-to-end headers, relays whichever response framing
the server chose, and parses each message to give stages what they need. The
era matters in two places only. Routing-header checks are stricter for
stateless requests, and replies written by the gateway itself (such as a
policy denial) carry `resultType` when the revision requires it.

## Invariants

These hold whether or not any stage is configured, and the contract tests
check each one:

- **One strict message per POST.** Batches, duplicate JSON keys, `NaN` and
  `Infinity`, invalid UTF-8 and malformed envelopes are refused. Lenient
  parsers disagree on these, and a policy decision is only as good as the
  parse it was made on.
- **Headers agree with the body.** A stateless request whose `Mcp-Method` or
  `Mcp-Name` differs from its body, or that repeats a routing header, is
  refused. Anything behind the gateway might route on those headers.
- **Client credentials stop at the gateway.** `Authorization` and `Cookie` are
  never forwarded. Credentials for an upstream are configured per upstream and
  injected. Hop-by-hop headers, including any named in `Connection`, are
  dropped in both directions.
- **Only valid JSON-RPC reaches the client.** An upstream body or SSE event
  that is not strict JSON-RPC, or an answer to a request it was not asked, is
  withheld. On a JSON body the client gets a `502` with a JSON-RPC error. On a
  stream the bad event is dropped. If the stream then breaks before the
  request is answered, the client gets a synthesised error event, so it is
  never left waiting.
- **Fail closed.** A stage that raises, or replaces a message with one that
  changes its id, method or target, stops that message. The client receives an
  `INTERNAL_ERROR` in its place.
- **Unchanged means byte-identical.** Unmodified JSON bodies and SSE events,
  `id:` fields included, are forwarded byte for byte.

## Failure semantics

| Situation | Client receives |
| --- | --- |
| Unknown upstream | `404`, JSON-RPC `-32600` |
| Foreign `Origin` | `403`, JSON-RPC `-32600` |
| Body over `limits.max_request_bytes` | `413` |
| Malformed body | `400`, `-32700` or `-32600` |
| Routing header mismatch | `400`, `-32020` |
| Upstream unreachable | `502`, `-32080` |
| Upstream timeout | `504`, `-32081` |
| Invalid upstream answer | `502`, `-32082` (JSON) or synthesised error event (SSE) |
| Stage failure | `500`, `-32603` |

Gateway error codes sit in the implementation-defined range and avoid the
codes MCP already reserves (`-32000`, `-32001`, `-32020` to `-32022`, `-32042`).

## Writing a stage

```python
from mcp_customs.pipeline import CONTINUE, ClientMessageContext, ClientOutcome, Stage, tool_error_reply


class DenyTransfers(Stage):
    name = "deny-transfers"

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        message = ctx.message
        if message.method == "tools/call" and message.params.get("name") == "transfer_funds":
            return tool_error_reply(ctx, "Transfers need approval")
        return CONTINUE
```

`on_server_message` receives each message on the way back, together with the
client request it answers (or `None` on a server-initiated stream), and may
return `Replace(...)` to rewrite it.

## Known limitations

- No authentication, policy or detection yet. In v0.0.1 the gateway is a
  faithful pass-through and must not be relied on as a security control.
- JSON-RPC batches are refused. Batching was removed from MCP in 2025-06-18
  and is not part of the stateless revision.
- A client that disconnects before the upstream has sent response headers
  does not cancel the upstream call. Once streaming has started, a disconnect
  does close the upstream stream.
- A response replayed on a resumed GET stream (`Last-Event-ID`) is checked
  without the request it answers.
- A stage that rewrites `tools/call` arguments which the tool mirrors into
  `Mcp-Param-*` headers would make the headers stale. The upstream then
  rejects the call, so this fails closed.
- `Set-Cookie` from upstreams is dropped, so cookie-based sticky sessions do
  not work through the gateway.
- Browser clients: there is no CORS preflight handling yet.
- Streamable HTTP only; the stdio wrapper is planned for weekend 7.
