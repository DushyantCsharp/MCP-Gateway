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
│ 1. origin       foreign browser Origin → 403                    │
│ 2. identity     bearer JWT verified → else 401                  │
│ 3. route        unknown upstream → 404                          │
│ 4. session      session id bound to this agent → else 404       │
│ 5. read body    size limit → 413                                │
│ 6. parse        exactly one strict JSON-RPC message → else 400  │
│ 7. routing      Mcp-Method / Mcp-Name agree with body → else 400│
│ 8. pipeline     client stages (policy, ...): continue / replace │
│                 / respond                                       │
│ 9. audit        request row committed (durable) → else 503      │
│10. forward      filtered headers, original bytes, traceparent   │
└───────────────────────────────┬─────────────────────────────────┘
                                ▼
                       upstream MCP server
                                │  application/json  or  text/event-stream
┌───────────────────────────────▼─────────────────────────────────┐
│11. relay        JSON body, or SSE event by event                │
│12. validate     strict JSON-RPC; answers match the request id   │
│13. pipeline     server stages (listing filter, ...): continue / │
│                 replace                                         │
│14. return       original bytes unless replaced; session id      │
│                 re-bound to the agent                           │
└─────────────────────────────────────────────────────────────────┘
```

Identity is checked at the HTTP layer, before anything else, so it covers
every request including GET streams and DELETEs. The pipeline then runs the
configured stages in order. The policy stage ships now. Request guards,
approval and response guards follow, each as a new stage class plus one
entry under `stages:` in the configuration.

## Identity and sessions

With `auth` configured, every request to `/mcp/<upstream>` needs
`Authorization: Bearer <JWT>`. The token must be signed with a configured key
(shared secret, PEM public key, or the issuer's JWKS), unexpired, issued for
the gateway's audience and, if set, by the configured issuer. Only the
configured algorithms are accepted. A missing or bad token gets a `401` with
an RFC 6750 `WWW-Authenticate` challenge, before the gateway reveals whether
the upstream exists. The token never travels upstream.

Handshake-era sessions are bound to the agent that opened them. The gateway
never shows the client the upstream's `Mcp-Session-Id`. It issues
`<upstream id>.<tag>`, where the tag is an HMAC over the upstream, the agent
and the upstream id, and strips the tag again on the way in. A request that
presents another agent's session id, or an untagged one, gets the `404` the
spec prescribes for an unknown session: a legitimate client starts a new
session, and the caller learns nothing. The binding is stateless, so it
survives restarts and works across replicas that share `auth.session_secret`.
Without that key, a random one is generated at start-up, and sessions do not
outlive the process.

## Policy

The policy stage decides every request that names a tool, prompt, resource
or unknown method, from the caller's identity, the upstream, the target and
the arguments. Deny rules win, nothing is allowed by default, and an argument
the gateway cannot check counts against the call. A denied `tools/call` comes
back as a tool error the model can read; other denials are JSON-RPC errors.
Listings are filtered so a model is never offered what it may not call. The
rules and their semantics are in the [policy reference](policy-reference.md).
The engine sits behind a small interface (`PolicyEngine`), so an OPA or Cedar
adapter could replace it.

## Redaction

The redaction stage keeps secrets and personal data from crossing the
gateway. On the way out it scans the string arguments of `tools/call` and
`prompts/get`, by default for secrets only, so a model cannot paste a
credential into a tool. (A recipient's email address is personal data, but
sending email needs it.) On the way back it scans every string a model would
read, by default for secrets and personal data.

| Kind | Examples | Checked by |
| --- | --- | --- |
| secrets | private keys, AWS, GitHub, Slack, Stripe, Google and AI API keys, JWTs, bearer tokens, `user:password@` in URLs, `password=` / `api_key:` values | pattern; only the value after a label |
| pii | emails, phone numbers, payment cards, IBANs, South African ID numbers, US SSNs | pattern plus Luhn, mod 97, date and issuance checks |

`redact` replaces each value with `[REDACTED:<kind>]` and notes it under
`_meta["io.github.mcp-customs/redaction"]`. `flag` only records it, in
`_meta`, the audit row and the span. `block` refuses the call (`-32092` for
prompts) or withholds the result, naming the kinds and fields, never the
values. `allow` lists patterns for values that must pass, such as internal
addresses.

```yaml
stages:
  - type: policy          # first: decide on the real values
    file: policies/finance-agent.yaml
  - type: redaction       # then scrub them
    mode: redact
    requests: [secrets]
    responses: [secrets, pii]
    allow: ['.*@acme\.example']
```

**Rewritten arguments and `Mcp-Param-*` headers.** At 2026-07-28 a client
copies some arguments into headers, and the server refuses a call whose
headers and body disagree. The gateway learns which arguments each tool
mirrors from the `tools/list` answers it relays. When a stage rewrites
arguments, it recomputes those headers to match. If it has never seen the
tool's schema, it refuses the call rather than send stale headers.

## Injection detection

The injection stage scores every string a model would read in the answers
to `tools/call`, `resources/read` and `prompts/get`: text blocks, embedded
resources and the string leaves of `structuredContent`. It acts on any
result that scores at or above the threshold:

| Mode | What the agent receives |
| --- | --- |
| `block` | a tool error saying the result was withheld, and why; a JSON-RPC error (`-32091`) for other methods |
| `flag` | the result, with a warning block in front of it and the finding under `_meta["io.github.mcp-customs/injection"]` |
| `strip` | the result, with the flagged text (or only its spans, when the detector reports them) replaced by a marker |

```yaml
stages:
  - type: policy
    file: policies/finance-agent.yaml
  - type: injection
    detector: layered   # hidden | classifier | layered
    mode: flag          # block | flag | strip
    threshold: 0.5      # on calibrated scores: every detector's own decision point sits at 0.5
    classifier_threshold: 0.997  # the classifier's raw cut-off; this one was chosen on dev for ~5% false positives
    max_chars: 16000    # the classifier reads the first and last 8,000 characters of longer text
```

Detectors score on different scales, so each is calibrated before they are
combined: a detector's own decision point maps to 0.5, and `threshold` is set
once, on that common scale. The hidden-text checks score 0.6 to 1.0 when they
fire, so any finding of theirs acts at the default threshold.

Two detectors, which `layered` runs in order:

- `hidden`: cheap checks for text a human reviewer would not see. Unicode
  tag characters, direction overrides, invisible characters inside words,
  Latin words with Cyrillic or Greek look-alike letters, and base64 that
  decodes to readable text. They run in microseconds on every result, and
  report spans, so `strip` removes just that part. When one is certain, the
  classifier is skipped.
- `classifier`: ProtectAI's `deberta-v3-base-prompt-injection-v2`
  (Apache-2.0, pinned revision), run on ONNX Runtime without PyTorch
  (`pip install mcp-customs[classifier]`). Scoring is CPU-bound and runs in
worker threads, off the event loop. Its measured trade-off is in
`bench/results/`: at the model's default threshold it flags 36% of
legitimate tool output, and at a threshold that flags about 4% it catches
about half the attacks. Until a better detector layer exists, run it in
`flag` mode (the default), not `block`. Every decision goes into the audit
log and the span (`customs.injection.*`), so its false positives can be
reviewed.

**The character budget.** The classifier reads 512-token windows, so its cost
grows with the length of a result. `max_chars` bounds it: longer text is cut
to its first and last halves, where injected instructions usually sit, and
the hidden-text checks still read all of it. Measured on the benchmark's 109
samples longer than 2,000 characters (Apple M4, 5 threads):

| `max_chars` | Median | Slowest | Of the 109 flagged |
| --- | --- | --- | --- |
| 16,000 (default) | 3.4 s | 11.5 s | 74 |
| 8,000 | 1.9 s | 4.5 s | 69 |
| 4,000 | 0.9 s | 1.8 s | 65 |
| 2,000 | 0.4 s | 0.7 s | 60 |

All 109 are legitimate output: no attack in the benchmark is longer than
2,000 characters, so what a smaller budget costs in detection is not
measured. What it gives up is plain: an instruction placed in the middle of a
long result, past the budget, is never read by the classifier.

## Audit

Every exchange leaves events in an append-only, hash-chained Postgres table
(`customs_audit`). A `request` event (who, what, where, the decision and the
deciding rule) is written *before* a request is forwarded. In durable mode,
the default, the gateway waits for that row to commit, so if the log cannot
be written the call is refused with a `503` rather than run unaudited. A
`result` event (outcome, status, digest of the answer, duration) follows when
the exchange completes. Notifications, GET streams and DELETEs leave
`message` and `transport` events. Requests refused before they could be read
(bad token, unknown upstream or session, malformed body) leave `rejected`
events, which are attack signals. Arguments are stored only as a SHA-256
digest unless `record_arguments` is on.

Writes are group-committed: one writer task per gateway hashes queued events
onto the chain and commits each batch in a single transaction, so under load
many calls share one commit. Each row's hash covers the chain name, sequence
number, previous hash and canonical event JSON; with `audit.key` it is
HMAC-SHA256. Changing, reordering or deleting a row breaks every later link,
and `customs verify-audit` reports the first break. The table refuses
`UPDATE`, `DELETE` and `TRUNCATE` through triggers. Each gateway holds an
advisory lock on its chain, and the primary key `(chain, seq)` makes forks
unwritable.

What it is not: a ledger. Someone with database access and the key (or any
database access, without a key) can rewrite a chain consistently, and
cutting off the newest rows is invisible unless the head is recorded
elsewhere. The gateway logs the head when the chain opens and closes; ship
those logs off the host.

## Telemetry

Each exchange is a server span named after the MCP method and target
(`tools/call transfer_funds`), with MCP and GenAI semantic-convention
attributes (`mcp.method.name`, `mcp.protocol.version`, `mcp.session.id`,
`jsonrpc.request.id`, `gen_ai.operation.name`, `gen_ai.tool.name`) plus the
gateway's own (`customs.agent`, `customs.decision`). Conventions are pinned
to schema 1.44.0. Each pipeline stage gets a child span carrying its
annotations (`customs.policy.decision`, `customs.policy.rule`), and the
upstream exchange gets a client span that ends when its body or stream does.
Spans go out over OTLP/HTTP (Jaeger in the demo).

The gateway joins the caller's trace from `params._meta.traceparent`
(SEP-414, as the MCP SDKs send it), falling back to the HTTP `traceparent`
header. It does not rewrite `_meta`, so the upstream server's span is a
sibling of the gateway's under the caller's span rather than its child. A
`traceparent` header carries the gateway's upstream span for HTTP-level
instrumentation. Audit rows carry the `trace_id`, so a row leads to its
trace and a trace to its rows.

At start-up the gateway logs what it enforces, and warns about what is off
(no authentication, no stages, no audit). A gateway that silently runs
without its policy is the failure this exists to prevent.

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
| Missing or invalid token | `401`, JSON-RPC `-32083`, `WWW-Authenticate` challenge |
| Token issuer's keys unreachable (none cached) | `503`, JSON-RPC `-32083` |
| Unknown upstream | `404`, JSON-RPC `-32600` |
| Foreign `Origin` | `403`, JSON-RPC `-32600` |
| Session id not bound to this agent | `404`, JSON-RPC `-32084` |
| Durable audit row could not be committed in time | `503`, JSON-RPC `-32085`; the call is not made |
| Tool call denied by policy | tool result with `isError: true` |
| Other request denied by policy | `200`, JSON-RPC `-32090` |
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

- Injection detection is a first layer, not protection: see the measured
  rates in `bench/results/`. It looks at one tool result at a time, so an
  attack spread across several results is not seen as one. Long results
  cost seconds to score. Data redaction, approvals and budgets are not built
  yet.
- Durable audit covers the `request` event. `result` events are written
  after the response, so a crash between the two leaves a request without
  its outcome.
- One gateway process handles roughly 1,000 to 1,500 calls a second
  (`bench/README.md`). Running several workers or replicas needs one audit
  chain each (`audit.chain`); two processes on one chain refuse to start.
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
