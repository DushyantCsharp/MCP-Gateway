# Build notes

What we found while building each milestone: surprises in the protocol and
the SDK, bugs the tests caught, decisions and why, and what was deferred.
Each entry links to the test or code that pins it down. This is the raw
material for the launch write-up, so it records what went wrong as well as
what went right.

## Weekend 1: pass-through proxy (2026-10-02)

**Result:** an agent completes its task through the gateway with no code
changes, in both protocol eras. 334 tests, 97% line and branch coverage,
suite runs in about 3 s. Images about 71 MB compressed.

### The protocol moved under the plan

1. **The MCP Python SDK is now v2 (2.2.0).** `FastMCP` is now `MCPServer`.
   The wire types live in a separate `mcp-types` package. HTTP goes through
   `httpx2`, Pydantic's maintained fork of httpx. We use `httpx2` for upstream
   calls too, so there is one HTTP stack.

2. **A stateless protocol revision exists (2026-07-28)**, alongside the
   session-based ones (2024-11-05 to 2025-11-25). In stateless mode there is
   no `initialize` and no `Mcp-Session-Id`. Every request carries its own
   `_meta` envelope (protocol version, client capabilities, client info),
   servers cannot send requests to clients, and cancelling a request means
   closing its stream. The SDK client probes `server/discover` and falls back
   to `initialize`.
   *Decision:* the gateway is a transparent JSON-RPC reverse proxy rather
   than an MCP server that re-originates calls. Terminating the protocol
   would mean reimplementing both eras and would quietly drop whatever the
   gateway did not model. Every contract test runs in both eras
   (`tests/contract/test_passthrough.py`).

3. **Stateless requests mirror routing data into HTTP headers**
   (`Mcp-Method`, `Mcp-Name`, and `Mcp-Param-*` for arguments a tool marks
   with `x-mcp-header`) so intermediaries can route without parsing bodies.
   That opens a header/body desync: the gateway decides on the body, but
   something behind it might route on the header.
   *Decision:* refuse any request whose routing headers disagree with its
   body, or that repeats one (`test_routing_headers_must_match_the_body`).

4. **Every 2026-07-28 result must carry `resultType`.** A reply the gateway
   writes itself without it fails the client's validation. Gateway replies
   are therefore shaped by protocol version (`pipeline/replies.py`). This
   surfaced as a Pydantic error in the first seam test.

5. **The SDK client only sends `Mcp-Param-*` headers for tools it has
   already listed**, and servers refuse calls that lack them. The first
   stateless smoke run failed this way through the gateway, and failed
   identically against the server directly, so it was not a gateway bug.
   Real agents list tools first, and the scripted agent now does too.

### Security decisions

6. **Parser differentials.** Python's `json` keeps the last of duplicate
   keys, other parsers keep the first, so
   `{"name": "read_doc", "name": "send_email"}` could be checked as one tool
   and run as another. `NaN` and `Infinity` are not JSON but Python accepts
   them. Both are refused, along with batches and invalid UTF-8
   (`test_malformed_messages_are_refused`).

7. **No token passthrough.** `Authorization` and `Cookie` stop at the
   gateway. Upstream credentials are configured per upstream and injected
   (`test_client_credentials_stop_at_the_gateway`). Hop-by-hop headers,
   including any named in `Connection`, are dropped.

8. **DNS rebinding.** The SDK turns on Host and Origin checks only when a
   server binds to localhost. The gateway checks `Origin` itself, against
   `security.allowed_origins`, and lets the HTTP client set `Host` for each
   upstream.

9. **Only valid JSON-RPC goes back to the client, and an answer must match
   the request it answers.** An upstream body that fails strict parsing, or
   answers a different request id, is withheld (502). On a stream the bad
   event is dropped (`test_invalid_upstream_answers_are_withheld`). An error
   with a null id is let through: the SDK uses it for transport-level
   refusals such as an expired session.

### Streaming

10. **SSE relay preserves bytes.** Each event keeps its raw bytes, so an
    unmodified event, `id:` field included, is forwarded verbatim. The
    parser handles CRLF split across chunks and CR-only line endings; it is
    tested at every split point and one byte at a time (`tests/unit/test_sse.py`).

11. **When to fake an answer.** If an upstream stream breaks before
    answering, the gateway synthesises an error event so the client is not
    left waiting. A stream that closes cleanly without an answer is *not*
    an error: servers may close streams on purpose and let the client
    resume with `Last-Event-ID`.
    *Bug found in review:* if the only answer was malformed and got dropped,
    and the stream then closed cleanly, the client would hang. The relay now
    synthesises an error in that case too
    (`test_a_stream_whose_only_answer_was_dropped_still_answers`).

12. **Disconnects propagate.** uvicorn reports ASGI spec 2.3, so Starlette
    watches for client disconnects and cancels the relay, which closes the
    upstream stream (`test_a_client_disconnect_closes_the_upstream_stream`).
    Known gap: a disconnect before the upstream has sent headers does not
    cancel the upstream call.

13. **`Accept-Encoding: identity` upstream**, so the relay always inspects
    plain bytes and never has to decompress and recompress.

### Tooling and environment

14. `astral-sh/setup-uv` publishes only exact version tags, so `@v10` did
    not resolve. Actions are now pinned to commit SHAs, with Dependabot
    keeping them current.
15. GitHub's `ubuntu-latest` moves to Ubuntu 26 on 2026-10-19. Runners are
    pinned to `ubuntu-24.04`, so benchmark numbers stay comparable.
16. uv 0.12 images are Debian trixie, so runtime images use
    `python:3.12-slim-trixie` to keep the venv's interpreter path identical.
17. Port 8000 was already taken on the development machine. Demo ports are
    configurable (`CUSTOMS_PORT`, `WORKSPACE_PORT`, `FINANCE_PORT`).

## Weekend 2: identity and policy (2026-10-02)

**Result:** 29 of 29 disallowed calls blocked and 11 of 11 allowed calls
delivered, in both protocol eras, checked at a recorder in front of each
real upstream. Each run also fuzzes 300 transfers through the gateway and
2,000 against the engine. 619 tests, 97% coverage.

### Bugs the tests caught

1. **`optional` was wrong on deny rules.** The read-only example's
   `no-bulk-reads` rule (`limit: {min: 51, optional: true}`) fired whenever
   `limit` was absent, which blocked every default-size search. The
   hand-written decision table caught it. `optional` now means *absence is
   harmless*: an absent argument satisfies an allow rule and never triggers
   a deny rule (`test_missing_arguments_are_unknown_unless_optional`).

2. **A length limit accepted the wrong type.** Hypothesis generated
   `memo: []`, which passed `max_length: 140` because length checks
   accepted lists as well as strings. The upstream would have rejected it
   anyway, but the policy allowed something its author never meant to.
   Length checks now apply to strings only. Lesson: an operator that works
   on several types quietly widens what a rule allows.

3. **`1e400` is infinity to Python** and an exact decimal to other parsers,
   another parser differential. Strict parsing now rejects numbers that
   overflow a double.

4. **A test helper switched the policy off without anyone noticing.** The
   contract-test gateway helper always passed an explicit empty pipeline,
   which overrode the policy configured in `stages:`. The first enforcement
   run showed denied prompts reaching the upstream. It was caught only
   because the suite checks the upstream's recorder rather than the
   gateway's replies. Lessons: measure enforcement at the boundary you are
   protecting; and a gateway that can silently run without its policy needs
   to say loudly at start-up what it is enforcing (Weekend 3 follow-up).

5. **Two key-handling failures would have become 500s.** A malformed PEM
   key only failed on the first request, and a key that does not fit the
   token's algorithm (an RSA key for an ES256 token) raises a PyJWT error
   outside the `InvalidTokenError` family. Keys are now parsed at start-up,
   and every PyJWT error is a 401
   (`test_a_key_that_does_not_fit_the_algorithm_is_a_401`).

### Decisions

6. **Three-valued constraints.** A constraint is true, false or *unknown*
   (wrong type, missing, or a string too long to check). Unknown never
   satisfies an allow rule and always triggers a deny rule, so wrapping a
   value in a list (`["ACC-PAYROLL"]`) cannot slip past
   `equals: ACC-PAYROLL`. Rules combine as in Cedar: deny wins, default deny,
   order irrelevant.

7. **Type-aware equality.** In Python `True == 1`. In a policy, `true` must
   not equal `1`, while `1` must equal `1.0`. Decimal strings count as
   numbers only in plain form (`"18450.00"`, not `"1e3"`, `"07"` or `" 7"`).

8. **Authenticate before routing.** An unauthenticated caller gets a 401
   whether or not the upstream exists, so upstream names are not revealed.

9. **Session binding returns 404, not 403.** The spec tells a client to
   start a new session on a 404, so a legitimate client recovers by itself
   (after a key rotation, say), and a caller holding someone else's session
   id learns nothing. The binding is a stateless HMAC tag, so it works across
   replicas that share `auth.session_secret`. Without that key, sessions do
   not survive a restart.

10. **The JWKS refresh cooldown is a trade-off.** An unknown key id cannot
    force a refetch within 30 s of the last one, so a stream of forged
    tokens cannot hammer the identity provider. The cost: a genuinely new
    key can be refused for up to 30 s after rotation.

11. **Denials tell the model what, not how.** A blocked tool call returns a
    tool error naming the rule, so the model can change course. It does not
    say which argument failed or what the limit is, because a model told
    "max 10,000" can split one payment into two. Per-call policy cannot stop
    splitting anyway; that is what budgets are for (Weekend 6).

12. **Filtered listings must be private.** 2026-07-28 results carry cache
    hints. A filtered `tools/list` depends on who asked, so the gateway
    marks it `cacheScope: private`.

13. **Algorithm families follow the key source.** A shared secret allows
    only HS256/384/512, and a public key or JWKS allows only asymmetric
    algorithms. Together with PyJWT's own refusal to use a PEM key as an
    HMAC secret, this blocks the classic algorithm-confusion forgery
    (`test_public_keys_cannot_be_used_as_hmac_secrets`).

### SDK and tooling notes

14. The SDK wraps an exception raised inside `async with Client(...)` in
    nested `ExceptionGroup`s, so the demo agent printed tracebacks instead of
    "TASK BLOCKED". The agent now unwraps them, and does the same for
    `MCPError` (for example, a 401 from the gateway).
15. `docker compose up --wait` fails when a one-shot service exits, even
    successfully. The demo's token issuer moved into the `agent` profile, so
    it runs only as an agent's dependency.
16. A named volume takes its ownership from the image directory it is first
    mounted over, so the demo image creates `/tokens` owned by its non-root
    user.

## Follow-ups

| Item | Why | When |
| --- | --- | --- |
| Log the active auth mode and pipeline stages at start-up | A gateway silently running without its policy is the worst failure (W2 finding 4) | Weekend 3 |
| Audit every decision, with the deciding rule | Denials are only logged today | Weekend 3 |
| Recompute `Mcp-Param-*` headers when a stage rewrites arguments | Redaction will change header-mirrored values; today the upstream rejects the mismatch, which fails closed | Weekend 5 |
| Treat results on resumed GET streams conservatively | They arrive without the request they answer | Weekend 4 |
| Cancel the upstream call when the client disconnects before response headers | Wasted upstream work, and a modern-era cancellation not honoured | Before v0.1 |
| RE2 or a timeout for policy regexes | Backtracking on attacker-chosen strings; the 8,192-character cap bounds it but does not remove it | Before v0.1 |
| Budgets across calls | Split payments get under per-call limits | Weekend 6 |
| OAuth protected-resource metadata (RFC 9728) and CORS preflight | OAuth-capable and browser clients need them to discover and reach the gateway | After v0.1 |
| Nested argument paths in policies | Only top-level arguments can be constrained | After v0.1 |
