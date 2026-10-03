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

## Weekend 3: audit, telemetry, first benchmark (2026-10-02)

**Result:** every call has a trace and a verifiable audit row, checked in
both protocol eras by `tests/contract/test_observability.py`, and in CI
against the deployed demo stack (`verify-audit` plus a query to Jaeger).
First latency numbers are in `bench/results/`; see *Performance* below.

### Tracing

1. **MCP carries trace context in the body**, `params._meta.traceparent`
   (SEP-414), not in HTTP headers. The SDK client injects it and the SDK
   server reads it. The gateway reads it too, so its spans join the agent's
   trace.
   *Decision:* do not rewrite `_meta` to make the upstream span a child of
   the gateway's, since that would break byte-identical relaying. The
   upstream span is a sibling under the agent's span, and a `traceparent`
   HTTP header carries the gateway's span for HTTP-level tooling
   (`test_the_gateway_joins_the_callers_trace`).

2. **The MCP semantic conventions exist** in OpenTelemetry's incubating set
   (`mcp.method.name`, `mcp.protocol.version`, `mcp.session.id`,
   `jsonrpc.request.id`, alongside GenAI's `gen_ai.tool.name`), and the MCP
   SDK already uses them. The gateway uses the same names, pinned to schema
   1.44.0.

3. **Each gateway app owns its tracer provider** rather than installing a
   global one. The tests run several gateways in one process, and a global
   provider would mix their spans.

4. **Answers get stage spans; the notifications before them do not.** A
   progress-heavy stream would otherwise bury the trace in spans for every
   progress event.

### Audit

5. **Write before forwarding, and refuse if the write fails.** In durable
   mode a call's `request` row must commit before the call is forwarded, so
   an outage refuses calls (503) rather than running them unaudited.
   Group commit keeps the cost to about one transaction per batch. The
   outcome (`result`) is written after the response and is not durable: a
   crash between the two loses the outcome, not the fact of the call.

6. **Hash the text, query the JSON.** Postgres `jsonb` normalises key order
   and number formatting, so hashing what `jsonb` gives back would not
   reproduce what was hashed. Each row stores the canonical JSON text that
   was hashed, plus a generated `jsonb` column for queries.

7. **The algorithm is stored per row, and verification enforces it.**
   Otherwise someone could replace keyed HMAC rows with plain SHA-256 rows
   they can compute themselves. Verifying with a key rejects any unkeyed row
   as a possible downgrade (`test_downgrading_a_keyed_chain_is_detected`).

8. **One writer per chain.** A session advisory lock makes a second gateway
   on the same chain fail at start-up, and the `(chain, seq)` primary key
   makes a fork unwritable even without the lock. A container's host name
   changes when it is recreated, so the demo names its chain explicitly.

### Bugs the tests caught

9. **Postgres tests skipped silently.** testcontainers 4.15 deprecated its
   `testcontainers.postgres` import path. The test configuration turns
   warnings into errors, and a broad `except` around container start-up
   turned that error into "Docker unavailable, skip". All eight audit tests
   "passed" by skipping. Now only real Docker errors skip, and CI sets
   `CUSTOMS_REQUIRE_POSTGRES` so a skip there is a failure. Lesson: a skip
   is a silent pass, so make it fail where it matters.

10. **Shutdown hung while the audit store was down.** The writer retried
    forever, and the app's lifespan waited for it. The test's thread-join
    timeout hid it: the only symptom was a 15-second test. `close()` now
    gives the store `commit_timeout_s` to come back, then stops the writer
    and logs how many events were not written
    (`test_shutdown_does_not_hang_on_a_dead_store`).

11. **A stream closed by the client never ended its spans.** A client that
    disconnects mid-stream closes the relay's generator (`GeneratorExit`),
    not cancels it, so the cancellation handler never ran. The relay now
    tracks whether it reached the end.

12. **A false positive in mypy.** OpenTelemetry's recursive `AnyValue` type
    alias makes `attributes.get(key) == "x"` look impossible to strict
    equality checking, so mypy flagged code that does run as unreachable.

### Tooling

13. **Jaeger 2.21 dropped the old query API.** `/api/traces` returns 404;
    traces are at `/api/v3/traces`, as OTLP JSON
    (`demo/scripts/check_traces.py`).
14. **The Weekend 2 follow-up is done:** the gateway logs what it enforces at
    start-up, and warns when authentication, stages or audit are off
    (`tests/unit/test_app_describe.py`).

### Performance

15. **Per-call cost is small; throughput is the limit.** Measured on an Apple
    M4 (`bench/results/latency-2026-10-02.md`, commit `0a7f95f`), with one
    client the gateway adds 0.40 ms p50 as a pass-through, 0.47 ms with
    authentication and policy, and 1.57 ms with durable audit and tracing as
    well. Most of the last is the audit commit, which on macOS crosses
    Docker's VM.
    At 10 and 50 clients the gateway becomes the bottleneck: one process
    peaks at roughly 1,000 to 1,500 calls a second, against about 3,500 for
    the MCP server behind it, and queueing dominates (+33.6 ms p50 for the
    pass-through at 50 clients).

16. **The profile points at the HTTP client, not the gateway's logic.**
    Under load, the largest single cost is `httpcore2`'s connection pool,
    which checks every idle socket for readability (a `poll` call) on each
    request. Next come `h11` header handling and `anyio` socket bookkeeping.
    Parsing, routing checks and policy hardly register. The plan's stack
    table predicted "slower than Go; fine at this scale, and the benchmark
    will show it", and it does. Options, cheapest first: several workers,
    each with its own audit chain; a C-accelerated upstream client; a
    compiled hot path.

17. **Measure what you publish against a clean commit.** The first run
    recorded the last commit while the code under test was uncommitted. The
    harness now appends `+dirty` when `src/` or `demo/` has uncommitted
    changes, and records the machine's load average (3.3 here, from
    unrelated containers that were left running).

## Weekend 4: injection detection, layer one (2026-10-02 to 03)

**Result:** the first honest results table, misses included, is in
`bench/results/detection-2026-10-02-classifier.md`. On the held-out test
split, ProtectAI's DeBERTa classifier at its default threshold flags 82.0% of
attacks [78.5, 85.0] and 36.0% of legitimate tool output [27.3, 45.8]. With
the threshold chosen on dev for about 5% false positives, it catches 52.9%
[48.7, 57.1] at 4.0% [1.6, 9.8].

### The benchmark

1. **Source attacks, do not write them.** Attack samples come only from
   published, licensed benchmarks, pinned to a commit (InjecAgent first),
   and are not committed: they are rebuilt from the pin. Results list
   misses and false positives by sample id and score, never by text, so
   publishing results never republishes attacks.

2. **InjecAgent's 2,108 cases are only 62 distinct attacks.** Each attacker
   instruction is crossed with 17 tool-output templates. A per-sample split
   would put every instruction in both halves and inflate any tuned result.
   The split is by instruction, and the build refuses to write if a group
   lands in both. The cost is that the test split holds just 16 distinct
   attacks, 5 of them exfiltration, which is why exfiltration differs by
   16 points between dev (78.5%) and test (62.4%). The intervals say so.

3. **The hardest benign class mirrors the attacks.** `paired` samples are
   the same 17 templates with the attack slot filled by ordinary,
   hand-written content: reviews, notes, emails, including everyday
   requests addressed to people. A detector cannot score well by
   recognising the format. It is also where the classifier does worst
   (40% flagged).

### The detector

4. **An off-the-shelf classifier is not calibrated for tool output.** It
   was trained on prompts, and it scores many ordinary tool fields near
   1.0. The threshold for 5% false positives on dev is 0.9969, which is
   why that operating point catches only about half the attacks. Run it in
   `flag` mode; `block` would break ordinary tool use.

5. **Repetition reads as injection.** Plain benign text repeated scores
   high even within one 512-token window: one sentence repeated 20 times
   scores 0.985, while 1,500 tokens of real prose score 0.001. Logs and
   ledgers repeat by nature, so 81.5% of the synthetic long outputs were
   flagged at the default threshold.

6. **Long outputs are expensive.** 30 ms per sample at the median, but
   4.8 s at p99 on an M4, because a long result needs many windows. That
   would dominate the gateway's latency budget. Detection runs in worker
   threads so other requests are not held up, but the call itself waits.

7. **ONNX instead of PyTorch.** The model ships an ONNX export, so the
   runtime is `onnxruntime` plus `tokenizers` (tens of megabytes) rather
   than PyTorch (gigabytes). It is an optional extra (`[classifier]`), and
   the model (740 MB) is downloaded once at start-up, at a pinned revision.

8. **The rules layer moved.** The plan had rules first and the classifier in
   Weekend 5. The classifier came first because it needed no hand-written
   patterns, and its measured weaknesses now show what a cheaper layer must
   cover.

### Tooling

9. AgentDojo pins `websockets` below 17 and pulls in about 60 packages, so
   it lives in its own `bench` dependency group, which CI jobs do not
   install.
10. `tokenizers` 0.23 requires `huggingface-hub` below 2.0. The extra pins
    only a floor and lets the resolver choose.
11. **The benchmark drifted with the docs.** The `security_docs` class was
    built from the repository's current documentation, so writing up the
    results grew it from 102 to 121 samples and changed its hash. A rebuild
    at a later commit would have scored a different dataset under the same
    name. The build now reads the documents with `git show` at a pinned
    commit, and the manifest records it. A rebuild reproduces the published
    data's hashes exactly. Lesson: anything generated from the repository
    must be pinned like an external source.

## Weekend 5: redaction and a second detector layer (2026-10-03)

**Result:** redaction of secrets and personal data in both directions, a
hidden-text detector layered with the classifier on one calibrated scale,
and benchmark v2. The weekend's "done when" (detection and false positives
both improve on Weekend 4, or say why not) was not met. On v2's test split
the layered detector catches 80.9% of attacks [77.4, 84.0] and flags 36.0%
of legitimate output [27.3, 45.8], the same as the classifier alone. Why not:
finding 4.

### The benchmark

1. **One character separated the classes.** Testing whether the classifier
   reacts to the JSON shape of tool output, rather than its words, meant
   parsing each sample. Scoring each field on its own lowered paired false
   positives only from 44.3% to 40.0% on dev. But 114 of 140 paired samples
   parsed and none of the 782 attacks did. InjecAgent stores each attack
   wrapped in an extra pair of double quotes, which the paired fills did not
   have, so a detector could tell the classes apart by the first character.
   Benchmark v2 removes the wrapping, and the build refuses to write if
   attacks and their pairs are quoted differently. The classifier's test
   detection moved from 82.0% to 80.9%: it had been getting a small free
   advantage. Lesson: compare the classes on every surface feature, not only
   on what the text says.

2. **A rerun overwrote the published v1 results.** Result files were named
   by UTC date and detector, so the v2 run wrote over the v1 file of the same
   day. It was restored from git. Names now carry the benchmark version
   (`detection-v2-…`), the harness refuses to overwrite without `--force`,
   and it records the commit and environment before scoring, so the commit
   recorded is the code that ran.

3. **No attack is longer than 2,000 characters.** All 109 samples over that
   length are legitimate output. Anything that depends on length, such as the
   character budget (finding 6), can be measured for cost and false
   positives, but not for detection.

### The detection layer

4. **A layer that keeps the stronger score cannot lower false positives.**
   The hidden-text checks look for what a reader cannot see: Unicode tag
   characters, direction overrides, invisible characters inside words,
   look-alike letters, and base64 that decodes to text. On v2 they flag
   nothing, attack or benign: the benchmark has no obfuscated attacks. So the
   result measures only their cost (2 ms at p99) and their false positives
   (none of 440). This is why the "done when" failed. Combining by maximum
   can add detections, and can never remove a false positive. The false
   positives are the classifier's, on long and repetitive output (81.5% of
   it flagged) and on paired samples (40%). Lowering them needs a better
   model, or a layer that can veto (judge a result benign), not one more
   layer that can only flag.

5. **One threshold for detectors on different scales.** The classifier's
   scores sit near 1.0 for both classes (its 5% point is 0.9969), while a
   hidden-text finding is 0.6 to 1.0 by rule. Each detector is now wrapped
   in a piecewise-linear calibration that maps its own decision point to
   0.5. The stage's `threshold` is set once on that scale, and the raw cut-off
   is `classifier_threshold`. The stage now defaults to `flag`, since `block`
   at the model's own threshold would withhold a third of legitimate results.

6. **A budget bounds the cost; it does not make it small.** The classifier
   now reads at most `max_chars` characters (default 16,000: the first and
   last halves). The p99 moved only from 5.5 s to 4.9 s, because the
   benchmark's long outputs are 11,000 to 29,000 characters, so 16,000 still
   means about 10 windows. On those 109 samples the median is 3.4 s at
   16,000, 1.9 s at 8,000, 0.9 s at 4,000 and 0.4 s at 2,000 characters, and
   the samples flagged fall from 74 to 60. (The 16,000 figures come from the
   full run; the others from re-scoring just those samples, same machine and
   threads.) The default stays at 16,000, which reads most real results
   whole. The cost of a small budget is plain even though it is not
   measured: text in the middle of a long result is never read by the
   classifier, and padding is a cheap way to put it there. The hidden-text
   checks always read everything.

7. **The attack the layer looks for happened to its own source.** Writing
   the detector and its tests through the editing tools turned `\u` escapes
   into the literal invisible and Cyrillic characters, twice, once through a
   shell heredoc. The files looked unchanged, and a reviewer would not have
   seen the difference. Every non-ASCII character in source is now written
   as an escape. Ruff's `PLE` rules (control, direction and zero-width
   characters) and `RUF001` (ambiguous letters) are enabled, so most literal
   ones fail the lint.

### Redaction

8. **Redact after policy.** Policy decides on real values (an allowed
   recipient, a known vendor account), so the redaction stage goes after
   it. A scrubbed value would make any rule that constrains it fail.

9. **Defaults follow what tools need.** Requests are scanned for secrets
   only: a recipient's email address is personal data, but sending email
   needs it. Results are scanned for secrets and personal data. `allow`
   patterns let internal values through (the demo allows `@acme.example`).

10. **Rewriting an argument breaks its header.** At 2026-07-28 a client
    mirrors some arguments into `Mcp-Param-*` headers, and the server
    refuses a call whose headers and body disagree. The gateway now learns
    each tool's header mapping from the `tools/list` answers it relays, and
    recomputes the headers after a rewrite. When it has not seen the schema,
    it answers 500 rather than forward a mismatch. The schemas are held in
    memory, so after a restart a redacted call fails closed until the client
    lists tools again.

11. **Text and structured content say the same thing twice.** The demo
    invoice's billing contact is redacted four times: the email and the
    phone, in the text block and again in `structuredContent`. A stage that
    scrubbed only text would leak through the structured copy. Both are
    scanned, and the contract test checks the agent never sees either.

12. **A South African ID number is also a valid card number.** Its check
    digit is Luhn, so the card pattern matched it. Stricter kinds are now
    tried first. A Luhn-valid 13-digit number with an impossible date is
    still reported, as a card.

13. **Test secrets are built at runtime.** Fake keys in the tests are
    assembled from parts, so the repository holds no string that a secret
    scanner (or push protection) would flag.

14. **A missing extra is a configuration error.** The default injection
    detector needs the `[classifier]` extra. Without it the gateway stopped
    with a raw `ModuleNotFoundError`. It now refuses to start with a message
    naming the extra, or `detector: hidden`, which needs nothing. A model
    that cannot be downloaded fails the same way.

### Not done

15. **More attack categories.** AgentDojo's documents and public obfuscated
    and multi-step datasets still need converters, and their licences
    checked. Meta's Prompt Guard 2 needs the Llama licence accepted on
    Hugging Face. Both carry over (follow-ups).

## Weekend 6: approvals and budgets (2026-10-03)

**Result:** the "done when" is met. A consequential call waits for a human
and survives a gateway restart, in both protocol eras. The test stops the
gateway while a payment waits, starts a new one on the same port, approves the
payment there, and checks that the agent's original `call_tool` returns the
receipt and that the finance server recorded exactly one payment
(`tests/contract/test_approvals_restart.py`). CI does the same in the Docker
demo with `docker compose restart gateway`. Budgets hold under load: with
counters in Redis, no call and no amount got past any agent's limit, through
one gateway or two (`bench/results/budget-v1-2026-10-03.md`).

### Approvals

1. **The protocol already had a way to wait.** Since 2025-11-25 (SEP-1699) a
   server may end an event stream after an event that has an id, and the
   client reconnects with `Last-Event-ID` after the `retry` interval. The
   Python SDK does this on its own, in both eras. So a held call needs no
   client changes: the gateway opens the stream with a resume token as the
   event id, ends it every `stream_s`, and picks the call up from Postgres
   whenever the client comes back, from whichever gateway it reaches. MCP's
   tasks (SEP-1686, an extension in 2026-07-28) fit too, but only for clients
   that opt in, and most do not.

2. **The SDK reconnects twice.** Each attempt waits `retry` milliseconds, and
   after two failures the call fails. A restart therefore has about twice
   `retry_ms` (10 seconds by default) to come back.

3. **A restart waited on streams that never end.** Uvicorn's graceful
   shutdown waits for every open connection, with no limit by default. A
   handshake-era client keeps a server-initiated GET stream open, so the old
   gateway was still waiting on it when the client's two reconnects failed
   (the logs show no reconnect reaching any gateway). The stateless era passed and the handshake era
   failed, which pointed at the GET stream. The gateway now passes
   `server.shutdown_grace_s` (5 seconds) to uvicorn. The same wait would have
   stalled every production restart.

4. **Without a fixed key, a restart forgets sessions.** Handshake-era session
   ids are HMAC-bound to their agent with `auth.session_secret`. When none is
   set, the key is random per process, so after a restart the client's resume
   gets a `404` for an unknown session. This was documented for replicas;
   approvals make it matter for restarts too. Start-up now warns when
   approvals are on without the key, and the demo sets one.

5. **Postgres caught what the memory store did not.** `CASE WHEN %s IS NULL`
   with an untyped parameter fails in Postgres ("could not determine data
   type"). Every unit test passed against the memory store; the first run
   against Postgres failed. Lesson: test a state machine against the store it
   will run on.

6. **At most once, not exactly once.** Making an approved call starts with a
   conditional `approved` to `executing` update, and the answer is stored
   before it is delivered. If the gateway stops in between, nobody can know
   whether the payment went through, so the call becomes `unknown` and the
   agent is told to check. Retrying a payment would be worse than asking a
   person to look.

7. **The approved call runs the pipeline again.** Rather than storing where
   the pipeline stopped, the gateway runs every stage again on the original
   request, with the approval attached. Holds are waived and denials are not,
   so a policy tightened in the meantime still wins. It costs one rule: the
   budget stage must come after the policy stage, or a call charged before
   policy held it would be charged again when approved.

8. **Approve beats allow, and the unknown goes to a human.** An approve rule
   must not be bypassable by a broad allow rule, so it comes second, after
   deny. Like deny, it fires on what cannot be checked. In the decision table
   the two over-limit payments became approvals, and so did two payments
   whose amount cannot be read (`"1e3"`, `true`): the restated intent now
   says so in three values, and agrees with the engine on 2,000 generated
   transfers.

9. **The approvals page is an injection target too.** The arguments an
   approver reads were written by an agent, possibly one steered by a prompt
   injection aimed at the approver. The page escapes everything, allows no
   scripts (CSP), and carries a CSRF token on every form. An approver cannot
   approve a call made under their own identity, and the resume token is
   stored only as a digest.

10. **Two tests hung instead of failing.** Making large payments approvable
    turned tests that expected a denial into tests waiting forever for a
    human, and a test helper choked on the empty data of the stream's first
    event. pytest's faulthandler found both. A hold is a new kind of outcome,
    and every caller has to handle it, test helpers included.

### Budgets

11. **The benchmark found a production bug on its first run.** Under 200
    concurrent calls, redis-py's default async pool raised "Too many
    connections" instead of waiting. The stage failed closed, so nothing
    slipped through, but calls were refused for the wrong reason. The store
    now uses a blocking pool, with a test that drives 100 concurrent charges
    through 2 connections. The first results file was discarded, and the
    numbers were measured again at a clean commit.

12. **Replicas must share their counters.** Measured, not argued: with
    counters in each process, two gateways let 400 calls and 79,657.59 in
    payments past per-agent limits, since each admits an agent's full limit.
    With Redis, nothing gets past. A single Lua script drops expired entries,
    checks every limit that applies and charges them all or none.

13. **A negative amount would lower the total.** A sum limit refuses a call
    whose amount is missing, not a number or negative. Amounts are integers
    in millionths, so decimal sums never drift.

14. **Budgets stop early rather than late.** A call is charged when admitted,
    with no refund if a later stage or the upstream fails. Under contention a
    payment that would not fit is refused even if a smaller one later would
    have. The spend scenario stopped agents at most 21.54 short of 10,000.

15. **The same deprecated import, twice.** `testcontainers.redis` warns
    that it is deprecated, which CI's warnings-as-errors would turn into a
    failure, just as `testcontainers.postgres` did in Weekend 3. The current
    path is `testcontainers.community.redis`.

16. **The demo's order matters.** An approved 18,450 payment is charged
    against the daily budget, so the next payment needs a human as well. Run
    after it, the split payment's first half was held too. That is the
    design working, but it confused the story, so the README and CI run the
    split payment first.

## Follow-ups

| Item | Why | When |
| --- | --- | --- |
| ~~Log the active auth mode and pipeline stages at start-up~~ | Done in Weekend 3 | |
| ~~Audit every decision, with the deciding rule~~ | Done in Weekend 3 | |
| Raise per-process throughput, or document scaling out | One process tops out at about 1,000 to 1,500 calls a second, set by the pure-Python HTTP client | Before v0.1 |
| Anchor audit chain heads outside the database | Without that, cutting off the newest rows cannot be detected | Before v0.1 |
| Least-privilege audit role (INSERT and SELECT only) and retention or partitioning | The demo connects as the table owner, which can drop the triggers | Before v0.1 |
| OpenTelemetry metrics (decisions, latency histograms) | Traces exist; dashboards need metrics | After v0.1 |
| ~~A cheap detection layer beside the classifier~~ | Done in Weekend 5; it cannot lower false positives (finding 4) | |
| More attack categories: AgentDojo's retrieved documents, obfuscated, multi-step and long attacks | The benchmark covers two categories in one format family, none over 2,000 characters; the hidden-text layer and the character budget are unmeasured on detection | Next |
| Compare a second classifier (Meta Prompt Guard 2) on the same benchmark | One model is not a baseline; needs the Llama licence accepted | Next |
| Make detection on long results fast | The budget bounds it, but p99 is still 4.9 s; options: batch windows, a smaller default once long attacks are measured | Before v0.1 |
| ~~Recompute `Mcp-Param-*` headers when a stage rewrites arguments~~ | Done in Weekend 5 | |
| Treat results on resumed GET streams conservatively | They arrive without the request they answer | Weekend 4 |
| Cancel the upstream call when the client disconnects before response headers | Wasted upstream work, and a modern-era cancellation not honoured | Before v0.1 |
| RE2 or a timeout for policy regexes | Backtracking on attacker-chosen strings; the 8,192-character cap bounds it but does not remove it | Before v0.1 |
| ~~Budgets across calls~~ | Done in Weekend 6 | |
| OAuth protected-resource metadata (RFC 9728) and CORS preflight | OAuth-capable and browser clients need them to discover and reach the gateway | After v0.1 |
| Nested argument paths in policies | Only top-level arguments can be constrained | After v0.1 |
| A detector layer that can judge a result benign, not only flag it | Max-combined layers only add false positives; the classifier's are on long, repetitive and paired text | Before v0.1 |
| Measure redaction on public PII and secret datasets | The patterns are covered by tests only | Before v0.1 |
| Fetch a tool's schema when it is unknown, instead of refusing | After a restart, redacted calls with `Mcp-Param-*` headers fail closed until the client lists tools | Before v0.1 |
| Notify approvers when a call is held (an outbound webhook to chat or email) | Today an approver has to look at the page or the API | Before v0.1 |
| Sign approvers in through the identity provider (OIDC), not by pasting a token | Pasting a JWT works but is not how people log in | After v0.1 |
| Wake waiting connections across replicas at once (Postgres LISTEN/NOTIFY) | A decision made on another replica is seen within `poll_s` (1 second) | After v0.1 |
| Support MCP tasks for clients that opt in | Stream resumption covers every client today; tasks would let a client show progress | After v0.1 |
| Refund a budget charge when the upstream fails | Charges are conservative: a failed call still counts | After v0.1 |
