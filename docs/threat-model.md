# Threat model

mcp-customs is defence in depth for AI agents that use MCP tools. It narrows
what an agent can do, puts a human in front of what matters, keeps a record
that is hard to rewrite, and catches some of what a model should not read. It
does not make an agent safe on its own. This page says what it protects, from
whom, and how, and, just as plainly, what it does not stop.

## What sits where

```
 agent (MCP client)  ──►  mcp-customs  ──►  MCP servers (remote over HTTP, or local over stdio)
   untrusted intent        trusted          trusted to run tools; everything they return is untrusted
                              │
          identity provider (trusted) · approvers (trusted people) · Postgres, Redis (trusted infrastructure)
```

| Party | Trusted to | Not trusted to |
| --- | --- | --- |
| Agent | Present a token it was issued | Stay within its task: it may be confused, or steered by text it reads |
| MCP server | Carry out the tool calls it receives | Return content free of instructions or secrets; behave well at the protocol level |
| Content in tool results (emails, pages, documents) | Nothing | Anything: it may be written by an attacker |
| Identity provider | Issue tokens for real agents and approvers | |
| Approvers | Decide held calls in good faith | Be immune to persuasive arguments shown to them |
| Operators | Configure policy, budgets and secrets | |
| Postgres and Redis | Store what they are given | Prevent their own administrators from editing it |

## What it protects, and how

| Threat | Mitigation | Evidence |
| --- | --- | --- |
| An agent calls a tool, prompt or resource outside its role or task | Default-deny policy on agent, role, upstream, target and arguments; task-scoped tokens can only narrow it; listings hide what cannot be used | Enforcement suite: every disallowed case blocked at the upstream, in both protocol eras, plus fuzzed transfers |
| An agent passes arguments it should not (an external recipient, an extra `cc`, a payroll account) | Argument constraints in three-valued logic: what cannot be checked never satisfies an allow rule and always triggers a deny or approve rule | Same suite; an independent restatement of the policy checked against 2,000 generated transfers |
| A consequential call is made without anyone looking | Approve rules and budget limits hold the call until an approver decides; the approved call is made at most once, after the pipeline runs again | Restart test: a held payment survives a gateway restart and is made exactly once |
| An agent stays under per-call limits by splitting the work | Per-agent budgets across calls (counts, sums of an argument, costs), atomic in Redis | Budget accuracy: no call or amount past a limit with 200 concurrent clients |
| Secrets or personal data cross the gateway | Redaction of secrets in requests, and of secrets and personal data in results, with checksums where they exist | Unit and contract tests (not measured on real traffic) |
| Tool output carries instructions for the model | Injection stage: hidden-text checks and a classifier, flagging, stripping or withholding results | 80.9% of benchmark attacks flagged at 36.0% false positives, or 52.8% at 4.0% (test split); misses listed by id |
| A client's token reaches a server it was not issued for | No token passthrough: `Authorization` and `Cookie` stop at the gateway; upstream credentials are injected per upstream | Header tests |
| Another agent takes over a session or a held call | Session ids are HMAC-bound to their agent; resume tokens are random, stored as digests, and checked against agent, upstream and session | Contract tests |
| A browser page drives the gateway (DNS rebinding) | `Origin` allow-list | Contract tests |
| A malformed or ambiguous message slips past a check | One strict JSON-RPC message per request; duplicate keys, `NaN`, batches and routing-header mismatches refused | Property and contract tests |
| A local server reads the gateway's secrets | A `command` upstream inherits only `PATH`, `HOME`, the locale and its own `env` | Contract test |
| Someone edits the record afterwards | Hash-chained audit log (HMAC with a key), append-only triggers, `customs verify-audit`; durable mode refuses calls it cannot record | Audit tests, including verification across gateway restarts |
| The gateway fails | Every failure is closed: a stage error, an unreachable audit log, budget store or approval store stops the call | Failure tests |

## What it does not stop

- **A prompt-injected agent.** The detectors miss attacks: about one in five
  benchmark attacks at a false-positive rate too high to block on, and about
  half at a usable one. They look at one result at a time, so an attack
  spread across several results is not seen as one. Obfuscation beyond hidden
  characters, look-alike letters and base64 is not covered. Attack success
  against a live agent with the gateway on has not been measured (see the
  Weekend 7 build notes). Treat detection as a tripwire, and rely on policy,
  approvals and budgets for anything that matters.
- **Exfiltration through allowed channels.** If policy allows email to the
  company's domain, an agent can still put data into an email to an internal
  address, or encode it in any field a rule permits.
- **What a tool does inside.** The gateway sees calls and their arguments,
  not the side effects of a tool, or what an MCP server does with other
  systems.
- **A fooled or malicious approver.** The approvals page shows the arguments,
  escaped and without scripts, but a person can still be persuaded by them.
  Approvers are trusted.
- **Policies that say too little.** Constraints apply to top-level arguments
  only, and per call; an allow rule written too broadly allows too much.
- **Secrets and personal data the patterns do not know.** Redaction is
  pattern-based: free-form secrets, encoded data and unusual formats pass.
- **Rewriting the audit log by its database owner.** The chain is
  tamper-evident, not tamper-proof: cutting off its newest rows cannot be
  detected without anchoring its head somewhere else, and the table owner can
  drop the append-only triggers.
- **A compromised gateway host.** It holds the token secret, the audit key and
  the upstream credentials.
- **Local servers acting on the machine.** A `command` upstream runs with the
  gateway's user, without a sandbox: it can read files and use the network as
  that user. Run untrusted local servers in their own container.
- **Denial of service.** Budgets limit each agent, but there is no global
  rate limit, the classifier spends seconds on long results, and policy
  regexes run on a backtracking engine (input length is capped).
- **Traffic that does not go through it.** If an agent can reach an MCP
  server directly, nothing here applies.

## What a deployment must provide

- MCP servers reachable only through the gateway (network policy, or
  credentials only the gateway holds).
- TLS in front of the gateway.
- Short-lived tokens from a real identity provider (`auth.jwt.jwks_url`),
  with distinct identities for agents and approvers.
- `auth.session_secret` and `audit.key` set, and kept out of the
  configuration file.
- Redis with `maxmemory-policy noeviction` for budgets, shared by every
  replica.
- The approvals page behind HTTPS, with `approvals.secure_cookies` left on.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
