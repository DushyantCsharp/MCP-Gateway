# ADR 0003: Enforcement fails closed; detection and tracing degrade

- **Status:** accepted
- **Decided:** over Weekends 1 to 6 (2026-10-02 to 03), recorded 2026-10-13
- **Related:** [architecture: failure semantics](../architecture.md#failure-semantics),
  [threat model](../threat-model.md)

## Context

The gateway depends on things that can fail: Postgres (audit and held
calls), Redis (budgets), the identity provider's keys, the classifier, the
trace collector and the upstream servers. For each one, the gateway must
choose between letting calls through without that dependency and refusing
them.

## Decision

Anything that enforces something fails closed. If the gateway cannot check
a call, it does not make it. Anything that only observes or advises keeps
working without its dependency.

| When this fails | The gateway | So that |
| --- | --- | --- |
| Audit row cannot commit within `commit_timeout_s` (5 s) | refuses the call: `503`, `-32085` | no call runs unaudited |
| Approval store, when a call needs holding | refuses the call with a readable tool error (`-32094` for other requests) | "needs a human" never becomes "allowed" |
| Budget store (Redis) | refuses the call with a tool error | a limit is never skipped |
| Identity provider's keys, none cached | refuses: `503`, `-32083` | no unauthenticated call |
| Any stage raises | refuses the request (`500`, `-32603`), or withholds the result | a crashed check is not a pass |
| A tool's header schema is unknown after a restart, and a stage rewrote its arguments | refuses the call until the client lists tools again | redacted values never travel in headers |
| Upstream unreachable or times out | `502` or `504`, not retried | a payment is never sent twice |
| Gateway stops while making an approved call | `unknown`, not retried | at most once |
| Classifier is slow on a long result | reads only the first and last 8,000 characters (`max_chars`) | latency stays bounded; the hidden-text checks still read everything |
| Classifier is wrong (36% false positives at its default threshold) | flags, does not block (`mode: flag`, the default) | a noisy detector does not become an outage |
| Trace collector | drops spans (OpenTelemetry's batch processor); calls continue | tracing is not the record; the audit log is |

## Why

The gateway exists so that a risk function can say "every call was
authenticated, checked, budgeted and recorded". One unchecked call breaks
that claim. An outage is visible and recoverable; a silently skipped check
is neither.

Detection is the exception because it is not a reliable control. The
measured false-positive rate makes blocking on it an outage of its own (see
[Results](../../README.md#results)). Policy, approvals and budgets stop a
steered agent. The detector is a tripwire that flags for review.

## Consequences

- Postgres and Redis are availability dependencies. A Postgres outage stops
  every call while durable audit is on. Run them highly available, or accept
  that the gateway is down when they are. `audit.durable: false` trades the
  guarantee for availability.
- Budget charges are not refunded when a later stage or the upstream fails,
  so budgets err towards stopping early.
- There is **no load shedding yet.** Under overload the gateway queues, and
  latency grows: +60 ms at p50 at 50 clients, with no errors (see
  [What breaks first at 10x](../../README.md#what-breaks-first-at-10x)).
  The only caps are per resource: request size, `max_pending_per_agent` (20)
  held calls, and `max_sessions` (32) local processes per upstream. A
  concurrency limit that answers `503` early is open work.
