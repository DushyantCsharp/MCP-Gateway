# ADR 0001: Held calls wait in Postgres, not a message queue

- **Status:** accepted
- **Decided:** 2026-10-03 (Weekend 6), recorded 2026-10-13
- **Related:** [architecture: approvals](../architecture.md#approvals),
  [build notes: Weekend 6](../build-notes.md#weekend-6-approvals-and-budgets-2026-10-03)

## Context

Two kinds of work wait inside the gateway.

1. **Held calls.** A call that needs a human waits minutes to an hour
   (`ttl_s`, default 3,600). It must survive a gateway restart, be picked up
   by whichever replica the client reconnects to, be made at most once
   after approval, and keep its full request: the approver has to read the
   arguments, and the gateway has to replay them. The approver chooses which
   call to decide, in any order. Holds arrive at human pace, not at
   request rate.
2. **Audit events.** Every call's `request` row must commit before the call
   is forwarded (durable mode, the default), at request rate.

## Decision

- **Held calls are rows in Postgres** (`customs_held_calls`), with a status
  column as the state machine: `pending`, then `approved`, `denied` or
  `expired`, then `executing`, then `completed` or `unknown`. Making an
  approved call starts with a conditional update from `approved` to
  `executing`, which only one connection can win. The answer is stored
  before it is delivered. Waiting connections poll for a decision every
  `poll_s` (1 second).
- **Audit events go through an in-process queue** that one writer task
  drains, committing each batch in a single transaction (group commit). A
  durable call waits for its batch to commit, up to `commit_timeout_s`
  (5 seconds), and is refused if it does not.
- **There is no message broker.**

## Why

A held call needs a durable record with a compare-and-set on its status, not
delivery to a consumer. Nothing consumes holds in order: a person picks one
from a page. A broker (RabbitMQ, SQS, Kafka, Redis streams) would deliver the
message, but the approvals page, the stored answer and the single-winner
claim would still need a database. That is two stores to keep consistent
instead of one.

Postgres is already required for the audit log, and the held-call table may
share its database. Redis is in the stack for budgets, but its default
persistence can lose recent writes on a crash, and a lost held payment is
worse than a slow one.

For audit, a broker would put a network hop and a second durability story
between "the row is safe" and "forward the call". Group commit gets the
batching a queue would give, with the commit itself as the acknowledgement.

## Consequences

- A held call survives a restart and moves between replicas that share the
  database. The contract test and the Docker demo in CI both prove this.
- A decision made on one replica reaches a client waiting on another within
  `poll_s`. Postgres `LISTEN`/`NOTIFY` would make that immediate; it is a
  follow-up.
- Held rows keep their arguments in full, unlike the audit log, which keeps
  a digest. They are deleted `retention_days` (30) after they finish.
- At most once, never exactly once. If a gateway stops between claiming a
  call and storing its answer, the call becomes `unknown` and is not retried.
- Each gateway process has its own audit chain and writer, so scaling out
  means more chains, not a shared queue.

## Alternatives considered

| Option | Why not |
| --- | --- |
| Redis lists or streams | Durability depends on how Redis persistence is configured; still needs a store for the approver page and the stored answer |
| A broker (RabbitMQ, SQS, Kafka) | One more service to run; delivers messages but does not give a single-winner claim or a readable record |
| In memory | Lost on restart, which is the case the milestone exists to cover |
| MCP tasks (SEP-1686) | Only clients that opt in support them. Stream resumption (SEP-1699) needs no client changes. Tasks may be added later for clients that want progress |
