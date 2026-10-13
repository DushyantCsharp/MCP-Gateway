# ADR 0002: The gateway creates its schema at start-up; no migration tool yet

- **Status:** accepted for v0.1; to be revisited at the first schema change
- **Decided:** 2026-10-02 (Weekend 3, audit) and 2026-10-03 (Weekend 6, approvals), recorded 2026-10-13
- **Related:** [architecture: audit](../architecture.md#audit),
  `src/mcp_customs/audit/store.py`, `src/mcp_customs/approvals/store.py`

## Context

The gateway owns two Postgres tables:

| Table | Lifetime of a row | Can rows change? |
| --- | --- | --- |
| `customs_audit` | Forever (the record) | No. Triggers refuse `UPDATE`, `DELETE` and `TRUNCATE` |
| `customs_held_calls` | `ttl_s` to decide, then `retention_days` (30) | Yes, through the status state machine |

v0.1 is the first release, so there is one version of each table and nothing
to migrate from.

## Decision

- At start-up the gateway runs `CREATE TABLE IF NOT EXISTS` and
  `CREATE OR REPLACE` for its triggers, under a Postgres advisory lock so
  replicas starting together do not race. There is no migration framework.
- An audit row's hash covers the chain name, sequence number, previous hash
  and the canonical event JSON (`body`). The `event` column is generated from
  `body` and is not part of the hash. Each event carries a schema version
  (`"v": 1`).

## Why

With one schema version, a migration tool would have nothing to run.
Creating what is missing keeps `docker compose up` and `customs run` to one
step.

## Consequences

- `CREATE TABLE IF NOT EXISTS` never alters a table that exists. A release
  that changes a column would not apply that change to an existing database.
  The first schema change therefore needs a real migration step; this ADR
  must be superseded before that change ships.
- **The audit table cannot be migrated by rewriting rows.** That is the
  point of it. Any change to what an event records has to be a new event
  version, written beside the old ones. `verify-audit` must go on verifying
  every version ever written. New columns can only be generated from `body`
  or left empty for old rows.
- Creating tables at start-up needs DDL rights, so in v0.1 the gateway
  connects as the table owner. An owner can also drop the triggers. A
  least-privilege role (only `INSERT` and `SELECT` on the audit table) is a
  [follow-up](../build-notes.md#follow-ups), and it conflicts with
  creating the schema at start-up.

## Open: what the first migration should look like

This is a proposal, not a decision:

1. A `customs migrate` command, run once per release with owner rights,
   applies numbered SQL files and records them in a version table. The
   gateway runs with `INSERT` and `SELECT` only, and refuses to start if the
   schema version is not the one it expects.
2. Audit changes are additive only: a new event version, never a rewritten
   row.
3. Breaking changes to `customs_held_calls` drain instead of migrating.
   Stop accepting new holds, let pending ones be decided or expire within
   `ttl_s`, then switch tables. In-flight holds are why this needs a plan:
   a held payment must not be lost or replayed across the change.
