# Demo walkthrough

A three-minute tour of the Docker demo, written to be recorded: two terminals
side by side (agent on the left, operator on the right) and a browser. Every
command is from the [Quick start](../README.md#quick-start); timings are what
to aim for.

Before recording: `docker compose -f demo/compose.yaml up --build --wait`, so
the stack is already running, and in each terminal
`alias c='docker compose -f demo/compose.yaml'`.

## 0:00 What it is (15 s)

Show the README's results table.

> "mcp-customs sits between an AI agent and its MCP tools. Every call is
> checked, recorded, and if it matters, put in front of a human. These are the
> measured numbers, including what isn't measured."

## 0:15 An ordinary task (25 s)

Left: `c run --rm agent`

> "A scripted accounts-payable agent summarises an invoice. Note the line
> `gateway redacted: email, phone`: the vendor's personal contact details
> never reached the agent."

## 0:40 Splitting a payment (40 s)

Left: `c run --rm -e AGENT_TASK=split-payment agent`

> "Now it pays the same invoice in two halves, each under the 10,000
> per-payment limit. The first goes through. The second would take today's
> total past the daily budget, so it waits: the gateway's notice is right
> there."

Right: `c run --rm approver approvals list`, then
`c run --rm approver approvals deny <id> --reason "split payment"`

> "A person looks at it and says no. The agent is told why, and stops."

## 1:20 A payment that needs a human, and a restart (60 s)

Left: `c run --rm -e AGENT_TASK=pay-invoice agent`

> "Paying the whole 18,450 needs approval under the policy. The agent just
> waits."

Right: `c restart gateway`

> "Now I restart the gateway, mid-wait. The held call is in Postgres, and the
> agent reconnects by itself."

Browser: open <http://localhost:8000/approvals>, sign in with the approver
token (`c run --rm --entrypoint cat approver /tokens/approver.jwt`), and
approve.

> "The approver sees exactly what will be sent. Approve, and the agent's
> original call returns the payment receipt: made once, after the restart."

## 2:20 The record (30 s)

Right: `c exec gateway customs verify-audit --key-env CUSTOMS_AUDIT_KEY`

> "Every call, hold, decision and payment is in a hash-chained audit log, and
> this re-hashes all of it."

Browser: <http://localhost:16686>, open a `tools/call transfer_funds` trace.

> "And every call is traced, a span per stage."

## 2:50 Close (10 s)

> "Policy, approvals, budgets, redaction, audit and tracing, in front of any
> MCP server, remote or local. The threat model says what it doesn't stop."
