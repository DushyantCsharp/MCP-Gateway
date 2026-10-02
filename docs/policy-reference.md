# Policy reference

A policy decides, for every request that names a tool, prompt or resource,
whether the caller may make it. Policies are YAML files loaded by the policy
stage:

```yaml
# customs.yaml
stages:
  - type: policy
    file: policies/finance-agent.yaml   # relative to this file
```

Check a policy, or a single call against it, without running the gateway:

```bash
customs check-policy policies/examples/finance-agent.yaml
customs check-policy policies/examples/finance-agent.yaml \
  --agent ap-agent --upstream finance --tool transfer_funds \
  --arguments '{"from_account": "ACC-OPERATING", "to_account": "ACC-NORTHWIND", "amount": "18450.00", "memo": "INV-2026-091"}'
# DENY: arguments not permitted by rule 'ap-pay-known-vendors'
#   ap-pay-known-vendors: argument 'amount': max failed
```

The exit status is 0 when the call is allowed, 1 when it is denied and 2 on an
error, so policy expectations can run in CI.

## How rules combine

1. A call is **denied** if any deny rule that matches it holds.
2. Otherwise it is **allowed** if any allow rule that matches it holds.
3. Otherwise it is **denied**. Nothing is allowed by default.

Rule order never matters. To allow everything, write an allow rule for `"*"`.
Writing a deny-list on top of an allow-everything rule is possible, but a
deny-list fails open on whatever its author did not think of.

If the caller's token carries `mcp:` scope grants, a call outside those grants
is denied before any rule is consulted (see [Identity](#identity)).

## File format

```yaml
version: 1
description: Optional text.
rules:
  - id: ap-pay-known-vendors           # unique; shown in denials and logs
    effect: allow                      # allow | deny
    description: Optional text.
    agents: [ap-agent]                 # who (globs); omitted = any caller, even anonymous
    roles: [accounts-payable]          # caller holds any of these (globs)
    upstreams: [finance]               # where (globs); omitted = every upstream
    tools: [transfer_funds]            # what: tools, prompts, resources and/or methods (globs)
    arguments:                         # optional constraints on top-level arguments
      amount: {min: 0.01, max: 10000}
      to_account: {in: [ACC-NORTHWIND]}
    additional_arguments: false        # allow rules only: unlisted arguments fail the rule
```

| Field | Meaning |
| --- | --- |
| `id` | Letters, digits, `_`, `.` and `-`; unique in the file. |
| `effect` | `allow` or `deny`. |
| `agents` | Agent ids, as globs. When present, anonymous callers never match. |
| `roles` | Matches when the caller holds at least one listed role (globs). |
| `upstreams` | Upstream names from the gateway configuration (globs). |
| `tools` | Tool names for `tools/call` (globs). |
| `prompts` | Prompt names for `prompts/get` (globs). |
| `resources` | Resource URIs for `resources/read`, `resources/subscribe` and `resources/unsubscribe` (globs). |
| `methods` | Any other JSON-RPC method by name (globs), for example `subscriptions/listen`. |
| `arguments` | Constraints on the arguments of a tool or prompt call. |
| `additional_arguments` | Defaults to `true`. With `false` (allow rules only), an argument not listed under `arguments` fails the rule, which stops a model from adding a `cc` or `fee_account` nobody reviewed. |

A rule needs at least one of `tools`, `prompts`, `resources` or `methods`.
Globs are case-sensitive shell patterns: `*` matches any run of characters,
including `/`.

## Which requests are governed

| Request | Treatment |
| --- | --- |
| `initialize`, `ping`, `server/discover`, `logging/setLevel` | Always allowed: protocol plumbing. |
| Notifications, and answers to the server's own requests | Always allowed. |
| `tools/list`, `prompts/list`, `resources/list` | Allowed; results are filtered (see [Listings](#listings)). |
| `resources/templates/list` | Allowed and not filtered. |
| `tools/call`, `prompts/get` | Decided by name, with argument constraints. |
| `resources/read`, `resources/subscribe`, `resources/unsubscribe` | Decided by URI. |
| `completion/complete` | Decided as a call to the referenced prompt (with no arguments) or resource. |
| Anything else | Decided by method name under `methods`. Unknown methods are denied unless a rule allows them. |

A governed request without a name or URI is refused as malformed.

## Argument constraints

Each constraint applies to one top-level argument. Every operator given must
hold.

| Operator | Holds when | Applies to |
| --- | --- | --- |
| `equals: v` | the value equals `v` | strings, numbers, booleans, null |
| `in: [...]` | the value equals one of the list | same |
| `not_in: [...]` | the value equals none of the list | same |
| `matches: re` | the whole string matches the regular expression | strings |
| `not_matches: re` | the whole string does not match | strings |
| `min: n`, `max: n` | the number is within range (inclusive) | numbers, and decimal strings such as `"18450.00"` |
| `min_length: n`, `max_length: n` | the string has that many characters | strings |
| `optional: true` | see below | any |

Equality follows JSON, not Python: `true` is not `1`, and `1` equals `1.0`.
Decimal strings are compared as numbers only in plain form (`-?digits[.digits]`);
`"1e3"`, `"07"` and `" 7"` are not numbers.

### Unknown, and why it matters

A constraint can be true, false or **unknown**. It is unknown when the value
has the wrong type (a list where a string was expected), when the argument is
missing, when the arguments are not an object, or when a string is longer than
8,192 characters (too long to match patterns against safely).

- An allow rule holds only if every constraint is **true**.
- A deny rule holds if no constraint is **false**, so an **unknown** constraint
  triggers it.

So whatever the gateway cannot check, it does not let through. For example,
`to_account: {equals: ACC-PAYROLL}` on a deny rule also catches
`to_account: ["ACC-PAYROLL"]`, a value a lenient server might accept.

### `optional`

By default a missing argument is unknown. That fails an allow rule and
triggers a deny rule. `optional: true` says absence is harmless: a missing
argument satisfies that constraint on an allow rule, and never triggers a
deny rule.

```yaml
- id: ap-read-balances
  effect: allow
  tools: [list_transactions]
  arguments:
    limit: {min: 1, max: 50, optional: true}   # the server's default page size is fine
```

## Identity

With authentication configured, every caller presents a JWT. The policy sees:

| Claim (default name) | Used as |
| --- | --- |
| `sub` | the agent id matched by `agents` |
| `roles` (list, or space-separated string) | roles matched by `roles` |
| `task` | a label for logs and audit |
| `scope` | `mcp:` grants that narrow the token to one task |

Claim names are configurable under `auth.jwt` (`agent_claim`, `roles_claim`,
`task_claim`, `scope_claim`).

A scope entry `mcp:<upstream>:<name>` grants one upstream and one tool,
prompt, resource URI or method name; either part may be a glob. Other scope
values (`openid`, `email`) are ignored. When a token carries any `mcp:`
entries, calls outside them are denied whatever the policy says. A
task-scoped token can only narrow what the agent's policy allows, never
widen it. A token with no `mcp:` entries is not narrowed.

```text
scope: "openid mcp:workspace:search_docs mcp:workspace:read_doc mcp:finance:get_*"
```

Without authentication every caller is anonymous: only rules with no `agents`
or `roles` can match.

## Listings

`tools/list`, `prompts/list` and `resources/list` results are filtered, so a
model is never shown a tool it may not call. An item is listed when some
allow rule could allow it for this caller (argument constraints aside), no
deny rule without argument constraints forbids it outright, and the token's
grants cover it. A filtered result is marked `cacheScope: private` because it
now depends on who asked.

## What the caller sees

| Denied request | Reply |
| --- | --- |
| `tools/call` | A tool result with `isError: true` and the text `Blocked by gateway policy: <reason>.`. The model can read this and change course. |
| Anything else | JSON-RPC error `-32090` with the same message and `data.rule`. |

The reason names the deciding rule, but not which argument failed or what
limit applies, so a model cannot easily probe its way around the rule (for
example by splitting one payment into several). The gateway log records the
details.

## Limitations

- Constraints apply to top-level arguments only; there are no nested paths yet.
- Patterns run on Python's backtracking regex engine against attacker-chosen
  strings. The length cap bounds the input, but a pathological pattern can
  still be slow. Keep patterns simple and anchored by design (matching is
  always full-string).
- Policies are per call. Limits across calls, such as a daily payment total,
  are what budgets are for (a later milestone).
- `resources/templates/list` is not filtered.
