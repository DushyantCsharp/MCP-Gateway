# Security policy

mcp-customs is pre-release software that sits on a security boundary, so
reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately, through GitHub's
[private vulnerability reporting](https://github.com/DushyantCsharp/MCP-Gateway/security/advisories/new),
not in a public issue. Include what you found, how to reproduce it, and the
commit or version you tested.

You can expect an acknowledgement within a week and, once a fix is ready, a
public advisory that credits you unless you prefer otherwise.

## Scope

In scope: ways to get a call past policy, an approval or a budget; to forge,
replay or steal sessions, held calls or tokens; to edit the audit log without
`customs verify-audit` noticing; to make the gateway forward what it should
refuse, or fail open. Out of scope: the limits listed in the
[threat model](docs/threat-model.md) under "What it does not stop", such as
injection attacks the detectors miss (those are welcome as benchmark
contributions instead).
