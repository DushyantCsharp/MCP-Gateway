"""What the example finance policy must decide, written as its author intends it.

Shared by the engine's unit tests and the gateway's enforcement tests, so the
same table is checked in-process and over the wire.
"""

import re
from decimal import Decimal, InvalidOperation
from typing import Any, NamedTuple

from hypothesis import strategies as st

from mcp_customs.auth import Identity
from mcp_customs.policy import Effect, TargetKind

AP = Identity("ap-agent")
AUDITOR = Identity("audit-bot", frozenset({"auditor"}))
INTRUDER = Identity("intruder")
T, P, R = TargetKind.TOOL, TargetKind.PROMPT, TargetKind.RESOURCE
ALLOW, DENY, APPROVE = Effect.ALLOW, Effect.DENY, Effect.APPROVE


class Case(NamedTuple):
    label: str
    identity: Identity | None
    upstream: str
    kind: TargetKind
    name: str
    arguments: Any
    expected: Effect


def transfer(**overrides: Any) -> dict[str, Any]:
    base = {
        "from_account": "ACC-OPERATING",
        "to_account": "ACC-NORTHWIND",
        "amount": "500.00",
        "memo": "INV-1",
    }
    return {key: value for key, value in {**base, **overrides}.items() if value is not None}


def email(**overrides: Any) -> dict[str, Any]:
    base = {"to": "ap@acme.example", "subject": "Summary", "body": "Paid."}
    return {key: value for key, value in {**base, **overrides}.items() if value is not None}


W, F = "workspace", "finance"
PAYROLL = "ACC-PAYROLL"
OPS = {"account_id": "ACC-OPERATING"}

# fmt: off
FINANCE_CASES: list[Case] = [
    Case("read docs", AP, W, T, "search_docs", {"query": "x"}, ALLOW),
    Case("read a doc", AP, W, T, "read_doc", {"doc_id": "x"}, ALLOW),
    Case("docs on the wrong upstream", AP, F, T, "read_doc", {"doc_id": "x"}, DENY),
    Case("document index", AP, W, R, "workspace://documents", None, ALLOW),
    Case("other resource", AP, W, R, "workspace://secrets", None, DENY),
    Case("summary prompt", AP, W, P, "summarise_document", {"doc_id": "x"}, ALLOW),
    Case("other prompt", AP, W, P, "leak_everything", {}, DENY),
    Case("reindex", AP, W, T, "reindex", {}, DENY),
    Case("internal email", AP, W, T, "send_email", email(), ALLOW),
    Case("external email", AP, W, T, "send_email", email(to="x@evil.example"), DENY),
    Case("lookalike domain", AP, W, T, "send_email", email(to="ap@acme.example.evil.io"), DENY),
    Case("display-name smuggling", AP, W, T, "send_email", email(to="ap@acme.example <x@evil.io>"), DENY),
    Case("recipient list", AP, W, T, "send_email", email(to=["ap@acme.example"]), DENY),
    Case("hidden cc", AP, W, T, "send_email", {**email(), "cc": "x@evil.example"}, DENY),
    Case("no recipient", AP, W, T, "send_email", email(to=None), DENY),
    Case("oversized body", AP, W, T, "send_email", email(body="x" * 5001), DENY),
    Case("balance", AP, F, T, "get_balance", OPS, ALLOW),
    Case("transactions, default page", AP, F, T, "list_transactions", OPS, ALLOW),
    Case("transactions, page of 50", AP, F, T, "list_transactions", {**OPS, "limit": 50}, ALLOW),
    Case("transactions, page of 51", AP, F, T, "list_transactions", {**OPS, "limit": 51}, DENY),
    Case("small vendor payment", AP, F, T, "transfer_funds", transfer(), ALLOW),
    Case("payment at the limit", AP, F, T, "transfer_funds", transfer(amount=10000), ALLOW),
    Case("payment over the limit", AP, F, T, "transfer_funds", transfer(amount="10000.01"), APPROVE),
    Case("the Northwind invoice", AP, F, T, "transfer_funds", transfer(amount="18450.00"), APPROVE),
    Case("payment at the approval cap", AP, F, T, "transfer_funds", transfer(amount="50000"), APPROVE),
    Case("payment over the approval cap", AP, F, T, "transfer_funds", transfer(amount="50000.01"), DENY),
    Case("large, unknown vendor", AP, F, T, "transfer_funds", transfer(amount="18450", to_account="X"), DENY),
    Case("large, payroll", AP, F, T, "transfer_funds", transfer(amount="18450", from_account=PAYROLL), DENY),
    Case("large, long memo", AP, F, T, "transfer_funds", transfer(amount="18450", memo="m" * 141), DENY),
    Case("auditor, large payment", AUDITOR, F, T, "transfer_funds", transfer(amount="18450.00"), DENY),
    Case("zero payment", AP, F, T, "transfer_funds", transfer(amount=0), DENY),
    Case("negative payment", AP, F, T, "transfer_funds", transfer(amount=-5), DENY),
    Case("exponent amount", AP, F, T, "transfer_funds", transfer(amount="1e3"), APPROVE),
    Case("boolean amount", AP, F, T, "transfer_funds", transfer(amount=True), APPROVE),
    Case("unknown vendor", AP, F, T, "transfer_funds", transfer(to_account="ACC-ATTACKER"), DENY),
    Case("to payroll", AP, F, T, "transfer_funds", transfer(to_account="ACC-PAYROLL"), DENY),
    Case("from payroll", AP, F, T, "transfer_funds", transfer(from_account="ACC-PAYROLL"), DENY),
    Case("extra argument", AP, F, T, "transfer_funds", {**transfer(), "fee_account": "X"}, DENY),
    Case("long memo", AP, F, T, "transfer_funds", transfer(memo="m" * 141), DENY),
    Case("unknown tool", AP, F, T, "close_account", {}, DENY),
    Case("case variant", AP, F, T, "Transfer_Funds", transfer(), DENY),
    Case("auditor reads", AUDITOR, F, T, "get_balance", OPS, ALLOW),
    Case("auditor pays", AUDITOR, F, T, "transfer_funds", transfer(), DENY),
    Case("auditor emails", AUDITOR, W, T, "send_email", email(), DENY),
    Case("intruder reads", INTRUDER, W, T, "read_doc", {"doc_id": "x"}, DENY),
    Case("anonymous reads", None, W, T, "read_doc", {"doc_id": "x"}, DENY),
]
# fmt: on


# -- generated transfers, and what the policy's author intends for them ----------------------------

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**12), max_value=10**12),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    st.text(max_size=20),
)
json_values = st.recursive(json_scalars, lambda inner: st.lists(inner, max_size=3), max_leaves=5)
amounts = st.one_of(
    json_values,
    st.decimals(min_value=-20000, max_value=20000, places=2, allow_nan=False).map(str),
    st.integers(min_value=-100, max_value=20000),
)
accounts = st.one_of(
    st.sampled_from(["ACC-OPERATING", "ACC-NORTHWIND", "ACC-PAYROLL", "acc-operating"]), json_values
)


type Tri = bool | None


def _all(*values: Tri) -> Tri:
    if False in values:
        return False
    return None if None in values else True


def _argument(arguments: dict[str, Any], name: str, check: Any) -> Tri:
    """Unknown when absent; unknown for a list or object where a value was expected."""
    if name not in arguments:
        return None
    value = arguments[name]
    return None if isinstance(value, list | dict) else check(value)


def _amount(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return None
    if isinstance(value, str) and not re.fullmatch(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?", value):
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None


def _in_range(value: Any, low: str, high: str) -> Tri:
    amount = _amount(value)
    return None if amount is None else Decimal(low) <= amount <= Decimal(high)


def author_intends(arguments: dict[str, Any]) -> Effect:
    """What the finance policy's author intends for a transfer, restated without the engine.

    Payroll never pays, even when the source cannot be read. A payment to a
    vendor on file above the single-approver limit, up to 50,000, goes to a
    human, and so does one that would qualify except that a value cannot be
    read: what the gateway cannot check, a human checks. Smaller payments that
    meet every condition go ahead. Everything else is refused.
    """
    payroll = _argument(arguments, "from_account", lambda value: value == "ACC-PAYROLL")
    if payroll is not False:
        return DENY
    large = _all(
        _argument(arguments, "from_account", lambda value: value == "ACC-OPERATING"),
        _argument(arguments, "to_account", lambda value: value == "ACC-NORTHWIND"),
        _argument(arguments, "amount", lambda value: _in_range(value, "10000.01", "50000")),
        _argument(arguments, "memo", lambda value: len(value) <= 140 if isinstance(value, str) else None),
    )
    if large is not False:
        return APPROVE
    return ALLOW if author_intends_to_allow(arguments) else DENY


def author_intends_to_allow(arguments: dict[str, Any]) -> bool:
    """The finance policy's single-approver rule, restated from its comments, without the engine."""
    if set(arguments) != {"from_account", "to_account", "amount", "memo"}:
        return False
    amount = arguments["amount"]
    if isinstance(amount, bool) or not isinstance(amount, int | float | str):
        return False
    if isinstance(amount, str) and not re.fullmatch(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?", amount):
        return False
    try:
        value = Decimal(str(amount))
    except InvalidOperation:
        return False
    memo = arguments["memo"]
    return (
        arguments["from_account"] == "ACC-OPERATING"
        and isinstance(arguments["from_account"], str)
        and arguments["to_account"] == "ACC-NORTHWIND"
        and isinstance(arguments["to_account"], str)
        and Decimal("0.01") <= value <= Decimal(10000)
        and isinstance(memo, str)
        and len(memo) <= 140
    )


transfer_arguments = st.fixed_dictionaries(
    {},
    optional={
        "from_account": accounts,
        "to_account": accounts,
        "amount": amounts,
        "memo": st.one_of(st.text(max_size=160), json_values),
        "fee_account": accounts,
    },
)
"""Argument objects for transfer_funds: valid, invalid, mistyped, incomplete and over-full."""
