"""What the example finance policy must decide, written as its author intends it.

Shared by the engine's unit tests and the gateway's enforcement tests, so the
same table is checked in-process and over the wire.
"""

import re
from decimal import Decimal, InvalidOperation
from typing import Any, NamedTuple

from hypothesis import strategies as st

from mcp_customs.auth import Identity
from mcp_customs.policy import TargetKind

AP = Identity("ap-agent")
AUDITOR = Identity("audit-bot", frozenset({"auditor"}))
INTRUDER = Identity("intruder")
T, P, R = TargetKind.TOOL, TargetKind.PROMPT, TargetKind.RESOURCE


class Case(NamedTuple):
    label: str
    identity: Identity | None
    upstream: str
    kind: TargetKind
    name: str
    arguments: Any
    allowed: bool


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
OPS = {"account_id": "ACC-OPERATING"}

# fmt: off
FINANCE_CASES: list[Case] = [
    Case("read docs", AP, W, T, "search_docs", {"query": "x"}, True),
    Case("read a doc", AP, W, T, "read_doc", {"doc_id": "x"}, True),
    Case("docs on the wrong upstream", AP, F, T, "read_doc", {"doc_id": "x"}, False),
    Case("document index", AP, W, R, "workspace://documents", None, True),
    Case("other resource", AP, W, R, "workspace://secrets", None, False),
    Case("summary prompt", AP, W, P, "summarise_document", {"doc_id": "x"}, True),
    Case("other prompt", AP, W, P, "leak_everything", {}, False),
    Case("reindex", AP, W, T, "reindex", {}, False),
    Case("internal email", AP, W, T, "send_email", email(), True),
    Case("external email", AP, W, T, "send_email", email(to="x@evil.example"), False),
    Case("lookalike domain", AP, W, T, "send_email", email(to="ap@acme.example.evil.io"), False),
    Case("display-name smuggling", AP, W, T, "send_email", email(to="ap@acme.example <x@evil.io>"), False),
    Case("recipient list", AP, W, T, "send_email", email(to=["ap@acme.example"]), False),
    Case("hidden cc", AP, W, T, "send_email", {**email(), "cc": "x@evil.example"}, False),
    Case("no recipient", AP, W, T, "send_email", email(to=None), False),
    Case("oversized body", AP, W, T, "send_email", email(body="x" * 5001), False),
    Case("balance", AP, F, T, "get_balance", OPS, True),
    Case("transactions, default page", AP, F, T, "list_transactions", OPS, True),
    Case("transactions, page of 50", AP, F, T, "list_transactions", {**OPS, "limit": 50}, True),
    Case("transactions, page of 51", AP, F, T, "list_transactions", {**OPS, "limit": 51}, False),
    Case("small vendor payment", AP, F, T, "transfer_funds", transfer(), True),
    Case("payment at the limit", AP, F, T, "transfer_funds", transfer(amount=10000), True),
    Case("payment over the limit", AP, F, T, "transfer_funds", transfer(amount="10000.01"), False),
    Case("the Northwind invoice", AP, F, T, "transfer_funds", transfer(amount="18450.00"), False),
    Case("zero payment", AP, F, T, "transfer_funds", transfer(amount=0), False),
    Case("negative payment", AP, F, T, "transfer_funds", transfer(amount=-5), False),
    Case("exponent amount", AP, F, T, "transfer_funds", transfer(amount="1e3"), False),
    Case("boolean amount", AP, F, T, "transfer_funds", transfer(amount=True), False),
    Case("unknown vendor", AP, F, T, "transfer_funds", transfer(to_account="ACC-ATTACKER"), False),
    Case("to payroll", AP, F, T, "transfer_funds", transfer(to_account="ACC-PAYROLL"), False),
    Case("from payroll", AP, F, T, "transfer_funds", transfer(from_account="ACC-PAYROLL"), False),
    Case("extra argument", AP, F, T, "transfer_funds", {**transfer(), "fee_account": "X"}, False),
    Case("long memo", AP, F, T, "transfer_funds", transfer(memo="m" * 141), False),
    Case("unknown tool", AP, F, T, "close_account", {}, False),
    Case("case variant", AP, F, T, "Transfer_Funds", transfer(), False),
    Case("auditor reads", AUDITOR, F, T, "get_balance", OPS, True),
    Case("auditor pays", AUDITOR, F, T, "transfer_funds", transfer(), False),
    Case("auditor emails", AUDITOR, W, T, "send_email", email(), False),
    Case("intruder reads", INTRUDER, W, T, "read_doc", {"doc_id": "x"}, False),
    Case("anonymous reads", None, W, T, "read_doc", {"doc_id": "x"}, False),
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


def author_intends_to_allow(arguments: dict[str, Any]) -> bool:
    """The finance policy's transfer rule, restated from its comments, without the engine."""
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
