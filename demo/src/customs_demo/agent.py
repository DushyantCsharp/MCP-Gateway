"""A scripted agent that completes one accounts-payable task over MCP.

The agent knows nothing about the gateway. It takes two server URLs, and
pointing them at the gateway instead of the servers is the only change needed
to put every call under the gateway's control.

The task: find the Northwind Logistics invoice, check that the operating
account can cover it, and email a payment summary to accounts payable.

This agent is deterministic on purpose, so the demo and the contract tests are
repeatable. The model-driven agent loop used for the attack benchmark comes
later.
"""

import argparse
import asyncio
import os
import re
import sys
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from mcp import Client
from mcp_types import CallToolResult, TextContent

AP_MAILBOX = "ap@acme.example"


class TaskFailedError(RuntimeError):
    """The agent could not complete its task."""


@dataclass
class TaskReport:
    invoice_id: str
    amount_due: Decimal
    available: Decimal
    email_message_id: str
    steps: list[str] = field(default_factory=list)


def _text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


def _structured(result: CallToolResult, step: str) -> Any:
    if result.is_error:
        raise TaskFailedError(f"{step} failed: {_text(result)}")
    if result.structured_content is None:
        raise TaskFailedError(f"{step} returned no structured content")
    return result.structured_content.get("result", result.structured_content)


async def run_task(workspace_url: str, finance_url: str, *, mode: str = "auto") -> TaskReport:
    steps: list[str] = []
    async with Client(workspace_url, mode=mode) as workspace, Client(finance_url, mode=mode) as finance:
        # Discover tools first, as a model-driven agent would. At 2026-07-28 the
        # client also learns from the listing which arguments to mirror into
        # Mcp-Param-* headers; servers refuse calls that omit them.
        offered = {tool.name for client in (workspace, finance) for tool in (await client.list_tools()).tools}
        needed = {"search_docs", "read_doc", "send_email", "get_balance"}
        if missing := needed - offered:
            raise TaskFailedError(f"tools not offered: {', '.join(sorted(missing))}")
        steps.append(f"list_tools -> {len(offered)} tools")

        hits = _structured(await workspace.call_tool("search_docs", {"query": "Northwind invoice"}), "search")
        invoice_hit = next((hit for hit in hits if hit["id"].startswith("inv-")), None)
        if invoice_hit is None:
            raise TaskFailedError("no invoice found in the document store")
        steps.append(f"search_docs -> {invoice_hit['id']}")

        read = await workspace.call_tool("read_doc", {"doc_id": invoice_hit["id"]})
        if read.is_error:
            raise TaskFailedError(f"read failed: {_text(read)}")
        invoice = _text(read)
        amount_match = re.search(r"Amount due:\s*([0-9]+\.[0-9]{2})", invoice)
        if amount_match is None:
            raise TaskFailedError("invoice has no amount due")
        amount_due = Decimal(amount_match.group(1))
        steps.append(f"read_doc -> amount due {amount_due}")

        balance = _structured(
            await finance.call_tool("get_balance", {"account_id": "ACC-OPERATING"}), "balance check"
        )
        available = Decimal(balance["available"])
        steps.append(f"get_balance -> {available} available")

        verdict = "can be paid" if available >= amount_due else "CANNOT be paid"
        email = _structured(
            await workspace.call_tool(
                "send_email",
                {
                    "to": AP_MAILBOX,
                    "subject": f"Payment summary: {invoice_hit['id']}",
                    "body": (
                        f"Invoice {invoice_hit['id']} for {amount_due} USD {verdict} "
                        f"from ACC-OPERATING ({available} USD available)."
                    ),
                },
            ),
            "email",
        )
        steps.append(f"send_email -> {email['message_id']}")

    return TaskReport(
        invoice_id=invoice_hit["id"],
        amount_due=amount_due,
        available=available,
        email_message_id=email["message_id"],
        steps=steps,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--workspace-url", default=os.environ.get("WORKSPACE_MCP_URL", "http://127.0.0.1:8001/mcp")
    )
    parser.add_argument(
        "--finance-url", default=os.environ.get("FINANCE_MCP_URL", "http://127.0.0.1:8002/mcp")
    )
    parser.add_argument(
        "--mode",
        default=os.environ.get("MCP_CONNECT_MODE", "auto"),
        help="'auto' negotiates the newest protocol; 'legacy' forces the initialize handshake",
    )
    args = parser.parse_args()
    print(f"workspace: {args.workspace_url}\nfinance:   {args.finance_url}\nmode:      {args.mode}")
    try:
        report = asyncio.run(run_task(args.workspace_url, args.finance_url, mode=args.mode))
    except TaskFailedError as exc:
        print(f"TASK FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    for step in report.steps:
        print(f"  {step}")
    print(f"TASK COMPLETE: summary for {report.invoice_id} sent as {report.email_message_id}")


if __name__ == "__main__":
    main()
