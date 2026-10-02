"""A scripted agent that does accounts-payable work over MCP.

The agent knows nothing about the gateway. It takes two server URLs and,
optionally, a bearer token. Pointing the URLs at the gateway and handing it a
token is the only change needed to put every call under the gateway's control.

Two tasks:

* ``summary``: find the Northwind Logistics invoice, check the operating
  account can cover it, and email a payment summary to accounts payable.
* ``pay-invoice``: find the same invoice and pay it. The invoice is over the
  single-approver limit in the demo policy, so behind the gateway this call
  is blocked, and the agent reports that instead of paying.

The agent is deterministic on purpose, so the demo and the contract tests are
repeatable. The model-driven agent loop used for the attack benchmark comes
later.
"""

import argparse
import asyncio
import os
import re
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

import httpx2
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp_types import CallToolResult, TextContent

AP_MAILBOX = "ap@acme.example"
POLICY_BLOCK_PREFIX = "Blocked by gateway policy"
EXIT_BLOCKED = 3

type Task = Literal["summary", "pay-invoice"]


class TaskFailedError(RuntimeError):
    """The agent could not complete its task."""


class TaskBlockedError(TaskFailedError):
    """A step was refused by the gateway's policy."""


@dataclass
class TaskReport:
    invoice_id: str
    amount_due: Decimal
    available: Decimal
    email_message_id: str | None = None
    transfer_id: str | None = None
    steps: list[str] = field(default_factory=list)


@asynccontextmanager
async def connect(url: str, *, mode: str, token: str | None) -> AsyncIterator[Client]:
    """An MCP client for ``url``, sending ``Authorization: Bearer <token>`` when one is given."""
    if token is None:
        async with Client(url, mode=mode) as client:
            yield client
        return
    headers = {"authorization": f"Bearer {token}"}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=300.0)) as http,
        Client(streamable_http_client(url, http_client=http), mode=mode) as client,
    ):
        yield client


def _text(result: CallToolResult) -> str:
    return "\n".join(block.text for block in result.content if isinstance(block, TextContent))


def _structured(result: CallToolResult, step: str) -> Any:
    if result.is_error:
        text = _text(result)
        error = TaskBlockedError if text.startswith(POLICY_BLOCK_PREFIX) else TaskFailedError
        raise error(f"{step}: {text}")
    if result.structured_content is None:
        raise TaskFailedError(f"{step} returned no structured content")
    return result.structured_content.get("result", result.structured_content)


def _task_error(error: BaseException) -> TaskFailedError | None:
    """A task failure or a refusal from the server, found inside the SDK's exception groups."""
    while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
        error = error.exceptions[0]
    if isinstance(error, TaskFailedError):
        return error
    if isinstance(error, MCPError):
        return TaskFailedError(f"the server refused: {error.message}")
    return None


async def run_task(
    workspace_url: str,
    finance_url: str,
    *,
    mode: str = "auto",
    token: str | None = None,
    task: Task = "summary",
) -> TaskReport:
    try:
        return await _run_task(workspace_url, finance_url, mode=mode, token=token, task=task)
    except (BaseExceptionGroup, MCPError) as caught:
        if (error := _task_error(caught)) is None:
            raise
        raise error from caught


async def _run_task(
    workspace_url: str, finance_url: str, *, mode: str, token: str | None, task: Task
) -> TaskReport:
    steps: list[str] = []
    async with (
        connect(workspace_url, mode=mode, token=token) as workspace,
        connect(finance_url, mode=mode, token=token) as finance,
    ):
        # Discover tools first, as a model-driven agent would. At 2026-07-28 the
        # client also learns from the listing which arguments to mirror into
        # Mcp-Param-* headers; servers refuse calls that omit them.
        offered = {tool.name for client in (workspace, finance) for tool in (await client.list_tools()).tools}
        needed = {"search_docs", "read_doc", "get_balance"} | (
            {"send_email"} if task == "summary" else {"transfer_funds"}
        )
        if missing := needed - offered:
            raise TaskFailedError(f"tools not offered: {', '.join(sorted(missing))}")
        steps.append(f"list_tools -> {len(offered)} tools")

        hits = _structured(await workspace.call_tool("search_docs", {"query": "Northwind invoice"}), "search")
        invoice_hit = next((hit for hit in hits if hit["id"].startswith("inv-")), None)
        if invoice_hit is None:
            raise TaskFailedError("no invoice found in the document store")
        invoice_id: str = invoice_hit["id"]
        steps.append(f"search_docs -> {invoice_id}")

        read = await workspace.call_tool("read_doc", {"doc_id": invoice_id})
        if read.is_error:
            raise TaskFailedError(f"read failed: {_text(read)}")
        amount_match = re.search(r"Amount due:\s*([0-9]+\.[0-9]{2})", _text(read))
        if amount_match is None:
            raise TaskFailedError("invoice has no amount due")
        amount_due = Decimal(amount_match.group(1))
        steps.append(f"read_doc -> amount due {amount_due}")

        balance = _structured(
            await finance.call_tool("get_balance", {"account_id": "ACC-OPERATING"}), "balance check"
        )
        available = Decimal(balance["available"])
        steps.append(f"get_balance -> {available} available")
        report = TaskReport(invoice_id, amount_due, available, steps=steps)

        if task == "pay-invoice":
            arguments = {
                "from_account": "ACC-OPERATING",
                "to_account": "ACC-NORTHWIND",
                "amount": str(amount_due),
                "memo": invoice_id,
            }
            receipt = _structured(await finance.call_tool("transfer_funds", arguments), "transfer_funds")
            report.transfer_id = receipt["transfer_id"]
            steps.append(f"transfer_funds -> {report.transfer_id}")
            return report

        verdict = "can be paid" if available >= amount_due else "CANNOT be paid"
        email = _structured(
            await workspace.call_tool(
                "send_email",
                {
                    "to": AP_MAILBOX,
                    "subject": f"Payment summary: {invoice_id}",
                    "body": (
                        f"Invoice {invoice_id} for {amount_due} USD {verdict} "
                        f"from ACC-OPERATING ({available} USD available)."
                    ),
                },
            ),
            "email",
        )
        report.email_message_id = email["message_id"]
        steps.append(f"send_email -> {report.email_message_id}")
    return report


def _token(args: argparse.Namespace) -> str | None:
    if args.token:
        return str(args.token)
    if path := os.environ.get("MCP_BEARER_TOKEN_FILE"):
        return Path(path).read_text().strip()
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--workspace-url", default=os.environ.get("WORKSPACE_MCP_URL", "http://127.0.0.1:8001/mcp")
    )
    parser.add_argument(
        "--finance-url", default=os.environ.get("FINANCE_MCP_URL", "http://127.0.0.1:8002/mcp")
    )
    parser.add_argument(
        "--task", choices=["summary", "pay-invoice"], default=os.environ.get("AGENT_TASK", "summary")
    )
    parser.add_argument(
        "--mode",
        default=os.environ.get("MCP_CONNECT_MODE", "auto"),
        help="'auto' negotiates the newest protocol; 'legacy' forces the initialize handshake",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("MCP_BEARER_TOKEN"),
        help="Bearer token; or set MCP_BEARER_TOKEN, or MCP_BEARER_TOKEN_FILE to a file holding one",
    )
    args = parser.parse_args()
    token = _token(args)
    print(f"workspace: {args.workspace_url}\nfinance:   {args.finance_url}")
    print(f"task:      {args.task}\nmode:      {args.mode}\ntoken:     {'yes' if token else 'none'}")
    try:
        report = asyncio.run(
            run_task(args.workspace_url, args.finance_url, mode=args.mode, token=token, task=args.task)
        )
    except TaskBlockedError as exc:
        print(f"TASK BLOCKED: {exc}")
        raise SystemExit(EXIT_BLOCKED) from exc
    except TaskFailedError as exc:
        print(f"TASK FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    for step in report.steps:
        print(f"  {step}")
    outcome = (
        f"paid as {report.transfer_id}"
        if report.transfer_id
        else f"summary sent as {report.email_message_id}"
    )
    print(f"TASK COMPLETE: {report.invoice_id} {outcome}")


if __name__ == "__main__":
    main()
