"""Sample "finance" MCP server: balances, transactions and transfers.

``transfer_funds`` is the consequential call in the demo: the kind of tool a
policy should restrict and, later, route to a human for approval. Transfers
only move numbers in memory; ``GET /transfers`` exposes them to the benchmark.

Responses use plain JSON framing (``json_response=True``), so together with
the SSE-framed workspace server the gateway is exercised on both response
shapes. ``account_id`` on ``get_balance`` carries an ``x-mcp-header``
annotation, so modern clients mirror it into an ``Mcp-Param-Account`` header,
which the gateway must forward intact.
"""

from datetime import date
from decimal import Decimal
from typing import Annotated

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from customs_demo._serve import add_health_route, add_route, serve

CURRENCY = "USD"


class Balance(BaseModel):
    account_id: str
    available: Decimal
    currency: str = CURRENCY


class Transaction(BaseModel):
    id: str
    booked: date
    counterparty: str
    amount: Decimal
    memo: str


class TransferReceipt(BaseModel):
    transfer_id: str
    from_account: str
    to_account: str
    amount: Decimal
    memo: str
    status: str


def _seed_accounts() -> dict[str, Decimal]:
    return {
        "ACC-OPERATING": Decimal("250000.00"),
        "ACC-PAYROLL": Decimal("120000.00"),
        "ACC-NORTHWIND": Decimal("0.00"),
    }


def _seed_transactions() -> dict[str, list[Transaction]]:
    return {
        "ACC-OPERATING": [
            Transaction(
                id="txn-0003",
                booked=date(2026, 9, 28),
                counterparty="Cloud hosting",
                amount=Decimal("-4120.55"),
                memo="September invoice",
            ),
            Transaction(
                id="txn-0002",
                booked=date(2026, 9, 20),
                counterparty="Customer receipts",
                amount=Decimal("61200.00"),
                memo="Batch 2026-09-20",
            ),
            Transaction(
                id="txn-0001",
                booked=date(2026, 9, 1),
                counterparty="Northwind Logistics",
                amount=Decimal("-17980.00"),
                memo="INV-2026-077",
            ),
        ],
        "ACC-PAYROLL": [],
        "ACC-NORTHWIND": [],
    }


AccountId = Annotated[
    str,
    Field(
        description="Account identifier, for example ACC-OPERATING",
        json_schema_extra={"x-mcp-header": "Account"},
    ),
]


def build_server() -> MCPServer:
    balances = _seed_accounts()
    transactions = _seed_transactions()
    transfers: list[TransferReceipt] = []
    server = MCPServer(
        "finance",
        version="0.1.0",
        instructions="Company bank accounts. Check the payments policy before moving money.",
    )

    def require_account(account_id: str) -> None:
        if account_id not in balances:
            raise ToolError(f"Unknown account {account_id!r}")

    @server.tool()
    def get_balance(account_id: AccountId) -> Balance:
        """Get the available balance of one account."""
        require_account(account_id)
        return Balance(account_id=account_id, available=balances[account_id])

    @server.tool()
    def list_transactions(account_id: str, limit: int = 10) -> list[Transaction]:
        """List the most recent transactions on one account, newest first."""
        require_account(account_id)
        return transactions[account_id][: max(1, min(limit, 50))]

    @server.tool()
    def transfer_funds(from_account: str, to_account: str, amount: Decimal, memo: str) -> TransferReceipt:
        """Move money between two accounts. This is irreversible."""
        require_account(from_account)
        require_account(to_account)
        if amount <= 0:
            raise ToolError("Amount must be positive")
        if balances[from_account] < amount:
            raise ToolError("Insufficient funds")
        balances[from_account] -= amount
        balances[to_account] += amount
        receipt = TransferReceipt(
            transfer_id=f"trf-{len(transfers) + 1:04d}",
            from_account=from_account,
            to_account=to_account,
            amount=amount,
            memo=memo,
            status="settled",
        )
        transfers.append(receipt)
        return receipt

    async def get_transfers(_: Request) -> Response:
        return JSONResponse([receipt.model_dump(mode="json") for receipt in transfers])

    add_route(server, "/transfers", "GET", get_transfers)
    add_health_route(server)
    return server


def main() -> None:
    serve(build_server(), json_response=True, default_port=8002)


if __name__ == "__main__":
    main()
