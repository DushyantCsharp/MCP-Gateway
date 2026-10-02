"""``customs verify-audit``: recompute every link of every chain."""

from collections.abc import AsyncIterator
from itertools import groupby

from mcp_customs.audit.chain import AuditRow, ChainReport, Hasher, verify_chain
from mcp_customs.audit.store import read_rows


async def _chains(rows: AsyncIterator[AuditRow]) -> AsyncIterator[tuple[str, list[AuditRow]]]:
    """Group a chain-ordered stream by chain. Each chain is held in memory while it is checked."""
    collected = [row async for row in rows]
    for chain, group in groupby(collected, key=lambda row: row.chain):
        yield chain, list(group)


async def verify_database(dsn: str, hasher: Hasher, chain: str | None = None) -> list[ChainReport]:
    reports: list[ChainReport] = []
    async with read_rows(dsn, chain) as rows:
        async for name, chain_rows in _chains(rows):
            reports.append(verify_chain(name, chain_rows, hasher))
    return reports
