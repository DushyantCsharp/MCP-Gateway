"""Where audit rows live: Postgres in production, memory in tests.

The Postgres table is append-only at three levels. The gateway only ever
inserts; triggers refuse ``UPDATE``, ``DELETE`` and ``TRUNCATE``, even from the
table's owner, until someone drops them; and the primary key ``(chain, seq)``
makes a fork in a chain impossible to write. Each running gateway holds a
session advisory lock on its chain, so two gateways configured with the same
chain name fail fast instead of interleaving.
"""

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Final, Protocol, cast

import psycopg

from mcp_customs.audit.chain import Algorithm, AuditRow, ChainHead

TABLE: Final = "customs_audit"

SCHEMA: Final = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    chain     text   NOT NULL,
    seq       bigint NOT NULL CHECK (seq > 0),
    alg       text   NOT NULL,
    prev_hash text   NOT NULL,
    hash      text   NOT NULL,
    body      text   NOT NULL,
    event     jsonb  GENERATED ALWAYS AS (body::jsonb) STORED,
    PRIMARY KEY (chain, seq)
);

CREATE OR REPLACE FUNCTION {TABLE}_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '{TABLE} is append-only' USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE OR REPLACE TRIGGER {TABLE}_no_rewrite
    BEFORE UPDATE OR DELETE ON {TABLE} FOR EACH ROW EXECUTE FUNCTION {TABLE}_append_only();

CREATE OR REPLACE TRIGGER {TABLE}_no_truncate
    BEFORE TRUNCATE ON {TABLE} FOR EACH STATEMENT EXECUTE FUNCTION {TABLE}_append_only();
"""

_SCHEMA_LOCK: Final = 0x6D6370_637573  # any constant; serialises concurrent schema creation
_HEAD: Final = f"SELECT seq, hash FROM {TABLE} WHERE chain = %s ORDER BY seq DESC LIMIT 1"  # noqa: S608
_INSERT: Final = (
    f"INSERT INTO {TABLE} (chain, seq, alg, prev_hash, hash, body) VALUES (%s, %s, %s, %s, %s, %s)"  # noqa: S608
)


class AuditStoreError(RuntimeError):
    """The audit store cannot be used."""


class AuditStore(Protocol):
    async def open(self, chain: str) -> ChainHead:
        """Claim ``chain`` for this process and return its current head."""
        ...

    async def append(self, rows: Sequence[AuditRow]) -> None:
        """Write rows atomically: all of them or none."""
        ...

    async def close(self) -> None: ...


class MemoryAuditStore:
    """For tests. ``fail_appends`` makes the next appends raise, to exercise outages."""

    def __init__(self) -> None:
        self.rows: list[AuditRow] = []
        self.fail_appends = 0

    async def open(self, chain: str) -> ChainHead:
        mine = [row for row in self.rows if row.chain == chain]
        return ChainHead(mine[-1].seq, mine[-1].hash) if mine else ChainHead()

    async def append(self, rows: Sequence[AuditRow]) -> None:
        if self.fail_appends:
            self.fail_appends -= 1
            raise AuditStoreError("simulated outage")
        existing = {(row.chain, row.seq) for row in self.rows}
        if any((row.chain, row.seq) in existing for row in rows):
            raise AuditStoreError("duplicate (chain, seq)")
        self.rows.extend(rows)

    async def close(self) -> None:
        pass


class PostgresAuditStore:
    def __init__(self, dsn: str, *, create_schema: bool = True) -> None:
        self._dsn = dsn
        self._create_schema = create_schema
        self._conn: psycopg.AsyncConnection[tuple[object, ...]] | None = None

    async def open(self, chain: str) -> ChainHead:
        await self.close()
        try:
            conn = await psycopg.AsyncConnection.connect(self._dsn, autocommit=True)
        except psycopg.Error as exc:
            raise AuditStoreError(f"cannot connect to the audit database: {exc}") from exc
        try:
            head = await self._claim(conn, chain)
        except psycopg.Error as exc:
            await conn.close()
            raise AuditStoreError(f"cannot open audit chain {chain!r}: {exc}") from exc
        except BaseException:
            await conn.close()
            raise
        self._conn = conn
        return head

    async def _claim(self, conn: psycopg.AsyncConnection[tuple[object, ...]], chain: str) -> ChainHead:
        if self._create_schema:
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(%s)", (_SCHEMA_LOCK,))
                await conn.execute(SCHEMA)
        cursor = await conn.execute(
            "SELECT pg_try_advisory_lock(hashtextextended(%s, 0))", (f"{TABLE}/{chain}",)
        )
        locked = await cursor.fetchone()
        if not locked or not locked[0]:
            raise AuditStoreError(f"audit chain {chain!r} is in use by another gateway; give each its own")
        cursor = await conn.execute(_HEAD, (chain,))
        head = await cursor.fetchone()
        return ChainHead(cast(int, head[0]), cast(str, head[1])) if head else ChainHead()

    async def append(self, rows: Sequence[AuditRow]) -> None:
        if self._conn is None or self._conn.closed:
            raise AuditStoreError("audit store is not open")
        try:
            async with self._conn.transaction(), self._conn.cursor() as cur:
                await cur.executemany(
                    _INSERT, [(r.chain, r.seq, r.alg, r.prev_hash, r.hash, r.body) for r in rows]
                )
        except psycopg.Error as exc:
            raise AuditStoreError(f"audit write failed: {exc}") from exc

    async def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            await self._conn.close()  # also releases the chain's advisory lock
        self._conn = None


@asynccontextmanager
async def read_rows(dsn: str, chain: str | None = None) -> AsyncIterator[AsyncIterator[AuditRow]]:
    """Stream every row (or one chain's) in chain and sequence order, without loading them all."""
    async with (
        await psycopg.AsyncConnection.connect(dsn) as conn,
        conn.cursor(name="customs_audit_scan") as cur,
    ):
        where = "WHERE chain = %s" if chain is not None else ""
        await cur.execute(
            f"SELECT chain, seq, alg, prev_hash, hash, body FROM {TABLE} {where} ORDER BY chain, seq",  # noqa: S608
            (chain,) if chain is not None else None,
        )

        async def rows() -> AsyncIterator[AuditRow]:
            async for chain_name, seq, alg, prev_hash, digest, body in cur:
                yield AuditRow(
                    cast(str, chain_name),
                    cast(int, seq),
                    cast(Algorithm, alg),
                    cast(str, prev_hash),
                    cast(str, digest),
                    cast(str, body),
                )

        yield rows()
