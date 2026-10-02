"""The Postgres audit store: append-only, one writer per chain, tamper-evident end to end."""

import uuid

import psycopg
import pytest
from typer.testing import CliRunner

from mcp_customs.audit import AuditLog, AuditStoreError, Hasher, PostgresAuditStore
from mcp_customs.audit.verify import verify_database
from mcp_customs.cli import app as cli

pytestmark = [pytest.mark.anyio, pytest.mark.contract]


def chain_name() -> str:
    return f"test-{uuid.uuid4().hex[:12]}"


async def write(dsn: str, chain: str, events: list[dict[str, object]], key: bytes | None = None) -> None:
    import anyio

    log = AuditLog(PostgresAuditStore(dsn), Hasher(key), chain)
    async with anyio.create_task_group() as tg:
        await tg.start(log.run)
        for item in events:
            await log.record(item, durable=True)
        await log.close()


async def test_rows_round_trip_and_verify(pg_dsn: str) -> None:
    chain = chain_name()
    await write(pg_dsn, chain, [{"n": i, "text": "naïve 🚀"} for i in range(25)], key=b"k")
    (report,) = await verify_database(pg_dsn, Hasher(b"k"), chain)
    assert (report.ok, report.rows, report.head.seq) == (True, 25, 25)


async def test_a_restarted_writer_continues_the_chain(pg_dsn: str) -> None:
    chain = chain_name()
    await write(pg_dsn, chain, [{"run": 1}])
    await write(pg_dsn, chain, [{"run": 2}, {"run": 3}])
    (report,) = await verify_database(pg_dsn, Hasher(), chain)
    assert (report.ok, report.rows) == (True, 3)


async def test_one_writer_per_chain(pg_dsn: str) -> None:
    chain = chain_name()
    first = PostgresAuditStore(pg_dsn)
    await first.open(chain)
    try:
        with pytest.raises(AuditStoreError, match="in use by another gateway"):
            await PostgresAuditStore(pg_dsn).open(chain)
    finally:
        await first.close()
    second = PostgresAuditStore(pg_dsn)
    await second.open(chain)  # released when the first closed
    await second.close()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE customs_audit SET body = '{}' WHERE chain = %s",
        "DELETE FROM customs_audit WHERE chain = %s",
        "TRUNCATE customs_audit",
    ],
    ids=["update", "delete", "truncate"],
)
async def test_the_table_is_append_only(pg_dsn: str, statement: str) -> None:
    chain = chain_name()
    await write(pg_dsn, chain, [{"n": 1}])
    async with await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="append-only"):
            await conn.execute(statement, (chain,) if "%s" in statement else None)


async def test_tampering_by_someone_who_disables_the_triggers_is_detected(pg_dsn: str) -> None:
    chain = chain_name()
    await write(pg_dsn, chain, [{"amount": 500}, {"amount": 18450}, {"amount": 20}], key=b"k")
    async with await psycopg.AsyncConnection.connect(pg_dsn, autocommit=True) as conn:
        await conn.execute("ALTER TABLE customs_audit DISABLE TRIGGER customs_audit_no_rewrite")
        try:
            await conn.execute(
                "UPDATE customs_audit SET body = %s WHERE chain = %s AND seq = 2", ('{"amount":185}', chain)
            )
        finally:
            await conn.execute("ALTER TABLE customs_audit ENABLE TRIGGER customs_audit_no_rewrite")
    (report,) = await verify_database(pg_dsn, Hasher(b"k"), chain)
    assert report.problem == "row 2 has been altered"


def test_verify_audit_command(pg_dsn: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import anyio

    chain = chain_name()
    events: list[dict[str, object]] = [{"n": 1}, {"n": 2}]
    anyio.run(write, pg_dsn, chain, events, b"secret-key")
    monkeypatch.setenv("CUSTOMS_AUDIT_DSN", pg_dsn)
    monkeypatch.setenv("CUSTOMS_AUDIT_KEY", "secret-key")
    runner = CliRunner()
    ok = runner.invoke(cli, ["verify-audit", "--key-env", "CUSTOMS_AUDIT_KEY", "--chain", chain])
    assert ok.exit_code == 0, ok.output
    assert f"{chain}: 2 rows, head 2" in ok.output
    assert ok.output.rstrip().endswith("ok")
    without_key = runner.invoke(cli, ["verify-audit", "--chain", chain])
    assert without_key.exit_code == 1
    assert "pass the audit key" in without_key.output
    nothing = runner.invoke(cli, ["verify-audit", "--chain", "no-such-chain"])
    assert (nothing.exit_code, nothing.output.strip()) == (0, "no audit rows for chain 'no-such-chain'")
    monkeypatch.setenv("CUSTOMS_AUDIT_DSN", "postgresql://nobody:wrong@127.0.0.1:1/none")
    assert runner.invoke(cli, ["verify-audit"]).exit_code == 2
