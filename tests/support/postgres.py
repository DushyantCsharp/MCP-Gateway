"""A Postgres for tests: ``CUSTOMS_TEST_POSTGRES_DSN`` if set, else a throwaway container.

Without Docker the tests that need it are skipped, unless
``CUSTOMS_REQUIRE_POSTGRES`` is set (CI sets it), in which case they fail:
a skipped audit test in CI would look like a passing one.
"""

import os
from collections.abc import Iterator
from contextlib import contextmanager

import pytest


@contextmanager
def postgres_dsn() -> Iterator[str]:
    if dsn := os.environ.get("CUSTOMS_TEST_POSTGRES_DSN"):
        yield dsn
        return
    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        if os.environ.get("CUSTOMS_REQUIRE_POSTGRES"):
            raise
        pytest.skip(f"Postgres unavailable (set CUSTOMS_TEST_POSTGRES_DSN or start Docker): {exc}")
    container = PostgresContainer("postgres:17-alpine", driver=None)
    container.start()
    try:
        yield container.get_connection_url()
    finally:
        container.stop()
