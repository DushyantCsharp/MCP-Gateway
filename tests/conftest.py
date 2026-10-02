from collections.abc import Iterator

import pytest

from tests.support.postgres import postgres_dsn


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    with postgres_dsn() as dsn:
        yield dsn
