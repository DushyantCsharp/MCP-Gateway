from collections.abc import Iterator

import pytest

from tests.support.postgres import postgres_dsn
from tests.support.redis import redis_url


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    with postgres_dsn() as dsn:
        yield dsn


@pytest.fixture(scope="session")
def redis_server() -> Iterator[str]:
    with redis_url() as url:
        yield url
