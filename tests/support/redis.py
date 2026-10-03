"""A Redis for tests: ``CUSTOMS_TEST_REDIS_URL`` if set, else a throwaway container.

Without Docker the tests that need it are skipped, unless
``CUSTOMS_REQUIRE_REDIS`` is set (CI sets it), in which case they fail.
"""

import os
from collections.abc import Iterator
from contextlib import contextmanager

import pytest


@contextmanager
def redis_url() -> Iterator[str]:
    if url := os.environ.get("CUSTOMS_TEST_REDIS_URL"):
        yield url
        return
    import docker
    from testcontainers.community.redis import RedisContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        if os.environ.get("CUSTOMS_REQUIRE_REDIS"):
            raise
        pytest.skip(f"Redis unavailable (set CUSTOMS_TEST_REDIS_URL or start Docker): {exc}")
    container = RedisContainer("redis:7-alpine")
    container.start()
    try:
        yield f"redis://{container.get_container_host_ip()}:{container.get_exposed_port(6379)}/0"
    finally:
        container.stop()
