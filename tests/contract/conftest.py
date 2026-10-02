"""Real servers on real sockets: two sample MCP servers, a rogue upstream and gateways in front."""

import socket
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import pytest

from customs_demo import finance_server, workspace_server
from customs_demo._serve import http_app
from mcp_customs.app import create_app
from mcp_customs.config import GatewayConfig, parse_config
from mcp_customs.pipeline import Pipeline, Stage
from tests.support.rogue import rogue_app
from tests.support.servers import serve_in_thread

ALLOWED_ORIGIN = "http://allowed.example"
INJECTED_TOKEN = "token-from-gateway-config"


@dataclass(frozen=True)
class Gateway:
    base: str

    def url(self, upstream: str) -> str:
        return f"{self.base}/mcp/{upstream}"


@pytest.fixture(scope="session")
def workspace_url() -> Iterator[str]:
    with serve_in_thread(http_app(workspace_server.build_server(), json_response=False)) as base:
        yield f"{base}/mcp"


@pytest.fixture(scope="session")
def finance_url() -> Iterator[str]:
    with serve_in_thread(http_app(finance_server.build_server(), json_response=True)) as base:
        yield f"{base}/mcp"


@pytest.fixture(scope="session")
def rogue_url() -> Iterator[str]:
    with serve_in_thread(rogue_app()) as base:
        yield f"{base}/mcp"


@pytest.fixture(scope="session")
def dead_url() -> str:
    """A port nothing listens on."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}/mcp"


@pytest.fixture(scope="session")
def direct_urls(workspace_url: str, finance_url: str) -> dict[str, str]:
    return {"workspace": workspace_url, "finance": finance_url}


def make_config(upstreams: Mapping[str, str | dict[str, Any]], **sections: Any) -> GatewayConfig:
    entries = {name: spec if isinstance(spec, dict) else {"url": spec} for name, spec in upstreams.items()}
    return parse_config({"upstreams": entries, **sections})


@contextmanager
def running_gateway(
    config: GatewayConfig, stages: list[Stage] | None = None, **app_options: Any
) -> Iterator[Gateway]:
    """Serve a gateway. ``stages`` replaces the pipeline; without it, ``config.stages`` builds one.

    ``app_options`` go to :func:`create_app` (``telemetry``, ``audit_store``).
    """
    pipeline = Pipeline(stages) if stages is not None else None
    with serve_in_thread(create_app(config, pipeline=pipeline, **app_options)) as base:
        yield Gateway(base)


@pytest.fixture(scope="session")
def gateway(workspace_url: str, finance_url: str, rogue_url: str, dead_url: str) -> Iterator[Gateway]:
    """A pass-through gateway (no stages) in front of every test upstream."""
    config = make_config(
        {
            "workspace": workspace_url,
            "finance": finance_url,
            "rogue": {"url": rogue_url, "headers": {"X-Upstream-Token": INJECTED_TOKEN}},
            "dead": dead_url,
        },
        security={"allowed_origins": [ALLOWED_ORIGIN]},
    )
    with running_gateway(config) as gw:
        yield gw


@pytest.fixture(params=["auto", "legacy"])
def mode(request: pytest.FixtureRequest) -> str:
    """``auto`` negotiates the stateless 2026-07-28 revision; ``legacy`` forces the initialize handshake."""
    value: str = request.param
    return value
