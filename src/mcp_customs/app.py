"""The ASGI application: health endpoints plus one MCP endpoint per upstream."""

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

import httpx2
from fastapi import FastAPI, Request, Response

from mcp_customs import __version__
from mcp_customs.auth import JwtAuthenticator, SessionBinder
from mcp_customs.config import GatewayConfig
from mcp_customs.pipeline import Pipeline
from mcp_customs.pipeline.factory import build_pipeline
from mcp_customs.proxy.streamable_http import StreamableHttpProxy


def create_app(
    config: GatewayConfig,
    *,
    pipeline: Pipeline | None = None,
    http_client: httpx2.AsyncClient | None = None,
) -> FastAPI:
    """Build the gateway app.

    The pipeline is built from ``config.stages`` unless one is given (tests
    pass their own). Policy files are loaded here, so a broken one fails fast.
    ``http_client`` is for tests; by default the app owns a pooled client for
    talking to upstreams (and the token issuer's JWKS), opened and closed with
    the app's lifespan.
    """
    stages = pipeline if pipeline is not None else build_pipeline(config.stages)
    sessions: SessionBinder | None = None
    if config.auth is not None:
        secret = config.auth.session_secret
        sessions = SessionBinder(secret.get_secret_value().encode() if secret is not None else None)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            client = http_client
            if client is None:
                max_connections = config.limits.max_upstream_connections
                client = await stack.enter_async_context(
                    httpx2.AsyncClient(
                        limits=httpx2.Limits(
                            max_connections=max_connections,
                            max_keepalive_connections=min(64, max_connections),
                        ),
                        follow_redirects=False,
                    )
                )
            authenticator = JwtAuthenticator(config.auth.jwt, client) if config.auth is not None else None
            app.state.proxy = StreamableHttpProxy(
                config, client, stages, authenticator=authenticator, sessions=sessions
            )
            yield

    app = FastAPI(
        title="mcp-customs",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.api_route("/mcp/{upstream}", methods=["GET", "POST", "DELETE"], include_in_schema=False)
    async def mcp_endpoint(upstream: str, request: Request) -> Response:
        proxy: StreamableHttpProxy = request.app.state.proxy
        return await proxy.handle(request, upstream)

    return app
