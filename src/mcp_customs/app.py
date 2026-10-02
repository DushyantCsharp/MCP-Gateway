"""The ASGI application: health endpoints plus one MCP endpoint per upstream."""

import logging
import socket
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

import anyio
import httpx2
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from mcp_customs import __version__
from mcp_customs.audit import AuditLog, AuditStore, Hasher, PostgresAuditStore
from mcp_customs.auth import JwtAuthenticator, SessionBinder
from mcp_customs.config import GatewayConfig
from mcp_customs.pipeline import Pipeline
from mcp_customs.pipeline.factory import build_pipeline
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.policy import RulePolicy
from mcp_customs.proxy.observe import Instruments
from mcp_customs.proxy.streamable_http import StreamableHttpProxy
from mcp_customs.telemetry import Telemetry

logger = logging.getLogger("mcp_customs")


def describe(config: GatewayConfig, pipeline: Pipeline, audit: AuditLog | None) -> list[tuple[int, str]]:
    """What this gateway enforces, as log lines. Gaps are warnings: running unprotected must be loud."""
    lines: list[tuple[int, str]] = [
        (
            logging.INFO,
            f"mcp-customs {__version__} serving {', '.join(f'/mcp/{n}' for n in config.upstreams)}",
        )
    ]
    if config.auth is None:
        lines.append((logging.WARNING, "auth: OFF - every caller is anonymous"))
    else:
        jwt = config.auth.jwt
        source = (
            f"JWKS {jwt.jwks_url}"
            if jwt.jwks_url
            else "public key"
            if jwt.public_key_file
            else "shared secret"
        )
        lines.append((logging.INFO, f"auth: JWT ({source}), audience {jwt.audience!r}"))
    if not pipeline:
        lines.append((logging.WARNING, "stages: NONE - calls are forwarded without any policy"))
    for stage in pipeline.stages:
        detail = ""
        if isinstance(stage, PolicyStage) and isinstance(stage.engine, RulePolicy):
            detail = f" ({len(stage.engine.document.rules)} rules)"
        lines.append((logging.INFO, f"stage: {stage.name}{detail}"))
    if audit is None:
        lines.append((logging.WARNING, "audit: OFF - calls are not recorded"))
    else:
        mode = (
            "durable: calls wait for their row" if config.audit and config.audit.durable else "asynchronous"
        )
        lines.append(
            (
                logging.INFO,
                f"audit: chain {audit.chain!r} ({audit.hasher.alg}) at seq {audit.head.seq}, {mode}",
            )
        )
    lines.append(
        (logging.INFO, f"telemetry: OTLP to {config.telemetry.otlp_endpoint or 'the OTEL_* endpoint'}")
        if config.telemetry
        else (logging.INFO, "telemetry: off")
    )
    return lines


def create_app(
    config: GatewayConfig,
    *,
    pipeline: Pipeline | None = None,
    http_client: httpx2.AsyncClient | None = None,
    telemetry: Telemetry | None = None,
    audit_store: AuditStore | None = None,
) -> FastAPI:
    """Build the gateway app.

    The pipeline is built from ``config.stages`` unless one is given (tests
    pass their own). Policy files are loaded here, so a broken one fails fast.
    ``http_client``, ``telemetry`` and ``audit_store`` are for tests; by
    default the app builds them from the configuration and owns their
    lifecycle. The audit chain is opened at start-up: if it cannot be, the
    gateway does not start.
    """
    stages = pipeline if pipeline is not None else build_pipeline(config.stages)
    sessions: SessionBinder | None = None
    if config.auth is not None:
        secret = config.auth.session_secret
        sessions = SessionBinder(secret.get_secret_value().encode() if secret is not None else None)
    if telemetry is None:
        telemetry = Telemetry.from_config(config.telemetry) if config.telemetry else Telemetry.disabled()
    stages.tracer = telemetry.tracer

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            stack.callback(telemetry.shutdown)
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
            audit: AuditLog | None = None
            if config.audit is not None:
                settings = config.audit
                store = audit_store or PostgresAuditStore(
                    settings.dsn.get_secret_value(), create_schema=settings.create_schema
                )
                key = settings.key.get_secret_value().encode() if settings.key else None
                audit = AuditLog(
                    store,
                    Hasher(key),
                    settings.chain or socket.gethostname(),
                    queue_size=settings.queue_size,
                    batch_size=settings.batch_size,
                    commit_timeout_s=settings.commit_timeout_s,
                )
                tasks = await stack.enter_async_context(anyio.create_task_group())
                await tasks.start(audit.run)
                stack.push_async_callback(audit.close)
            instruments = Instruments(
                telemetry.tracer,
                audit,
                durable=config.audit.durable if config.audit else False,
                record_arguments=config.audit.record_arguments if config.audit else False,
            )
            authenticator = JwtAuthenticator(config.auth.jwt, client) if config.auth is not None else None
            app.state.audit = audit
            app.state.proxy = StreamableHttpProxy(
                config,
                client,
                stages,
                authenticator=authenticator,
                sessions=sessions,
                instruments=instruments,
            )
            for level, line in describe(config, stages, audit):
                logger.log(level, line)
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
        """Liveness: the process is serving."""
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    async def readyz(request: Request) -> JSONResponse:
        """Readiness: everything a call depends on is up. Durable audit makes the log a dependency."""
        audit: AuditLog | None = request.app.state.audit
        if audit is not None and not audit.healthy:
            return JSONResponse({"status": "unavailable", "audit": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ok", "audit": "ok" if audit else "off"})

    @app.api_route("/mcp/{upstream}", methods=["GET", "POST", "DELETE"], include_in_schema=False)
    async def mcp_endpoint(upstream: str, request: Request) -> Response:
        proxy: StreamableHttpProxy = request.app.state.proxy
        return await proxy.handle(request, upstream)

    return app
