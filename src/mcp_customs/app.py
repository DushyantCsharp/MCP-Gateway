"""The ASGI application: health endpoints, one MCP endpoint per upstream, and the approvals page."""

import logging
import os
import socket
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

import anyio
import httpx2
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from mcp_customs import __version__
from mcp_customs.approvals import ApprovalService, ApprovalStore, HeldCall, PostgresApprovalStore
from mcp_customs.approvals.web import ApprovalsWeb
from mcp_customs.approvals.web import router as approvals_router
from mcp_customs.audit import AuditLog, AuditStore, AuditUnavailableError, Hasher, PostgresAuditStore
from mcp_customs.audit.chain import sha256_of
from mcp_customs.audit.events import event
from mcp_customs.auth import JwtAuthenticator, SessionBinder
from mcp_customs.budgets import BudgetStage
from mcp_customs.config import ApprovalsConfig, GatewayConfig
from mcp_customs.pipeline import Pipeline
from mcp_customs.pipeline.factory import build_pipeline
from mcp_customs.pipeline.policy import PolicyStage
from mcp_customs.policy import RulePolicy
from mcp_customs.proxy.observe import Instruments
from mcp_customs.proxy.stdio import HOST_SUFFIX, StdioTransport
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
    for name, upstream in config.upstreams.items():
        if upstream.command is not None:
            command = " ".join(upstream.command)
            lines.append(
                (logging.INFO, f"upstream {name}: local command `{command}`, one process per session")
            )
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
        elif isinstance(stage, BudgetStage):
            shared = "shared in Redis" if stage.backend == "redis" else "in this process only"
            detail = f" ({len(stage.limits)} limits, counted {shared})"
        lines.append((logging.INFO, f"stage: {stage.name}{detail}"))
    if config.approvals is not None:
        settings = config.approvals
        lines.append(
            (
                logging.INFO,
                f"approvals: held calls in Postgres, decided at /approvals by role "
                f"{settings.approver_role!r}, expire after {settings.ttl_s:g}s",
            )
        )
        if config.auth is not None and config.auth.session_secret is None:
            lines.append(
                (
                    logging.WARNING,
                    "approvals: auth.session_secret is not set, so a restart forgets handshake-era "
                    "sessions and their held calls cannot resume",
                )
            )
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
    approval_store: ApprovalStore | None = None,
) -> FastAPI:
    """Build the gateway app.

    The pipeline is built from ``config.stages`` unless one is given (tests
    pass their own). Policy files are loaded here, so a broken one fails fast.
    ``http_client``, ``telemetry``, ``audit_store`` and ``approval_store`` are
    for tests; by default the app builds them from the configuration and owns
    their lifecycle. The audit chain, the approval store and every stage's
    dependencies are opened at start-up: if one cannot be, the gateway does
    not start.
    """
    stages = (
        pipeline
        if pipeline is not None
        else build_pipeline(config.stages, approvals=config.approvals is not None)
    )
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
            local = local_transports(config)
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
                        mounts={
                            f"http://{name}{HOST_SUFFIX}": transport for name, transport in local.items()
                        },
                    )
                )
            if local:
                processes = await stack.enter_async_context(anyio.create_task_group())
                stack.callback(processes.cancel_scope.cancel)
                for transport in local.values():
                    await transport.start(processes)
                    stack.push_async_callback(transport.aclose)
            tasks = await stack.enter_async_context(anyio.create_task_group())
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
                await tasks.start(audit.run)
                stack.push_async_callback(audit.close)
            for stage in stages.stages:
                await stage.start()
                stack.push_async_callback(stage.close)
            instruments = Instruments(
                telemetry.tracer,
                audit,
                durable=config.audit.durable if config.audit else False,
                record_arguments=config.audit.record_arguments if config.audit else False,
            )
            authenticator = JwtAuthenticator(config.auth.jwt, client) if config.auth is not None else None
            approvals: ApprovalService | None = None
            if config.approvals is not None and authenticator is not None:
                approvals = await _open_approvals(config, config.approvals, approval_store, audit, stack)
                # Approved calls and the expiry sweep run in their own group, entered after the
                # store opens so it closes after them. Shutdown cancels the sweep; approved calls
                # are shielded and finish (and store their answers) first.
                tasks = await stack.enter_async_context(anyio.create_task_group())
                stack.callback(tasks.cancel_scope.cancel)
                await tasks.start(approvals.run)
                secret = config.auth.session_secret if config.auth else None
                app.state.approvals_web = ApprovalsWeb(
                    approvals,
                    authenticator,
                    approver_role=config.approvals.approver_role,
                    csrf_key=secret.get_secret_value().encode() if secret is not None else os.urandom(32),
                    secure_cookies=config.approvals.secure_cookies,
                )
            app.state.audit = audit
            app.state.proxy = StreamableHttpProxy(
                config,
                client,
                stages,
                authenticator=authenticator,
                sessions=sessions,
                instruments=instruments,
                approvals=approvals,
                tasks=tasks,
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

    if config.approvals is not None:
        app.include_router(approvals_router())

    @app.api_route("/mcp/{upstream}", methods=["GET", "POST", "DELETE"], include_in_schema=False)
    async def mcp_endpoint(upstream: str, request: Request) -> Response:
        proxy: StreamableHttpProxy = request.app.state.proxy
        return await proxy.handle(request, upstream)

    return app


async def _open_approvals(
    config: GatewayConfig,
    settings: ApprovalsConfig,
    store: ApprovalStore | None,
    audit: AuditLog | None,
    stack: AsyncExitStack,
) -> ApprovalService:
    if store is None:
        store = PostgresApprovalStore(settings.dsn.get_secret_value(), create_schema=settings.create_schema)
    await store.open()
    stack.push_async_callback(store.close)

    async def record(call: HeldCall) -> None:
        """Every decision goes into the audit log, next to the requests it unblocks."""
        if audit is None:
            return
        body = event(
            "approval",
            call.upstream,
            held=call.id,
            decision=call.status.value,
            approver=call.decided_by,
            reason=call.decision_reason,
            agent=call.agent,
            method=call.method,
            target=call.target,
            arguments_sha256=sha256_of(call.arguments) if call.arguments is not None else None,
            rule=call.rule,
        )
        try:
            await audit.record(body, durable=False)
        except AuditUnavailableError:
            logger.error("audit log unavailable; decision on %s not recorded", call.id)  # noqa: TRY400

    longest_call = max(upstream.read_timeout_s for upstream in config.upstreams.values())
    return ApprovalService(
        store,
        ttl_s=settings.ttl_s,
        retry_ms=settings.retry_ms,
        stream_s=settings.stream_s,
        poll_s=settings.poll_s,
        max_pending_per_agent=settings.max_pending_per_agent,
        execution_timeout_s=longest_call + 30,
        retention_s=settings.retention_days * 86400,
        on_decision=record,
    )


def local_transports(config: GatewayConfig) -> dict[str, StdioTransport]:
    """One stdio transport per command upstream, mounted on the upstream HTTP client."""
    return {
        name: StdioTransport(
            name,
            upstream.command,
            env=upstream.env,
            cwd=upstream.cwd,
            max_sessions=upstream.max_sessions,
            max_line_bytes=config.limits.max_response_bytes,
        )
        for name, upstream in config.upstreams.items()
        if upstream.command is not None
    }
