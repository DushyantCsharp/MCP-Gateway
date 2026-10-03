"""Command line: run the gateway, check configuration and policy, mint development tokens."""

import asyncio
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import anyio
import httpx2
import jwt
import psycopg
import typer
import uvicorn

from mcp_customs import __version__
from mcp_customs.app import create_app
from mcp_customs.audit import AuditStoreError, Hasher
from mcp_customs.audit.verify import verify_database
from mcp_customs.auth import JwtAuthenticator
from mcp_customs.auth.identity import Identity, parse_grants
from mcp_customs.config import (
    BudgetStageConfig,
    ConfigError,
    GatewayConfig,
    InjectionStageConfig,
    PolicyStageConfig,
    RedactionStageConfig,
    load_config,
)
from mcp_customs.pipeline.factory import build_pipeline
from mcp_customs.policy import Effect, PolicyError, PolicyRequest, RulePolicy, TargetKind

app = typer.Typer(
    name="customs",
    help="mcp-customs: a security and governance gateway for MCP.",
    no_args_is_help=True,
    add_completion=False,
)

token_app = typer.Typer(help="Development tokens. Production tokens come from your identity provider.")
app.add_typer(token_app, name="token")
approvals_app = typer.Typer(help="Decide calls held for approval, through a running gateway's API.")
app.add_typer(approvals_app, name="approvals")

ConfigOption = Annotated[
    Path,
    typer.Option(
        "--config", "-c", envvar="CUSTOMS_CONFIG", dir_okay=False, help="Gateway YAML configuration."
    ),
]


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(code=2)


def _check_commands(config: GatewayConfig) -> None:
    for name, upstream in config.upstreams.items():
        if upstream.command is not None and shutil.which(upstream.command[0]) is None:
            raise ConfigError(f"upstream {name!r}: command {upstream.command[0]!r} not found")


def _load(path: Path) -> GatewayConfig:
    """Load the configuration and every file it refers to, such as policies."""
    try:
        config = load_config(path)
        _check_commands(config)
        build_pipeline(config.stages, approvals=config.approvals is not None)
        if config.auth is not None:
            JwtAuthenticator(config.auth.jwt, httpx2.AsyncClient())  # reads and checks key files
    except (ConfigError, PolicyError) as exc:
        raise _fail(str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise _fail(f"cannot load the token verification key: {exc}") from exc
    return config


@app.command()
def run(
    config: ConfigOption = Path("customs.yaml"),
    host: Annotated[str | None, typer.Option(help="Override server.host.")] = None,
    port: Annotated[int | None, typer.Option(help="Override server.port.")] = None,
    log_level: Annotated[str, typer.Option(help="debug, info, warning or error.")] = "info",
) -> None:
    """Run the gateway."""
    settings = _load(config)
    logging.basicConfig(level=log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # One line per upstream request duplicates uvicorn's access log; keep only their warnings.
    for noisy in ("httpx2", "httpcore2"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, logging.getLogger().level))
    uvicorn.run(
        create_app(settings),
        host=host or settings.server.host,
        port=settings.server.port if port is None else port,
        log_level=log_level.lower(),
        server_header=False,
        proxy_headers=False,
        timeout_graceful_shutdown=settings.server.shutdown_grace_s,
    )


@app.command("check-config")
def check_config(config: ConfigOption = Path("customs.yaml")) -> None:
    """Validate a configuration file and print what it would serve."""
    settings = _load(config)
    typer.echo(f"ok: {config}")
    for name, upstream in settings.upstreams.items():
        target = f"local command `{' '.join(upstream.command)}`" if upstream.command else str(upstream.url)
        typer.echo(f"  /mcp/{name} -> {target}")
    if settings.auth is None:
        typer.echo("  auth: none (every caller is anonymous)")
    else:
        jwt_config = settings.auth.jwt
        source = (
            "shared secret" if jwt_config.secret else "public key" if jwt_config.public_key_file else "JWKS"
        )
        typer.echo(f"  auth: JWT ({source}), audience {jwt_config.audience!r}")
    for stage in settings.stages:
        match stage:
            case PolicyStageConfig():
                detail = str(stage.file)
            case InjectionStageConfig():
                detail = f"{stage.detector}, {stage.mode}"
            case RedactionStageConfig():
                sides = f"requests {', '.join(stage.requests)}; responses {', '.join(stage.responses)}"
                detail = f"{stage.mode}; {sides}"
            case BudgetStageConfig():
                where = "Redis" if stage.redis is not None else "in-process counters"
                limits = ", ".join(f"{limit.id} {limit.limit}/{limit.per}" for limit in stage.limits)
                detail = f"{where}; {limits}"
        typer.echo(f"  stage: {stage.type} ({detail})")
    if settings.approvals is not None:
        typer.echo(
            f"  approvals: Postgres, approver role {settings.approvals.approver_role!r}, "
            f"expire after {settings.approvals.ttl_s:g}s"
        )
    if settings.audit is None:
        typer.echo("  audit: none (calls are not recorded)")
    else:
        keyed = "HMAC-SHA256" if settings.audit.key else "SHA-256, no key"
        typer.echo(f"  audit: Postgres, {keyed}, {'durable' if settings.audit.durable else 'asynchronous'}")
    if settings.telemetry is not None:
        typer.echo(f"  telemetry: OTLP to {settings.telemetry.otlp_endpoint or 'the OTEL_* endpoint'}")


@app.command("verify-audit")
def verify_audit(
    dsn_env: Annotated[
        str, typer.Option(help="Environment variable holding the Postgres DSN.")
    ] = "CUSTOMS_AUDIT_DSN",
    key_env: Annotated[
        str | None, typer.Option(help="Environment variable holding the chain's HMAC key, if it has one.")
    ] = None,
    chain: Annotated[str | None, typer.Option(help="Verify one chain only.")] = None,
) -> None:
    """Recompute every link of the audit log. Exit status: 0 intact, 1 broken, 2 on errors."""
    dsn = os.environ.get(dsn_env)
    if not dsn:
        raise _fail(f"set {dsn_env} to the audit database's connection string")
    key = os.environ.get(key_env) if key_env else None
    if key_env and not key:
        raise _fail(f"{key_env} is not set")
    try:
        reports = asyncio.run(verify_database(dsn, Hasher(key.encode() if key else None), chain))
    except (AuditStoreError, OSError) as exc:
        raise _fail(str(exc)) from exc
    except psycopg.Error as exc:  # unreachable database, missing table, bad credentials
        raise _fail(f"cannot read the audit log: {exc}") from exc
    if not reports:
        typer.echo("no audit rows" + (f" for chain {chain!r}" if chain else ""))
        return
    for report in reports:
        status = "ok" if report.ok else f"BROKEN: {report.problem}"
        typer.echo(
            f"{report.chain}: {report.rows} rows, head {report.head.seq} {report.head.hash[:16]}... {status}"
        )
    if not all(report.ok for report in reports):
        raise typer.Exit(code=1)


@app.command("check-policy")
def check_policy(
    policy: Annotated[Path, typer.Argument(dir_okay=False, help="Policy YAML file.")],
    upstream: Annotated[str | None, typer.Option(help="Upstream the call goes to.")] = None,
    tool: Annotated[str | None, typer.Option(help="Tool name.")] = None,
    prompt: Annotated[str | None, typer.Option(help="Prompt name.")] = None,
    resource: Annotated[str | None, typer.Option(help="Resource URI.")] = None,
    method: Annotated[str | None, typer.Option(help="Any other JSON-RPC method.")] = None,
    arguments: Annotated[str, typer.Option(help="Call arguments as a JSON object.")] = "{}",
    agent: Annotated[
        str | None, typer.Option(help="Caller's agent id; omit for an anonymous caller.")
    ] = None,
    role: Annotated[list[str] | None, typer.Option(help="Caller role; repeatable.")] = None,
    scope: Annotated[str | None, typer.Option(help="Token scope, e.g. 'mcp:finance:get_balance'.")] = None,
) -> None:
    """Validate a policy; with a call described, decide it.

    Exit status: 0 when the call is allowed (or the policy is valid), 1 when denied, 2 on errors,
    3 when it needs a human's approval.
    """
    try:
        engine = RulePolicy.load(policy)
    except PolicyError as exc:
        raise _fail(str(exc)) from exc
    targets = [
        (kind, name)
        for kind, name in (
            (TargetKind.TOOL, tool),
            (TargetKind.PROMPT, prompt),
            (TargetKind.RESOURCE, resource),
            (TargetKind.METHOD, method),
        )
        if name is not None
    ]
    if not targets:
        typer.echo(f"ok: {policy} ({len(engine.document.rules)} rules)")
        for rule in engine.document.rules:
            typer.echo(f"  {rule.effect:7} {rule.id}")
        return
    if len(targets) > 1 or upstream is None:
        raise _fail("describe one call: --upstream and exactly one of --tool, --prompt, --resource, --method")
    try:
        args: Any = json.loads(arguments)
        grants = parse_grants(scope.split()) if scope else None
    except ValueError as exc:
        raise _fail(str(exc)) from exc
    identity = Identity(agent, frozenset(role or ()), grants=grants) if agent is not None else None
    ((kind, name),) = targets
    decision = engine.decide(PolicyRequest(identity, upstream, kind, name, args))
    typer.echo(f"{decision.effect.value.upper()}: {decision.reason}")
    for detail in decision.details:
        typer.echo(f"  {detail}")
    match decision.effect:
        case Effect.DENY:
            raise typer.Exit(code=1)
        case Effect.APPROVE:
            raise typer.Exit(code=3)
        case Effect.ALLOW:
            pass


@token_app.command("issue")
def issue_token(
    agent: Annotated[str, typer.Option(help="Agent id (the 'sub' claim).")],
    audience: Annotated[str, typer.Option(help="Must match auth.jwt.audience.")] = "mcp-customs",
    role: Annotated[list[str] | None, typer.Option(help="Role; repeatable.")] = None,
    scope: Annotated[
        list[str] | None, typer.Option(help="Scope entry such as mcp:finance:get_*; repeatable.")
    ] = None,
    task: Annotated[str | None, typer.Option(help="Task label for audit.")] = None,
    issuer: Annotated[str | None, typer.Option(help="The 'iss' claim.")] = None,
    ttl: Annotated[int, typer.Option(help="Lifetime in seconds.", min=1)] = 3600,
    secret_env: Annotated[str, typer.Option(help="Environment variable holding the HS256 secret.")] = (
        "CUSTOMS_JWT_SECRET"  # noqa: S107 - the name of a variable, not a secret
    ),
    out: Annotated[Path | None, typer.Option(help="Write the token here instead of printing it.")] = None,
) -> None:
    """Mint an HS256 token signed with a shared secret, for development and demos."""
    secret = os.environ.get(secret_env)
    if not secret or len(secret.encode()) < 32:
        raise _fail(f"set {secret_env} to a secret of at least 32 bytes")
    now = int(time.time())
    claims: dict[str, Any] = {"sub": agent, "aud": audience, "iat": now, "exp": now + ttl}
    if role:
        claims["roles"] = role
    if scope:
        claims["scope"] = " ".join(scope)
    if task:
        claims["task"] = task
    if issuer:
        claims["iss"] = issuer
    token = jwt.encode(claims, secret, algorithm="HS256")
    if out is None:
        typer.echo(token)
    else:
        out.write_text(token)
        out.chmod(0o644)


GatewayUrl = Annotated[str, typer.Option("--url", envvar="CUSTOMS_URL", help="The gateway's base URL.")]
ApproverTokenFile = Annotated[
    Path | None,
    typer.Option(
        envvar="CUSTOMS_APPROVER_TOKEN_FILE",
        help="File holding an approver token; else $CUSTOMS_APPROVER_TOKEN.",
        dir_okay=False,
    ),
]


def _approvals_request(
    method: str, url: str, path: str, token_file: Path | None, body: dict[str, Any] | None = None
) -> Any:
    token = (
        token_file.read_text().strip() if token_file is not None else os.environ.get("CUSTOMS_APPROVER_TOKEN")
    )
    if not token:
        raise _fail("give an approver token with --token-file or $CUSTOMS_APPROVER_TOKEN")
    try:
        response = httpx2.request(
            method,
            f"{url.rstrip('/')}/approvals/api{path}",
            headers={"authorization": f"Bearer {token}"},
            json=body,
            timeout=30,
        )
    except httpx2.TransportError as exc:
        raise _fail(f"cannot reach {url}: {exc}") from exc
    if response.status_code >= 400:
        try:
            message = response.json().get("error", response.text)
        except ValueError:
            message = response.text
        raise _fail(f"{response.status_code}: {message}")
    return response.json()


def _show(call: dict[str, Any]) -> str:
    what = f"{call['target'] or call['method']} on {call['upstream']}"
    by = f", {call['status']} by {call['decided_by']}" if call.get("decided_by") else ""
    return f"{call['id']}  {call['status']:9} {what} for {call['agent']} ({call['reason']}){by}"


@approvals_app.command("list")
def approvals_list(
    url: GatewayUrl = "http://127.0.0.1:8000",
    token_file: ApproverTokenFile = None,
    status: Annotated[str, typer.Option(help="pending, all, or a comma-separated list.")] = "pending",
    as_json: Annotated[bool, typer.Option("--json", help="Print the calls as JSON.")] = False,
) -> None:
    """List held calls, oldest decisions last."""
    calls = _approvals_request("GET", url, f"/calls?status={status}", token_file)
    if as_json:
        typer.echo(json.dumps(calls, indent=2))
        return
    for call in calls:
        typer.echo(_show(call))
        typer.echo(f"    arguments: {json.dumps(call['arguments'], sort_keys=True)}")


def _decide_command(
    decision: str, held_id: str, url: str, token_file: Path | None, reason: str | None
) -> None:
    call = _approvals_request(
        "POST", url, f"/calls/{held_id}/decision", token_file, {"decision": decision, "reason": reason}
    )
    typer.echo(_show(call))


@approvals_app.command("approve")
def approvals_approve(
    held_id: Annotated[str, typer.Argument(help="The held call's id.")],
    url: GatewayUrl = "http://127.0.0.1:8000",
    token_file: ApproverTokenFile = None,
    reason: Annotated[str | None, typer.Option(help="Recorded, and shown to nobody but approvers.")] = None,
) -> None:
    """Approve a held call: it goes ahead when its agent next connects."""
    _decide_command("approve", held_id, url, token_file, reason)


@approvals_app.command("deny")
def approvals_deny(
    held_id: Annotated[str, typer.Argument(help="The held call's id.")],
    url: GatewayUrl = "http://127.0.0.1:8000",
    token_file: ApproverTokenFile = None,
    reason: Annotated[str | None, typer.Option(help="Shown to the agent.")] = None,
) -> None:
    """Deny a held call: the agent is told, with the reason."""
    _decide_command("deny", held_id, url, token_file, reason)


@app.command("stdio")
def stdio(
    url: Annotated[str, typer.Argument(help="The gateway endpoint, such as https://gateway/mcp/workspace.")],
    token_file: Annotated[
        Path | None,
        typer.Option(help="File holding the agent's bearer token; else $CUSTOMS_TOKEN.", dir_okay=False),
    ] = None,
) -> None:
    """Relay MCP between stdin/stdout and the gateway, for clients that only launch local servers.

    Point the client's server command at `customs stdio <url>`: every message it
    writes goes to the gateway over HTTP with the token, and every message back
    is written to stdout. Logs go to stderr, never stdout.
    """
    token = token_file.read_text().strip() if token_file is not None else os.environ.get("CUSTOMS_TOKEN")
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    anyio.run(_relay_stdio, url, token)


_relay_log = logging.getLogger("mcp_customs.stdio")


async def _relay_stdio(url: str, token: str | None) -> None:
    from mcp.client.streamable_http import streamable_http_client
    from mcp.server.stdio import stdio_server

    headers = {"authorization": f"Bearer {token}"} if token else {}
    async with (
        stdio_server() as (from_client, to_client),
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=None)) as http,
        streamable_http_client(url, http_client=http) as (from_gateway, to_gateway),
        anyio.create_task_group() as tasks,
    ):

        async def upward() -> None:
            async for message in from_client:
                if isinstance(message, Exception):
                    _relay_log.warning("unreadable message from the client: %s", message)
                    continue
                await to_gateway.send(message)
            tasks.cancel_scope.cancel()  # the client closed stdin: we are done

        async def downward() -> None:
            async for message in from_gateway:
                if isinstance(message, Exception):
                    _relay_log.warning("gateway transport error: %s", message)
                    continue
                await to_client.send(message)

        tasks.start_soon(upward)
        tasks.start_soon(downward)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
