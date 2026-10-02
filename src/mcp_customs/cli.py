"""Command line: run the gateway, check configuration and policy, mint development tokens."""

import json
import logging
import os
import time
from pathlib import Path
from typing import Annotated, Any

import httpx2
import jwt
import typer
import uvicorn

from mcp_customs import __version__
from mcp_customs.app import create_app
from mcp_customs.auth import JwtAuthenticator
from mcp_customs.auth.identity import Identity, parse_grants
from mcp_customs.config import ConfigError, GatewayConfig, load_config
from mcp_customs.pipeline.factory import build_pipeline
from mcp_customs.policy import PolicyError, PolicyRequest, RulePolicy, TargetKind

app = typer.Typer(
    name="customs",
    help="mcp-customs: a security and governance gateway for MCP.",
    no_args_is_help=True,
    add_completion=False,
)

token_app = typer.Typer(help="Development tokens. Production tokens come from your identity provider.")
app.add_typer(token_app, name="token")

ConfigOption = Annotated[
    Path,
    typer.Option(
        "--config", "-c", envvar="CUSTOMS_CONFIG", dir_okay=False, help="Gateway YAML configuration."
    ),
]


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(code=2)


def _load(path: Path) -> GatewayConfig:
    """Load the configuration and every file it refers to, such as policies."""
    try:
        config = load_config(path)
        build_pipeline(config.stages)
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
    )


@app.command("check-config")
def check_config(config: ConfigOption = Path("customs.yaml")) -> None:
    """Validate a configuration file and print what it would serve."""
    settings = _load(config)
    typer.echo(f"ok: {config}")
    for name, upstream in settings.upstreams.items():
        typer.echo(f"  /mcp/{name} -> {upstream.url}")
    if settings.auth is None:
        typer.echo("  auth: none (every caller is anonymous)")
    else:
        jwt_config = settings.auth.jwt
        source = (
            "shared secret" if jwt_config.secret else "public key" if jwt_config.public_key_file else "JWKS"
        )
        typer.echo(f"  auth: JWT ({source}), audience {jwt_config.audience!r}")
    for stage in settings.stages:
        typer.echo(f"  stage: {stage.type} ({stage.file})")


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

    Exit status: 0 when the call is allowed (or the policy is valid), 1 when denied, 2 on errors.
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
            typer.echo(f"  {rule.effect:5} {rule.id}")
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
    typer.echo(f"{'ALLOW' if decision.allowed else 'DENY'}: {decision.reason}")
    for detail in decision.details:
        typer.echo(f"  {detail}")
    if not decision.allowed:
        raise typer.Exit(code=1)


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


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)
