"""Command line: ``customs run``, ``customs check-config`` and ``customs version``."""

import logging
from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from mcp_customs import __version__
from mcp_customs.app import create_app
from mcp_customs.config import ConfigError, GatewayConfig, load_config

app = typer.Typer(
    name="customs",
    help="mcp-customs: a security and governance gateway for MCP.",
    no_args_is_help=True,
    add_completion=False,
)

ConfigOption = Annotated[
    Path,
    typer.Option(
        "--config", "-c", envvar="CUSTOMS_CONFIG", dir_okay=False, help="Gateway YAML configuration."
    ),
]


def _load(path: Path) -> GatewayConfig:
    try:
        return load_config(path)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


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


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(__version__)
