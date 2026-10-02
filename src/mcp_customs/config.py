"""Gateway configuration: one YAML file, validated before anything starts.

String values may reference environment variables as ``${NAME}`` or
``${NAME:-default}``, so secrets such as upstream tokens stay out of the file.
Expansion runs on parsed values, never on raw YAML text, so an environment
variable cannot inject YAML structure.
"""

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Final

import yaml
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, ValidationError, field_validator

from mcp_customs.proxy.headers import HOP_BY_HOP

_ENV_REF: Final = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
UPSTREAM_NAME_PATTERN: Final = r"^[a-z0-9][a-z0-9_-]{0,62}$"


class ConfigError(ValueError):
    """The configuration file cannot be used."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class UpstreamConfig(_Model):
    url: AnyHttpUrl
    """The upstream MCP endpoint, for example ``http://workspace:8001/mcp``."""

    headers: dict[str, str] = Field(default_factory=dict)
    """Headers added to every request sent to this upstream, such as its own credentials."""

    connect_timeout_s: Annotated[float, Field(gt=0)] = 5.0
    read_timeout_s: Annotated[float, Field(gt=0)] = 300.0
    """Longest gap between bytes on a request's response. Server-initiated GET streams have none."""

    @field_validator("headers")
    @classmethod
    def _no_hop_by_hop(cls, headers: dict[str, str]) -> dict[str, str]:
        reserved = HOP_BY_HOP | {"host", "content-length"}
        if bad := sorted(name for name in headers if name.lower() in reserved):
            raise ValueError(f"cannot inject reserved header(s): {', '.join(bad)}")
        return headers


class ServerConfig(_Model):
    host: str = "127.0.0.1"
    port: Annotated[int, Field(ge=0, le=65535)] = 8000


class LimitsConfig(_Model):
    max_request_bytes: Annotated[int, Field(gt=0)] = 4 * 1024 * 1024
    max_response_bytes: Annotated[int, Field(gt=0)] = 16 * 1024 * 1024
    """Cap on a JSON response body, and on any single SSE event."""

    max_upstream_connections: Annotated[int, Field(gt=0)] = 512
    """Open GET streams each hold one, so this bounds concurrent legacy sessions too."""


class SecurityConfig(_Model):
    allowed_origins: list[str] = Field(default_factory=list)
    """Browser origins allowed to call the gateway. Requests with any other ``Origin`` are refused
    (DNS-rebinding protection); requests without an ``Origin``, as sent by non-browser agents, pass."""


class GatewayConfig(_Model):
    server: ServerConfig = ServerConfig()
    limits: LimitsConfig = LimitsConfig()
    security: SecurityConfig = SecurityConfig()
    upstreams: dict[Annotated[str, Field(pattern=UPSTREAM_NAME_PATTERN)], UpstreamConfig] = Field(
        min_length=1
    )
    """MCP servers behind the gateway; each is served at ``/mcp/<name>``."""


def expand_env(value: Any, environ: Mapping[str, str] | None = None) -> Any:
    """Replace ``${NAME}`` and ``${NAME:-default}`` in every string inside ``value``."""
    env = os.environ if environ is None else environ

    def substitute(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in env:
            return env[name]
        if default is not None:
            return default
        raise ConfigError(f"environment variable {name} is not set and has no default")

    if isinstance(value, str):
        return _ENV_REF.sub(substitute, value)
    if isinstance(value, list):
        return [expand_env(item, environ) for item in value]
    if isinstance(value, dict):
        return {key: expand_env(item, environ) for key, item in value.items()}
    return value


def parse_config(data: Any, environ: Mapping[str, str] | None = None) -> GatewayConfig:
    try:
        return GatewayConfig.model_validate(expand_env(data, environ))
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc


def load_config(path: Path, environ: Mapping[str, str] | None = None) -> GatewayConfig:
    try:
        data = yaml.safe_load(path.read_text())
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a mapping at the top level")
    return parse_config(data, environ)
