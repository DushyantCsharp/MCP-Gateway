"""Gateway configuration: one YAML file, validated before anything starts.

String values may reference environment variables as ``${NAME}`` or
``${NAME:-default}``, so secrets such as upstream tokens stay out of the file.
Expansion runs on parsed values, never on raw YAML text, so an environment
variable cannot inject YAML structure.

Relative file paths (policy files, public keys) resolve against the directory
of the configuration file, not the working directory.
"""

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Self

import yaml
from pydantic import (
    AfterValidator,
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)

from mcp_customs.proxy.headers import HOP_BY_HOP

_ENV_REF: Final = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
UPSTREAM_NAME_PATTERN: Final = r"^[a-z0-9][a-z0-9_-]{0,62}$"


class ConfigError(ValueError):
    """The configuration file cannot be used."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _resolve_path(value: Path, info: ValidationInfo) -> Path:
    base = (info.context or {}).get("base_dir")
    return value if value.is_absolute() or base is None else Path(base) / value


type ConfigPath = Annotated[Path, AfterValidator(_resolve_path)]


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


_HMAC_ALGORITHMS: Final = frozenset({"HS256", "HS384", "HS512"})
_ASYMMETRIC_ALGORITHMS: Final = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
_MIN_HMAC_SECRET_BYTES: Final = 32


class JwtConfig(_Model):
    """How bearer tokens are verified. Exactly one key source must be set."""

    audience: str = Field(min_length=1)
    """Required: a token must be issued for the gateway, never passed through from elsewhere."""
    issuer: str | None = None
    algorithms: list[str] | None = None
    """Defaults to HS256 for ``secret`` and RS256/ES256 for public keys."""

    secret: SecretStr | None = None
    """Shared HMAC secret, at least 32 bytes. For development and the demo."""
    public_key_file: ConfigPath | None = None
    """PEM public key of the token issuer."""
    jwks_url: AnyHttpUrl | None = None
    """The issuer's JSON Web Key Set, fetched and cached."""
    jwks_cache_s: Annotated[float, Field(gt=0)] = 300.0

    leeway_s: Annotated[float, Field(ge=0, le=300)] = 30.0
    agent_claim: str = "sub"
    roles_claim: str = "roles"
    task_claim: str = "task"
    scope_claim: str = "scope"

    @model_validator(mode="after")
    def _check_keys(self) -> Self:
        sources = [self.secret, self.public_key_file, self.jwks_url]
        if sum(source is not None for source in sources) != 1:
            raise ValueError("set exactly one of secret, public_key_file or jwks_url")
        allowed = _HMAC_ALGORITHMS if self.secret is not None else _ASYMMETRIC_ALGORITHMS
        if bad := sorted(set(self.effective_algorithms) - allowed):
            kind = "a shared secret" if self.secret is not None else "a public key"
            raise ValueError(f"algorithm(s) {', '.join(bad)} cannot be used with {kind}")
        if self.secret is not None and len(self.secret.get_secret_value().encode()) < _MIN_HMAC_SECRET_BYTES:
            raise ValueError(f"secret must be at least {_MIN_HMAC_SECRET_BYTES} bytes")
        return self

    @property
    def effective_algorithms(self) -> list[str]:
        if self.algorithms:
            return self.algorithms
        return ["HS256"] if self.secret is not None else ["RS256", "ES256"]


class AuthConfig(_Model):
    jwt: JwtConfig
    session_secret: SecretStr | None = None
    """Key that binds handshake-era session ids to the agent that opened them. Set it when the
    gateway runs as more than one replica or must keep sessions across restarts; otherwise a
    random key is generated at start-up."""
    resource_metadata_url: AnyHttpUrl | None = None
    """Advertised in ``WWW-Authenticate`` so OAuth-capable clients can find the authorization server."""


class PolicyStageConfig(_Model):
    type: Literal["policy"]
    file: ConfigPath


class InjectionStageConfig(_Model):
    """Inspect tool results for prompt injection before the agent reads them."""

    type: Literal["injection"]
    detector: Literal["classifier", "hidden", "layered"] = "layered"
    """``hidden``: the cheap checks for text a reader cannot see; ``classifier``: ProtectAI's DeBERTa
    prompt-injection model on ONNX Runtime (``[classifier]`` extra); ``layered``: both, cheap first."""
    mode: Literal["block", "flag", "strip"] = "block"
    threshold: Annotated[float, Field(ge=0, le=1)] = 0.5
    threads: Annotated[int, Field(ge=1, le=64)] = 2
    """Detector threads; scoring is CPU-bound and runs off the event loop."""
    max_chars: Annotated[int, Field(ge=1000)] | None = 16_000
    """The classifier reads at most this many characters of one text (the first and last halves); the
    cheap checks always read all of it. Bounds the cost of very long results. ``null`` reads everything."""


class RedactionStageConfig(_Model):
    """Keep secrets and personal data from crossing the gateway."""

    type: Literal["redaction"]
    mode: Literal["redact", "flag", "block"] = "redact"
    requests: list[str] = Field(default_factory=lambda: ["secrets"])
    """Kinds scrubbed from tool and prompt arguments: ``secrets``, ``pii`` or individual kinds."""
    responses: list[str] = Field(default_factory=lambda: ["secrets", "pii"])
    """Kinds scrubbed from what tools, resources and prompts return."""
    allow: list[str] = Field(default_factory=list)
    """Regular expressions for values never redacted, such as internal addresses (``.*@acme\\.example``)."""

    @field_validator("requests", "responses")
    @classmethod
    def _known_kinds(cls, names: list[str]) -> list[str]:
        from mcp_customs.detectors.sensitive import expand

        expand(names)
        return names

    @field_validator("allow")
    @classmethod
    def _compiles(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid allow pattern {pattern!r}: {exc}") from exc
        return patterns


type StageConfig = Annotated[
    PolicyStageConfig | InjectionStageConfig | RedactionStageConfig, Field(discriminator="type")
]


class AuditConfig(_Model):
    """The hash-chained audit log in Postgres."""

    dsn: SecretStr
    """Postgres connection string, e.g. ``postgresql://customs:...@postgres:5432/customs``."""
    chain: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")] | None = None
    """This gateway's chain. Each running gateway needs its own; defaults to the host name."""
    key: SecretStr | None = None
    """HMAC key for the chain. Without it the chain uses plain SHA-256, which detects edits by anyone
    who does not recompute every later hash; with it, rewriting history also needs the key."""
    durable: bool = True
    """Wait for a call's audit row to commit before forwarding the call. If the log cannot be written,
    calls are refused rather than run unaudited. ``False`` trades that guarantee for latency."""
    record_arguments: bool = False
    """Store call arguments in the log. Off by default: they may hold personal data or secrets, and
    a SHA-256 digest of them is always recorded."""
    queue_size: Annotated[int, Field(gt=0)] = 10_000
    batch_size: Annotated[int, Field(gt=0, le=10_000)] = 500
    commit_timeout_s: Annotated[float, Field(gt=0)] = 5.0
    """How long a durable call waits for its row before the gateway refuses it."""
    create_schema: bool = True
    """Create the table, index and append-only triggers at start-up if they are missing."""


class TelemetryConfig(_Model):
    """OpenTelemetry tracing, exported over OTLP/HTTP (Jaeger, Tempo, an OTel Collector...)."""

    otlp_endpoint: AnyHttpUrl | None = None
    """Base URL such as ``http://jaeger:4318``; omitted, the standard ``OTEL_EXPORTER_OTLP_*``
    environment variables apply."""
    service_name: str = "mcp-customs"
    sample_ratio: Annotated[float, Field(ge=0, le=1)] = 1.0


class GatewayConfig(_Model):
    server: ServerConfig = ServerConfig()
    limits: LimitsConfig = LimitsConfig()
    security: SecurityConfig = SecurityConfig()
    auth: AuthConfig | None = None
    """Without it every caller is anonymous; with it every MCP request needs a valid bearer token."""
    stages: list[StageConfig] = Field(default_factory=list)
    """Pipeline stages, run in this order on every message."""
    audit: AuditConfig | None = None
    telemetry: TelemetryConfig | None = None
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


def parse_config(
    data: Any, environ: Mapping[str, str] | None = None, *, base_dir: Path | None = None
) -> GatewayConfig:
    try:
        return GatewayConfig.model_validate(expand_env(data, environ), context={"base_dir": base_dir})
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
    return parse_config(data, environ, base_dir=path.parent)
