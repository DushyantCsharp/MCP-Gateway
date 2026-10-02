"""Bearer-token authentication: every MCP request carries a JWT issued for the gateway.

Verification is strict: the signature, an expiry, the audience and (when
configured) the issuer must all check out, and only the configured algorithms
are accepted, so a token cannot choose a weaker one or ``none``. Keys come
from a shared secret, a PEM public key, or the issuer's JWKS, which is cached
and refetched when an unknown key id appears, at most once per cooldown.
"""

import logging
import time
from collections.abc import Callable, Mapping
from typing import Any, Final

import anyio
import httpx2
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from mcp_customs.auth.identity import Identity, parse_grants
from mcp_customs.config import JwtConfig

logger = logging.getLogger(__name__)

_JWKS_REFRESH_COOLDOWN_S: Final = 30.0
_MAX_TOKEN_BYTES: Final = 16 * 1024


class AuthError(Exception):
    """Why a request could not be authenticated, in RFC 6750 terms.

    ``error`` is ``None`` when no credentials were sent, as RFC 6750 asks, and
    ``invalid_request`` for a malformed header.
    """

    def __init__(self, description: str, *, error: str | None = "invalid_token", status: int = 401) -> None:
        super().__init__(description)
        self.description = description
        self.error = error
        self.status = status


def bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise AuthError("Bearer token required", error=None)
    scheme, _, token = authorization.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        raise AuthError("Authorization header must be 'Bearer <token>'", error="invalid_request")
    if len(token) > _MAX_TOKEN_BYTES:
        raise AuthError("Bearer token too large", error="invalid_request")
    return token


def _string_list(value: Any, claim: str) -> list[str]:
    """A claim holding a list of strings, or one space-separated string."""
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise AuthError(f"Claim {claim!r} must be a string or a list of strings")


class _Jwks:
    """The issuer's key set, cached for ``ttl_s`` and refetched for unknown key ids."""

    def __init__(self, url: str, ttl_s: float, http: httpx2.AsyncClient, clock: Callable[[], float]) -> None:
        self._url = url
        self._ttl_s = ttl_s
        self._http = http
        self._clock = clock
        self._keys: jwt.PyJWKSet | None = None
        self._fetched_at = float("-inf")
        self._lock = anyio.Lock()

    async def key(self, kid: str | None) -> jwt.PyJWK:
        now = self._clock()
        if self._keys is None or now - self._fetched_at > self._ttl_s:
            await self._refresh(now)
        found = self._find(kid)
        if found is None and now - self._fetched_at > _JWKS_REFRESH_COOLDOWN_S:
            await self._refresh(now)  # the issuer may have rotated keys
            found = self._find(kid)
        if found is None:
            raise AuthError("Token signed with an unknown key")
        return found

    def _find(self, kid: str | None) -> jwt.PyJWK | None:
        if self._keys is None:
            return None
        keys = self._keys.keys
        if kid is None:
            return keys[0] if len(keys) == 1 else None
        return next((key for key in keys if key.key_id == kid), None)

    async def _refresh(self, now: float) -> None:
        async with self._lock:
            if self._keys is not None and self._fetched_at >= now:
                return  # another request refreshed while this one waited
            try:
                response = await self._http.get(self._url, timeout=5.0)
                response.raise_for_status()
                self._keys = jwt.PyJWKSet.from_dict(response.json())
                self._fetched_at = self._clock()
            except (httpx2.HTTPError, ValueError, jwt.PyJWKSetError) as exc:
                logger.warning("cannot fetch JWKS from %s: %s", self._url, exc)
                if self._keys is None:
                    raise AuthError("Token signing keys are unavailable", status=503) from exc


class JwtAuthenticator:
    def __init__(
        self,
        config: JwtConfig,
        http: httpx2.AsyncClient | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._algorithms = config.effective_algorithms
        self._static_key: str | bytes | None = None
        self._jwks: _Jwks | None = None
        if config.secret is not None:
            self._static_key = config.secret.get_secret_value()
        elif config.public_key_file is not None:
            pem = config.public_key_file.read_bytes()
            load_pem_public_key(pem)  # fail at start-up, not on the first request
            self._static_key = pem
        elif config.jwks_url is not None:
            if http is None:
                raise ValueError("an HTTP client is required to fetch a JWKS")
            self._jwks = _Jwks(str(config.jwks_url), config.jwks_cache_s, http, clock)

    async def authenticate(self, authorization: str | None) -> Identity:
        token = bearer_token(authorization)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise AuthError("Malformed token") from exc
        key: Any = self._static_key
        if self._jwks is not None:
            kid = header.get("kid")
            key = (await self._jwks.key(kid if isinstance(kid, str) else None)).key
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=self._algorithms,
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.leeway_s,
                options={"require": ["exp", self._config.agent_claim]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("Token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError(f"Invalid token: {exc}") from exc
        except (jwt.PyJWTError, ValueError, TypeError) as exc:
            # A key the token's algorithm cannot use, such as an RSA key for ES256.
            raise AuthError("Invalid token: signing key and algorithm do not match") from exc
        return self._identity(claims)

    def _identity(self, claims: Mapping[str, Any]) -> Identity:
        config = self._config
        agent = claims.get(config.agent_claim)
        if not isinstance(agent, str) or not agent.strip():
            raise AuthError(f"Claim {config.agent_claim!r} must be a non-empty string")
        task = claims.get(config.task_claim)
        if task is not None and not isinstance(task, str):
            raise AuthError(f"Claim {config.task_claim!r} must be a string")
        try:
            grants = parse_grants(_string_list(claims.get(config.scope_claim), config.scope_claim))
        except ValueError as exc:
            raise AuthError(str(exc)) from exc
        issuer = claims.get("iss")
        return Identity(
            agent=agent,
            roles=frozenset(_string_list(claims.get(config.roles_claim), config.roles_claim)),
            task=task,
            grants=grants,
            issuer=issuer if isinstance(issuer, str) else None,
        )


def www_authenticate(error: AuthError, *, resource_metadata_url: str | None = None) -> str:
    """The ``WWW-Authenticate`` challenge for a 401 (RFC 6750 section 3, RFC 9728 section 5.1)."""
    params = ['realm="mcp-customs"']
    if resource_metadata_url is not None:
        params.append(f'resource_metadata="{resource_metadata_url}"')
    if error.error is not None:
        printable = "".join(char for char in error.description if char.isprintable())
        description = printable.replace("\\", "").replace('"', "'")
        params.extend([f'error="{error.error}"', f'error_description="{description}"'])
    return "Bearer " + ", ".join(params)
