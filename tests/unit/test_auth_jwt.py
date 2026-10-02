import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from mcp_customs.auth import AuthError, Grant, JwtAuthenticator, www_authenticate
from mcp_customs.auth.jwt import bearer_token
from mcp_customs.config import ConfigError, JwtConfig, parse_config

SECRET = "unit-test-secret-that-is-long-enough-for-hs256"
AUDIENCE = "mcp-customs"

pytestmark = pytest.mark.anyio


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {"sub": "ap-agent", "aud": AUDIENCE, "iat": now, "exp": now + 300}
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not None}


def hs256(**overrides: Any) -> str:
    return jwt.encode(claims(**overrides), SECRET, algorithm="HS256")


def secret_auth(**config: Any) -> JwtAuthenticator:
    return JwtAuthenticator(JwtConfig.model_validate({"audience": AUDIENCE, "secret": SECRET, **config}))


async def test_a_valid_token_yields_the_identity() -> None:
    token = hs256(roles=["auditor", "reader"], task="inv-091", scope="openid mcp:finance:get_*", iss="idp")
    identity = await secret_auth().authenticate(f"Bearer {token}")
    assert identity.agent == "ap-agent"
    assert identity.roles == {"auditor", "reader"}
    assert identity.task == "inv-091"
    assert identity.grants == (Grant("finance", "get_*"),)
    assert identity.issuer == "idp"


async def test_roles_may_be_a_space_separated_string() -> None:
    identity = await secret_auth().authenticate(f"Bearer {hs256(roles='a b')}")
    assert identity.roles == {"a", "b"}


async def test_claim_names_are_configurable() -> None:
    token = hs256(sub=None, client_id="bot-7", groups=["ops"])
    identity = await secret_auth(agent_claim="client_id", roles_claim="groups").authenticate(
        f"Bearer {token}"
    )
    assert (identity.agent, identity.roles) == ("bot-7", frozenset({"ops"}))


@pytest.mark.parametrize(
    ("header", "error"),
    [
        (None, None),
        ("Basic dXNlcjpwYXNz", "invalid_request"),
        ("Bearer", "invalid_request"),
        ("Bearer a b", "invalid_request"),
        ("Bearer " + "x" * 20_000, "invalid_request"),
        ("Bearer not-a-jwt", "invalid_token"),
    ],
)
async def test_malformed_credentials(header: str | None, error: str | None) -> None:
    with pytest.raises(AuthError) as caught:
        await secret_auth().authenticate(header)
    assert caught.value.error == error
    assert caught.value.status == 401


@pytest.mark.parametrize(
    ("token", "fragment"),
    [
        (lambda: hs256(exp=int(time.time()) - 120), "expired"),
        (lambda: hs256(nbf=int(time.time()) + 600), "Invalid token"),
        (lambda: hs256(aud="someone-else"), "Invalid token"),
        (lambda: hs256(aud=None), "Invalid token"),
        (lambda: hs256(exp=None), "Invalid token"),
        (lambda: hs256(sub=None), "Invalid token"),
        (lambda: hs256(sub="   "), "non-empty"),
        (lambda: hs256(roles={"a": 1}), "roles"),
        (lambda: hs256(task=7), "task"),
        (lambda: hs256(scope="mcp:finance"), "malformed scope"),
        (lambda: jwt.encode(claims(), "x" * 48, algorithm="HS256"), "Invalid token"),
        (lambda: jwt.encode(claims(), SECRET * 2, algorithm="HS512"), "Invalid token"),
        (lambda: jwt.encode(claims(), "", algorithm="none"), "Invalid token"),
    ],
    ids=[
        "expired",
        "not-yet-valid",
        "wrong-audience",
        "no-audience",
        "no-expiry",
        "no-subject",
        "blank-subject",
        "bad-roles",
        "bad-task",
        "bad-scope",
        "wrong-key",
        "unlisted-algorithm",
        "alg-none",
    ],
)
async def test_invalid_tokens_are_rejected(token: Any, fragment: str) -> None:
    with pytest.raises(AuthError, match=fragment):
        await secret_auth().authenticate(f"Bearer {token()}")


async def test_the_issuer_is_checked_when_configured() -> None:
    auth = secret_auth(issuer="https://idp.example")
    assert (await auth.authenticate(f"Bearer {hs256(iss='https://idp.example')}")).agent == "ap-agent"
    with pytest.raises(AuthError):
        await auth.authenticate(f"Bearer {hs256(iss='https://evil.example')}")


async def test_leeway_tolerates_small_clock_skew() -> None:
    token = hs256(exp=int(time.time()) - 5)
    assert (await secret_auth(leeway_s=30).authenticate(f"Bearer {token}")).agent == "ap-agent"
    with pytest.raises(AuthError):
        await secret_auth(leeway_s=0).authenticate(f"Bearer {token}")


def pem(public_key: Any) -> bytes:
    data: bytes = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return data


@pytest.mark.parametrize("kind", ["rsa", "ec"])
async def test_public_key_tokens(tmp_path: Path, kind: str) -> None:
    if kind == "rsa":
        private: Any = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        algorithm = "RS256"
    else:
        private = ec.generate_private_key(ec.SECP256R1())
        algorithm = "ES256"
    key_file = tmp_path / "issuer.pub"
    key_file.write_bytes(pem(private.public_key()))
    auth = JwtAuthenticator(JwtConfig(audience=AUDIENCE, public_key_file=key_file))
    token = jwt.encode(claims(), private, algorithm=algorithm)
    assert (await auth.authenticate(f"Bearer {token}")).agent == "ap-agent"


async def test_public_keys_cannot_be_used_as_hmac_secrets(tmp_path: Path) -> None:
    """The classic algorithm-confusion attack: an HS256 token keyed with the public key's PEM bytes."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = pem(private.public_key())
    key_file = tmp_path / "issuer.pub"
    key_file.write_bytes(public_pem)
    auth = JwtAuthenticator(JwtConfig(audience=AUDIENCE, public_key_file=key_file))
    with pytest.raises(AuthError):
        await auth.authenticate(f"Bearer {forge_hs256(public_pem)}")


def forge_hs256(key: bytes) -> str:
    """Sign by hand: PyJWT itself refuses to use a PEM key as an HMAC secret."""

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    signing_input = b64(b'{"alg":"HS256","typ":"JWT"}') + b"." + b64(json.dumps(claims()).encode())
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64(signature)).decode()


class FakeJwks:
    """A JWKS endpoint whose keys and availability tests can change."""

    def __init__(self) -> None:
        self.keys: list[dict[str, Any]] = []
        self.requests = 0
        self.up = True

    def add(self, kid: str) -> Any:
        private = ec.generate_private_key(ec.SECP256R1())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
        self.keys.append({**jwk, "kid": kid, "alg": "ES256", "use": "sig"})
        return private

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests += 1
        if not self.up:
            return httpx2.Response(503)
        return httpx2.Response(200, json={"keys": self.keys})


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def jwks_auth(fake: FakeJwks, clock: Clock, cache_s: float = 300) -> JwtAuthenticator:
    client = httpx2.AsyncClient(transport=httpx2.MockTransport(fake.handler))
    config = JwtConfig.model_validate(
        {"audience": AUDIENCE, "jwks_url": "https://idp.example/jwks", "jwks_cache_s": cache_s}
    )
    return JwtAuthenticator(config, client, clock=clock)


def es256(private: Any, kid: str) -> str:
    return "Bearer " + jwt.encode(claims(), private, algorithm="ES256", headers={"kid": kid})


async def test_jwks_keys_are_selected_by_kid_and_cached() -> None:
    fake = FakeJwks()
    first, second = fake.add("k1"), fake.add("k2")
    auth = jwks_auth(fake, Clock())
    for header in (es256(first, "k1"), es256(second, "k2"), es256(first, "k1")):
        assert (await auth.authenticate(header)).agent == "ap-agent"
    assert fake.requests == 1


async def test_rotated_keys_are_fetched_once_the_cooldown_has_passed() -> None:
    fake, clock = FakeJwks(), Clock()
    auth = jwks_auth(fake, clock)
    await auth.authenticate(es256(fake.add("old"), "old"))
    rotated = fake.add("new")

    with pytest.raises(AuthError, match="unknown key"):
        await auth.authenticate(es256(rotated, "new"))
    assert fake.requests == 1  # an unknown kid cannot force a fetch inside the cooldown

    clock.now += 31
    assert (await auth.authenticate(es256(rotated, "new"))).agent == "ap-agent"
    assert fake.requests == 2

    stranger = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(AuthError, match="unknown key"):
        await auth.authenticate(es256(stranger, "nobody"))
    assert fake.requests == 2


async def test_an_unreachable_jwks_is_a_503_until_keys_are_known() -> None:
    fake = FakeJwks()
    private = fake.add("k1")
    fake.up = False
    with pytest.raises(AuthError) as caught:
        await jwks_auth(fake, Clock()).authenticate(es256(private, "k1"))
    assert caught.value.status == 503


async def test_a_jwks_outage_keeps_serving_cached_keys() -> None:
    fake, clock = FakeJwks(), Clock()
    private = fake.add("k1")
    auth = jwks_auth(fake, clock, cache_s=1)
    await auth.authenticate(es256(private, "k1"))
    fake.up = False
    clock.now += 120
    assert (await auth.authenticate(es256(private, "k1"))).agent == "ap-agent"
    assert fake.requests == 2


async def test_a_token_without_kid_uses_the_only_key() -> None:
    fake = FakeJwks()
    private = fake.add("only")
    token = "Bearer " + jwt.encode(claims(), private, algorithm="ES256")
    assert (await jwks_auth(fake, Clock()).authenticate(token)).agent == "ap-agent"


@pytest.mark.parametrize(
    "jwt_config",
    [
        {"audience": AUDIENCE},
        {"audience": AUDIENCE, "secret": SECRET, "jwks_url": "https://idp.example/jwks"},
        {"audience": AUDIENCE, "secret": "too-short"},
        {"audience": AUDIENCE, "secret": SECRET, "algorithms": ["RS256"]},
        {"audience": AUDIENCE, "jwks_url": "https://idp.example/jwks", "algorithms": ["HS256"]},
        {"audience": "", "secret": SECRET},
    ],
    ids=["no-key", "two-keys", "short-secret", "rsa-with-secret", "hmac-with-jwks", "empty-audience"],
)
def test_invalid_jwt_configs_are_rejected(jwt_config: dict[str, Any]) -> None:
    with pytest.raises(ConfigError):
        parse_config({"auth": {"jwt": jwt_config}, "upstreams": {"w": {"url": "http://w/mcp"}}})


def test_bearer_token_parsing_is_case_insensitive_on_the_scheme() -> None:
    assert bearer_token("bearer abc") == "abc"
    assert bearer_token("  Bearer   abc  ") == "abc"


def test_challenges_follow_rfc_6750() -> None:
    assert www_authenticate(AuthError("missing", error=None)) == 'Bearer realm="mcp-customs"'
    challenge = www_authenticate(AuthError('bad "quote"'), resource_metadata_url="https://gw/.well-known/x")
    assert challenge == (
        'Bearer realm="mcp-customs", resource_metadata="https://gw/.well-known/x", '
        'error="invalid_token", error_description="bad \'quote\'"'
    )


def test_a_malformed_public_key_fails_at_start_up(tmp_path: Path) -> None:
    key_file = tmp_path / "issuer.pub"
    key_file.write_text("-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----\n")
    with pytest.raises(ValueError, match="PEM"):
        JwtAuthenticator(JwtConfig.model_validate({"audience": AUDIENCE, "public_key_file": key_file}))


async def test_a_key_that_does_not_fit_the_algorithm_is_a_401(tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_file = tmp_path / "issuer.pub"
    key_file.write_bytes(pem(rsa_key.public_key()))
    auth = JwtAuthenticator(JwtConfig.model_validate({"audience": AUDIENCE, "public_key_file": key_file}))
    token = jwt.encode(claims(), ec.generate_private_key(ec.SECP256R1()), algorithm="ES256")
    with pytest.raises(AuthError) as caught:
        await auth.authenticate(f"Bearer {token}")
    assert caught.value.status == 401


def test_challenge_descriptions_are_header_safe() -> None:
    challenge = www_authenticate(AuthError("line one\nline two\x00"))
    assert "\n" not in challenge
    assert "\x00" not in challenge
