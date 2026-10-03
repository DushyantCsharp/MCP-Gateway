"""Clients for contract tests: SDK clients with a bearer token, and raw JSON-RPC over HTTP."""

import json
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import jwt
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types.version import LATEST_HANDSHAKE_VERSION, LATEST_MODERN_VERSION

from mcp_customs.auth import Identity
from mcp_customs.proxy.sse import SseParser

TEST_SECRET = "contract-test-secret-for-hs256-tokens-0123456789"
TEST_AUDIENCE = "mcp-customs"
ACCEPT = "application/json, text/event-stream"


def mint(
    agent: str,
    *,
    roles: tuple[str, ...] = (),
    scope: str | None = None,
    ttl: int = 300,
    secret: str = TEST_SECRET,
    audience: str = TEST_AUDIENCE,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {"sub": agent, "aud": audience, "iat": now, "exp": now + ttl}
    if roles:
        claims["roles"] = list(roles)
    if scope:
        claims["scope"] = scope
    return jwt.encode(claims, secret, algorithm="HS256")


def token_for(identity: Identity | None) -> str | None:
    return None if identity is None else mint(identity.agent, roles=tuple(sorted(identity.roles)))


@asynccontextmanager
async def mcp_client(url: str, *, token: str | None, mode: str = "auto") -> AsyncIterator[Client]:
    """An SDK client whose every request carries ``Authorization: Bearer <token>``."""
    headers = {"authorization": f"Bearer {token}"} if token else {}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0, read=300.0)) as http,
        Client(streamable_http_client(url, http_client=http), mode=mode) as client,
    ):
        yield client


def answer_of(response: httpx2.Response) -> Any:
    """The JSON-RPC answer in a response, whether framed as JSON or as SSE."""
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        parser = SseParser()
        messages = [
            json.loads(e.data) for e in parser.feed(response.content) if e.data
        ]  # skip priming events
        answers = [m for m in messages if "result" in m or "error" in m]
        return answers[-1] if answers else None
    return response.json() if response.content else None


class RawSession:
    """Speaks JSON-RPC to one endpoint directly, in either protocol era, with optional auth."""

    def __init__(self, http: httpx2.AsyncClient, url: str, token: str | None, *, modern: bool) -> None:
        self.http, self.url, self.token, self.modern = http, url, token, modern
        self.session_id: str | None = None

    def _headers(self, method: str | None = None, name: str | None = None) -> dict[str, str]:
        headers = {"accept": ACCEPT, "content-type": "application/json"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        if self.modern:
            headers["mcp-protocol-version"] = LATEST_MODERN_VERSION
            if method:
                headers["mcp-method"] = method
            if name:
                headers["mcp-name"] = name
        elif self.session_id:
            headers["mcp-session-id"] = self.session_id
            headers["mcp-protocol-version"] = LATEST_HANDSHAKE_VERSION
        return headers

    async def open(self) -> httpx2.Response | None:
        """Handshake era: initialize and confirm. Returns the initialize response."""
        if self.modern:
            return None
        init = {
            "jsonrpc": "2.0",
            "id": "init",
            "method": "initialize",
            "params": {
                "protocolVersion": LATEST_HANDSHAKE_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "raw", "version": "0"},
            },
        }
        response = await self.http.post(self.url, json=init, headers=self._headers())
        self.session_id = response.headers.get("mcp-session-id")
        if self.session_id:
            note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            await self.http.post(self.url, json=note, headers=self._headers())
        return response

    async def request(
        self, method: str, params: dict[str, Any], *, extra_headers: dict[str, str] | None = None
    ) -> tuple[str, httpx2.Response]:
        request_id = f"req-{uuid.uuid4().hex}"
        if self.modern:
            params = {
                **params,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": LATEST_MODERN_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            }
        name = params.get("name") if method in ("tools/call", "prompts/get") else params.get("uri")
        headers = {**self._headers(method, name if isinstance(name, str) else None), **(extra_headers or {})}
        body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        return request_id, await self.http.post(self.url, json=body, headers=headers)
