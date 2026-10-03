"""Local MCP servers behind the gateway: an upstream that is a command, not a URL.

Most MCP servers people run locally speak MCP over stdin and stdout and are
launched by the client. Configured with ``command``, an upstream is launched
by the gateway instead, one process per client session, and the rest of the
gateway reaches it through an HTTP transport mounted for its name. To the
proxy it is just another Streamable HTTP server, so policy, budgets,
approvals, redaction, injection checks and audit all apply unchanged.

The process speaks the handshake era: ``initialize`` starts a process and a
session, requests in that session go to its stdin, and what it writes back is
relayed as server-sent events. A client in ``auto`` mode probes
``server/discover`` first; that is answered "method not found", and the
client falls back to the handshake.

Routing what the process says: an answer goes to the request it answers. A
progress notification goes to the request that set its progress token.
Anything else (logs, list changes, the server's own requests) goes to the most
recent request still waiting, or to the session's GET stream when none is.

The process does not inherit the gateway's environment, which holds its
token secret, audit key and database credentials: only ``PATH``, ``HOME``,
the locale and temporary-directory variables, plus the upstream's ``env``.
"""

import contextlib
import json
import logging
import os
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import anyio
import httpx2
from anyio.abc import Process, TaskGroup
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp_customs.jsonrpc import (
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    SESSION_NOT_FOUND,
    UPSTREAM_UNAVAILABLE,
    dumps,
)
from mcp_customs.proxy.sse import encode_event

logger = logging.getLogger(__name__)

HOST_SUFFIX: Final = ".stdio.internal"
INHERITED_ENV: Final = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT")
"""The only gateway environment variables a local server sees (SYSTEMROOT: Windows needs it)."""


def internal_url(name: str) -> str:
    """Where the proxy sends a command upstream's traffic: a host only this gateway resolves."""
    return f"http://{name}{HOST_SUFFIX}/mcp"


def child_environment(extra: Mapping[str, str]) -> dict[str, str]:
    inherited = {name: os.environ[name] for name in INHERITED_ENV if name in os.environ}
    return {**inherited, **extra}


@dataclass(eq=False)
class _Session:
    id: str
    process: Process
    waiting: dict[Any, MemoryObjectSendStream[bytes]] = field(default_factory=dict)
    """Open requests: JSON-RPC id -> the stream their answer (and related messages) go to."""
    progress: dict[Any, Any] = field(default_factory=dict)
    """Progress token -> the id of the request that set it."""
    unsolicited: MemoryObjectSendStream[bytes] | None = None
    last_used: float = 0.0
    write_lock: anyio.Lock = field(default_factory=anyio.Lock)

    async def write(self, message: Any) -> None:
        if self.process.stdin is None:
            raise anyio.BrokenResourceError
        async with self.write_lock:
            await self.process.stdin.send(dumps(message) + b"\n")


def _event(message: Any) -> bytes:
    return encode_event(dumps(message).decode("utf-8"), event="message")


def _json_response(status: int, body: Any, headers: Mapping[str, str] | None = None) -> httpx2.Response:
    return httpx2.Response(
        status, headers={"content-type": "application/json", **(headers or {})}, content=dumps(body)
    )


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class _EventStream(httpx2.AsyncByteStream):
    """The body of a server-sent-event response, fed by the session's stdout reader."""

    def __init__(self, receive: MemoryObjectReceiveStream[bytes], on_close: Any = None) -> None:
        self._receive = receive
        self._on_close = on_close

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async with self._receive:
            async for chunk in self._receive:
                yield chunk

    async def aclose(self) -> None:
        await self._receive.aclose()
        if self._on_close is not None:
            self._on_close()


class StdioTransport(httpx2.AsyncBaseTransport):
    """Speaks Streamable HTTP to the proxy and MCP over stdio to one process per session."""

    def __init__(
        self,
        name: str,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        max_sessions: int = 32,
        idle_timeout_s: float = 1800.0,
        max_line_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        self.name = name
        self.command = list(command)
        self.env = child_environment(env or {})
        self.cwd = cwd
        self.max_sessions = max_sessions
        self.idle_timeout_s = idle_timeout_s
        self.max_line_bytes = max_line_bytes
        self._sessions: dict[str, _Session] = {}
        self._tasks: TaskGroup | None = None

    async def start(self, tasks: TaskGroup) -> None:
        self._tasks = tasks
        tasks.start_soon(self._reap_idle)

    async def aclose(self) -> None:
        for session in list(self._sessions.values()):
            await self._end(session)

    # -- requests from the proxy --------------------------------------------------------------------

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        session_id = request.headers.get("mcp-session-id")
        session = self._sessions.get(session_id) if session_id else None
        if session_id is not None and session is None:
            return _json_response(404, _error(None, SESSION_NOT_FOUND, "Session not found"))
        if session is not None:
            session.last_used = anyio.current_time()
        if request.method == "DELETE":
            if session is not None:
                await self._end(session)
            return httpx2.Response(200)
        if request.method == "GET":
            return self._listen(session) if session is not None else httpx2.Response(405)
        try:
            message = json.loads(await request.aread())
        except ValueError:
            return _json_response(400, _error(None, INVALID_REQUEST, "Invalid JSON"))
        if not isinstance(message, dict):
            return _json_response(400, _error(None, INVALID_REQUEST, "Expected one JSON-RPC message"))
        method, request_id = message.get("method"), message.get("id")
        if session is None:
            if method == "initialize":
                return await self._initialize(message)
            if method == "server/discover":  # a handshake-era server: the client falls back to initialize
                return _json_response(
                    200, _error(request_id, METHOD_NOT_FOUND, "Method not found: server/discover")
                )
            text = "This upstream is a local process that speaks the handshake era: initialize first"
            return _json_response(400, _error(request_id, INVALID_REQUEST, text))
        if method is not None and request_id is not None:
            return await self._request(session, message)
        await self._send_or_fail(session, message)
        return httpx2.Response(202)

    async def _initialize(self, message: dict[str, Any]) -> httpx2.Response:
        if len(self._sessions) >= self.max_sessions:
            return _json_response(
                503, _error(message.get("id"), UPSTREAM_UNAVAILABLE, "Too many local sessions")
            )
        try:
            process = await anyio.open_process(self.command, env=self.env, cwd=self.cwd)
        except OSError as exc:
            logger.error("cannot start local upstream %s: %s", self.name, exc)  # noqa: TRY400
            return _json_response(
                502, _error(message.get("id"), UPSTREAM_UNAVAILABLE, "Cannot start the local server")
            )
        session = _Session(uuid.uuid4().hex, process, last_used=anyio.current_time())
        self._sessions[session.id] = session
        if self._tasks is None:
            raise RuntimeError("the stdio transport is not started")
        self._tasks.start_soon(self._read, session)
        self._tasks.start_soon(self._drain_stderr, session)
        logger.info("started local upstream %s for session %s (pid %s)", self.name, session.id, process.pid)
        response = await self._request(session, message)
        response.headers["mcp-session-id"] = session.id
        return response

    async def _request(self, session: _Session, message: dict[str, Any]) -> httpx2.Response:
        send, receive = anyio.create_memory_object_stream[bytes](max_buffer_size=256)
        request_id = message["id"]
        session.waiting[request_id] = send
        token = ((message.get("params") or {}).get("_meta") or {}).get("progressToken")
        if token is not None:
            session.progress[token] = request_id

        def forget() -> None:
            session.waiting.pop(request_id, None)
            if token is not None:
                session.progress.pop(token, None)

        if not await self._send_or_fail(session, message):
            forget()
            send.close()
            return _json_response(
                200, _error(request_id, UPSTREAM_UNAVAILABLE, "The local server has exited")
            )
        return httpx2.Response(
            200, headers={"content-type": "text/event-stream"}, stream=_EventStream(receive, forget)
        )

    def _listen(self, session: _Session) -> httpx2.Response:
        if session.unsolicited is not None:
            return httpx2.Response(409)
        send, receive = anyio.create_memory_object_stream[bytes](max_buffer_size=256)
        session.unsolicited = send

        def forget() -> None:
            session.unsolicited = None

        return httpx2.Response(
            200, headers={"content-type": "text/event-stream"}, stream=_EventStream(receive, forget)
        )

    async def _send_or_fail(self, session: _Session, message: Any) -> bool:
        try:
            await session.write(message)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError, OSError):
            logger.warning("local upstream %s session %s is gone", self.name, session.id)
            await self._end(session)
            return False
        return True

    # -- what the process says ------------------------------------------------------------------------

    async def _read(self, session: _Session) -> None:
        stdout = session.process.stdout
        buffer = b""
        try:
            if stdout is not None:
                async for chunk in stdout:
                    buffer += chunk
                    if len(buffer) > self.max_line_bytes and b"\n" not in buffer:
                        logger.warning("local upstream %s wrote an over-long line; ending session", self.name)
                        break
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line.strip():
                            await self._route(session, line)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError, OSError):
            pass
        finally:
            await self._end(session)

    async def _route(self, session: _Session, line: bytes) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            logger.warning("local upstream %s wrote a line that is not JSON; dropped", self.name)
            return
        if not isinstance(message, dict):
            return
        answer = "method" not in message and ("result" in message or "error" in message)
        target: MemoryObjectSendStream[bytes] | None = None
        if answer:
            target = session.waiting.get(message.get("id"))
        elif message.get("method") == "notifications/progress":
            owner = session.progress.get((message.get("params") or {}).get("progressToken"))
            target = session.waiting.get(owner)
        if target is None and not answer:
            target = next(reversed(session.waiting.values()), None) or session.unsolicited
        if target is None:
            logger.debug("local upstream %s: no stream for a message; dropped", self.name)
            return
        with contextlib.suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
            await target.send(_event(message))
        if answer:
            session.waiting.pop(message.get("id"), None)
            target.close()

    async def _drain_stderr(self, session: _Session) -> None:
        stderr = session.process.stderr
        if stderr is None:
            return
        with contextlib.suppress(anyio.BrokenResourceError, anyio.ClosedResourceError, OSError):
            async for chunk in stderr:
                for line in chunk.decode("utf-8", "replace").splitlines():
                    logger.debug("local upstream %s: %s", self.name, line[:500])

    # -- ending -------------------------------------------------------------------------------------------

    async def _end(self, session: _Session) -> None:
        if self._sessions.pop(session.id, None) is None:
            return
        for request_id, stream in list(session.waiting.items()):
            with contextlib.suppress(anyio.BrokenResourceError, anyio.ClosedResourceError):
                await stream.send(
                    _event(_error(request_id, UPSTREAM_UNAVAILABLE, "The local server has exited"))
                )
            stream.close()
        session.waiting.clear()
        if session.unsolicited is not None:
            session.unsolicited.close()
        with anyio.CancelScope(shield=True):
            with contextlib.suppress(ProcessLookupError, OSError):
                if session.process.stdin is not None:
                    await session.process.stdin.aclose()
            with anyio.move_on_after(2):
                await session.process.wait()
            if session.process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    session.process.kill()
                with anyio.move_on_after(2):
                    await session.process.wait()
        logger.info("ended local upstream %s session %s", self.name, session.id)

    async def _reap_idle(self) -> None:
        while True:
            await anyio.sleep(min(60.0, self.idle_timeout_s))
            now = anyio.current_time()
            for session in list(self._sessions.values()):
                if now - session.last_used > self.idle_timeout_s and not session.waiting:
                    logger.info("local upstream %s session %s idle; ending it", self.name, session.id)
                    await self._end(session)
