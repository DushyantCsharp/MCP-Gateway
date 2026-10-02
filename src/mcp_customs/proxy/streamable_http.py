"""The gateway's request path: a JSON-RPC-aware Streamable HTTP reverse proxy.

Every upstream is served at ``/mcp/<name>``. The proxy speaks both eras of
the transport without terminating either:

* handshake-era revisions (2024-11-05 to 2025-11-25): ``initialize``,
  ``Mcp-Session-Id``, a server-initiated GET stream and DELETE to end it;
* the stateless revision (2026-07-28): one self-contained POST per request,
  with routing headers and no session.

Request and response bodies are forwarded byte for byte unless a pipeline
stage changes them. What the proxy does insist on:

* every client body is exactly one strictly valid JSON-RPC message;
* routing headers agree with the body;
* every upstream message it relays is strictly valid JSON-RPC, and answers on
  a POST answer that POST's request;
* a failing upstream or stage is reported to the client as a JSON-RPC error,
  so a caller is never left waiting on a request that went nowhere;
* a request the audit log cannot record (when it is durable) is refused,
  not forwarded.

Every exchange is observed (:mod:`mcp_customs.proxy.observe`): it gets a
server span, and audit events for what was asked, decided and answered.
"""

import logging
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from typing import Final

import anyio
import httpx2
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

from mcp_customs.audit import AuditUnavailableError
from mcp_customs.auth import AuthError, Identity, JwtAuthenticator, SessionBinder, www_authenticate
from mcp_customs.config import GatewayConfig, UpstreamConfig
from mcp_customs.jsonrpc import (
    AUDIT_UNAVAILABLE,
    HEADER_MISMATCH,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    SESSION_NOT_FOUND,
    UNAUTHENTICATED,
    UPSTREAM_BAD_RESPONSE,
    UPSTREAM_TIMEOUT,
    UPSTREAM_UNAVAILABLE,
    JSONObject,
    JsonRpcError,
    Message,
    MessageKind,
    RequestId,
    classify,
    dumps,
    error_object,
    loads_strict,
    parse_message,
)
from mcp_customs.pipeline.base import (
    Annotations,
    ClientMessageContext,
    Exchange,
    InvalidReplacementError,
    Pipeline,
    Replace,
    Respond,
    ServerMessageContext,
    StageFailedError,
)
from mcp_customs.proxy.headers import client_response_headers, upstream_request_headers
from mcp_customs.proxy.observe import Instruments, Observation
from mcp_customs.proxy.routing import protocol_version_of, routing_header_mismatch
from mcp_customs.proxy.sse import SseError, SseEvent, SseParser, encode_event

logger = logging.getLogger(__name__)

SSE_MEDIA_TYPE: Final = "text/event-stream"
JSON_MEDIA_TYPE: Final = "application/json"
SESSION_HEADER: Final = "mcp-session-id"
_ANSWER_KINDS: Final = frozenset({MessageKind.RESPONSE, MessageKind.ERROR})


@dataclass(frozen=True, slots=True)
class _Route:
    """One authenticated request, resolved to its upstream."""

    name: str
    upstream: UpstreamConfig
    identity: Identity | None
    session_id: str | None
    """The upstream's session id, after unbinding the one the client sent."""

    def exchange(self, request: Request, protocol_version: str | None) -> Exchange:
        return Exchange(
            upstream=self.name,
            http_method=request.method,
            headers=request.headers,
            protocol_version=protocol_version,
            session_id=self.session_id,
            identity=self.identity,
        )


@dataclass(slots=True)
class _Flow:
    """One exchange on its way back: what was asked, and how it is being observed."""

    exchange: Exchange
    request: Message | None
    obs: Observation
    annotations: Annotations = field(default_factory=dict)
    """What server-side stages noted about the answer."""

    @property
    def request_id(self) -> RequestId | None:
        return self.request.id if self.request is not None else None


class _BodyTooLargeError(Exception):
    pass


class _UpstreamFailedError(Exception):
    def __init__(self, status: int, code: int, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class _WithheldError(Exception):
    """A server message that the pipeline could not vet; it must not reach the client."""


def _media_type(content_type: str | None) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def _latin1_pairs(raw: Iterable[tuple[bytes, bytes]]) -> list[tuple[str, str]]:
    return [(name.decode("latin-1"), value.decode("latin-1")) for name, value in raw]


def _set_header(headers: list[tuple[str, str]], name: str, value: str | None) -> list[tuple[str, str]]:
    """Replace every ``name`` header with one carrying ``value`` (or none, for ``None``)."""
    kept = [(key, existing) for key, existing in headers if key.lower() != name]
    return kept if value is None else [*kept, (name, value)]


def _with_headers[R: Response](response: R, headers: Iterable[tuple[str, str]]) -> R:
    """Append headers as raw pairs, so repeated upstream headers survive."""
    response.raw_headers.extend((name.encode("latin-1"), value.encode("latin-1")) for name, value in headers)
    return response


def error_response(status: int, request_id: RequestId | None, code: int, message: str) -> Response:
    return Response(
        dumps(error_object(request_id, code, message)), status_code=status, media_type=JSON_MEDIA_TYPE
    )


async def _read_request_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise _BodyTooLargeError
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise _BodyTooLargeError
    return bytes(body)


async def _read_upstream_body(response: httpx2.Response, limit: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body += chunk
        if len(body) > limit:
            raise _BodyTooLargeError
    return bytes(body)


async def _close_quietly(response: httpx2.Response) -> None:
    # Shielded: this runs while a disconnected client's task is being cancelled.
    with anyio.CancelScope(shield=True):
        await response.aclose()


class StreamableHttpProxy:
    def __init__(
        self,
        config: GatewayConfig,
        http: httpx2.AsyncClient,
        pipeline: Pipeline,
        *,
        authenticator: JwtAuthenticator | None = None,
        sessions: SessionBinder | None = None,
        instruments: Instruments | None = None,
    ) -> None:
        self._config = config
        self._http = http
        self._pipeline = pipeline
        self._authenticator = authenticator
        self._sessions = sessions
        self._instruments = instruments or Instruments.none()

    async def handle(self, request: Request, upstream_name: str) -> Response:
        obs = self._instruments.begin(request, upstream_name)
        origin = request.headers.get("origin")
        if origin is not None and origin not in self._config.security.allowed_origins:
            return await _rejected(obs, error_response(403, None, INVALID_REQUEST, "Origin not allowed"))

        # Authenticate before revealing anything, including which upstreams exist.
        identity: Identity | None = None
        if self._authenticator is not None:
            try:
                identity = await self._authenticator.authenticate(request.headers.get("authorization"))
            except AuthError as exc:
                return await _rejected(obs, self._unauthenticated(exc), f"authentication: {exc.description}")
        obs.identified(identity)

        upstream = self._config.upstreams.get(upstream_name)
        if upstream is None:
            response = error_response(404, None, INVALID_REQUEST, f"Unknown upstream {upstream_name!r}")
            return await _rejected(obs, response)

        session_id = request.headers.get(SESSION_HEADER)
        if session_id is not None and self._sessions is not None and identity is not None:
            session_id = self._sessions.unbind(upstream_name, identity.agent, session_id)
            if session_id is None:
                # 404 is what the spec prescribes for an unknown session: a client
                # whose session predates a key change starts a new one, and a
                # caller holding someone else's id learns nothing.
                response = error_response(404, None, SESSION_NOT_FOUND, "Session not found")
                return await _rejected(obs, response, "session not bound to this agent")

        route = _Route(upstream_name, upstream, identity, session_id)
        if request.method == "POST":
            return await self._post(request, route, obs)
        return await self._forward_bodiless(request, route, obs)

    def _unauthenticated(self, exc: AuthError) -> Response:
        response = error_response(exc.status, None, UNAUTHENTICATED, exc.description)
        if exc.status == 401:
            metadata = self._config.auth.resource_metadata_url if self._config.auth else None
            challenge = www_authenticate(exc, resource_metadata_url=str(metadata) if metadata else None)
            response.headers["www-authenticate"] = challenge
        return response

    def _upstream_headers(self, request: Request, route: _Route, obs: Observation) -> list[tuple[str, str]]:
        headers = upstream_request_headers(_latin1_pairs(request.headers.raw), route.upstream.headers)
        if request.headers.get(SESSION_HEADER) is not None:
            headers = _set_header(headers, SESSION_HEADER, route.session_id)
        for name, value in obs.upstream_headers().items():
            headers = _set_header(headers, name, value)
        return headers

    def _client_headers(
        self, upstream_response: httpx2.Response, exchange: Exchange
    ) -> list[tuple[str, str]]:
        headers = client_response_headers(upstream_response.headers.multi_items())
        session_id = upstream_response.headers.get(SESSION_HEADER)
        if session_id is not None and self._sessions is not None and exchange.identity is not None:
            bound = self._sessions.bind(exchange.upstream, exchange.identity.agent, session_id)
            headers = _set_header(headers, SESSION_HEADER, bound)
        return headers

    # -- client to server ------------------------------------------------------------------------

    async def _post(self, request: Request, route: _Route, obs: Observation) -> Response:
        try:
            body = await _read_request_body(request, self._config.limits.max_request_bytes)
        except _BodyTooLargeError:
            return await _rejected(obs, error_response(413, None, INVALID_REQUEST, "Request body too large"))
        try:
            message = parse_message(body)
        except JsonRpcError as exc:
            return await _rejected(
                obs, error_response(400, exc.request_id, exc.code, exc.message), exc.message
            )

        raw_headers = _latin1_pairs(request.headers.raw)
        if (mismatch := routing_header_mismatch(message, request.headers, raw_headers)) is not None:
            return await _rejected(obs, error_response(400, message.id, HEADER_MISMATCH, mismatch), mismatch)

        exchange = route.exchange(request, protocol_version_of(message, request.headers))
        obs.parsed(message, exchange)
        ctx = ClientMessageContext(exchange, message)
        if self._pipeline:
            try:
                with obs.active():
                    outcome = await self._pipeline.client_message(ctx)
            except (StageFailedError, InvalidReplacementError, JsonRpcError):
                logger.exception("pipeline failed on %s to %s; not forwarded", message.method, route.name)
                error = error_object(message.id, INTERNAL_ERROR, "Gateway pipeline error")
                await obs.stopped("error", error, None, ctx.annotations, "gateway pipeline error")
                return await _answered(obs, 500, error, "gateway pipeline error")
            match outcome:
                case Respond(message=reply, stage=stage):
                    await obs.stopped("denied", reply, stage, ctx.annotations, f"answered by {stage}")
                    if not message.is_request:
                        await obs.finish(202)
                        return Response(status_code=202)
                    await obs.finish(200)
                    return Response(dumps(reply), media_type=JSON_MEDIA_TYPE)
                case Replace(message=replacement):
                    message = Message(replacement, message.kind)
                    body = dumps(replacement)
                case _:
                    pass

        try:
            await obs.forwarding(ctx.annotations)
        except AuditUnavailableError:
            logger.error("audit log unavailable; refused %s to %s", message.method, route.name)  # noqa: TRY400
            error = error_object(
                message.id, AUDIT_UNAVAILABLE, "Audit log unavailable; the call was not made"
            )
            return await _answered(obs, 503, error, "audit log unavailable")

        upstream_request = self._http.build_request(
            "POST",
            str(route.upstream.url),
            headers=self._upstream_headers(request, route, obs),
            content=body,
            timeout=self._timeout(route.upstream, stream=False),
        )
        flow = _Flow(exchange, message, obs)
        try:
            upstream_response = await self._send(upstream_request, route.name)
        except _UpstreamFailedError as exc:
            return await _answered(
                obs, exc.status, error_object(message.id, exc.code, exc.message), exc.message
            )
        return await self._relay(upstream_response, flow)

    async def _forward_bodiless(self, request: Request, route: _Route, obs: Observation) -> Response:
        """GET opens a server-initiated event stream (handshake era); DELETE ends a session."""
        exchange = route.exchange(request, request.headers.get("mcp-protocol-version"))
        obs.transport()
        upstream_request = self._http.build_request(
            request.method,
            str(route.upstream.url),
            headers=self._upstream_headers(request, route, obs),
            timeout=self._timeout(route.upstream, stream=request.method == "GET"),
        )
        try:
            upstream_response = await self._send(upstream_request, route.name)
        except _UpstreamFailedError as exc:
            return await _answered(obs, exc.status, error_object(None, exc.code, exc.message), exc.message)
        return await self._relay(upstream_response, _Flow(exchange, None, obs))

    def _timeout(self, upstream: UpstreamConfig, *, stream: bool) -> httpx2.Timeout:
        return httpx2.Timeout(
            connect=upstream.connect_timeout_s,
            read=None if stream else upstream.read_timeout_s,
            write=upstream.read_timeout_s,
            pool=upstream.connect_timeout_s,
        )

    async def _send(self, upstream_request: httpx2.Request, upstream_name: str) -> httpx2.Response:
        try:
            return await self._http.send(upstream_request, stream=True, follow_redirects=False)
        except httpx2.TimeoutException as exc:
            logger.warning("upstream %s timed out", upstream_name)
            raise _UpstreamFailedError(
                504, UPSTREAM_TIMEOUT, f"Upstream {upstream_name!r} timed out"
            ) from exc
        except httpx2.TransportError as exc:
            logger.warning("upstream %s unavailable: %s", upstream_name, exc)
            message = f"Upstream {upstream_name!r} unavailable"
            raise _UpstreamFailedError(502, UPSTREAM_UNAVAILABLE, message) from exc

    # -- server to client ------------------------------------------------------------------------

    async def _relay(self, upstream_response: httpx2.Response, flow: _Flow) -> Response:
        status = upstream_response.status_code
        flow.obs.upstream_responded(status)
        headers = self._client_headers(upstream_response, flow.exchange)
        media_type = _media_type(upstream_response.headers.get("content-type"))

        if media_type == SSE_MEDIA_TYPE:
            events = self._relay_sse(upstream_response, flow, status)
            return _with_headers(StreamingResponse(events, status_code=status), headers)

        try:
            content = await _read_upstream_body(upstream_response, self._config.limits.max_response_bytes)
        except _BodyTooLargeError:
            return await self._failed(flow, 502, UPSTREAM_BAD_RESPONSE, "Upstream response too large")
        except httpx2.TransportError:
            return await self._failed(flow, 502, UPSTREAM_UNAVAILABLE, "Upstream closed the connection")
        finally:
            await _close_quietly(upstream_response)

        if media_type == JSON_MEDIA_TYPE and content:
            inspected = await self._inspect_json_body(content, status, flow)
            if isinstance(inspected, Response):
                return inspected
            content = inspected
        await flow.obs.finish(status, annotations=flow.annotations)
        return _with_headers(Response(content, status_code=status), headers)

    async def _failed(self, flow: _Flow, status: int, code: int, message: str) -> Response:
        return await _answered(
            flow.obs, status, error_object(flow.request_id, code, message), message, flow.annotations
        )

    async def _inspect_json_body(self, content: bytes, status: int, flow: _Flow) -> bytes | Response:
        upstream = flow.exchange.upstream
        try:
            decoded = loads_strict(content)
        except JsonRpcError:
            logger.warning("upstream %s sent invalid JSON (HTTP %d)", upstream, status)
            return await self._failed(flow, 502, UPSTREAM_BAD_RESPONSE, "Upstream sent invalid JSON")
        try:
            message = classify(decoded)
        except JsonRpcError:
            if status >= 400:
                return content  # an HTTP-level error document, not a protocol message
            logger.warning("upstream %s sent a non-JSON-RPC body: %.200r", upstream, decoded)
            return await self._failed(flow, 502, UPSTREAM_BAD_RESPONSE, "Upstream sent an invalid message")
        if not self._answers(message, flow.request):
            logger.warning("upstream %s answered a request it was not asked", upstream)
            return await self._failed(flow, 502, UPSTREAM_BAD_RESPONSE, "Upstream answered the wrong request")
        try:
            replacement = await self._run_server_stages(flow, message)
        except _WithheldError:
            return await self._failed(flow, 500, INTERNAL_ERROR, "Gateway pipeline error")
        flow.obs.answered(replacement if replacement is not None else message.raw)
        return content if replacement is None else dumps(replacement)

    async def _relay_sse(
        self, upstream_response: httpx2.Response, flow: _Flow, status: int
    ) -> AsyncIterator[bytes]:
        parser = SseParser(self._config.limits.max_response_bytes)
        awaiting_answer = flow.request is not None and flow.request.is_request
        failure: str | None = None
        ended_early = True  # until the stream is read to its end, or fails in a way handled below
        try:
            async for chunk in upstream_response.aiter_bytes():
                for event in parser.feed(chunk):
                    out, answered = await self._relay_event(event, flow)
                    awaiting_answer = awaiting_answer and not answered
                    if out:
                        yield out
                    elif event.has_data:
                        failure = "Upstream sent an invalid message"
            for event in parser.close():
                out, _ = await self._relay_event(event, flow)
                if out:
                    yield out
            ended_early = False
        except SseError as exc:
            failure, ended_early = f"Upstream sent an invalid event stream: {exc}", False
        except httpx2.TransportError:
            failure, ended_early = "Upstream closed the event stream", False
        finally:
            await _close_quietly(upstream_response)
            if ended_early:  # the client went away: cancelled, or the response closed under us
                with anyio.CancelScope(shield=True):
                    await flow.obs.finish(status, failure="client disconnected", annotations=flow.annotations)

        # A stream may legitimately end before its answer (the client resumes
        # with Last-Event-ID), so an error is synthesised only when something
        # went wrong; otherwise the caller could wait forever for an answer
        # the gateway dropped.
        if failure is not None:
            logger.warning("upstream %s: %s", flow.exchange.upstream, failure)
            if awaiting_answer and flow.request is not None:
                error = error_object(flow.request.id, UPSTREAM_BAD_RESPONSE, failure)
                flow.obs.answered(error)
                yield encode_event(dumps(error).decode("utf-8"), event="message")
        await flow.obs.finish(status, failure=failure, annotations=flow.annotations)

    async def _relay_event(self, event: SseEvent, flow: _Flow) -> tuple[bytes, bool]:
        """Return the bytes to forward for one event, and whether it answered the request."""
        if event.data is None:
            return event.raw, False
        upstream = flow.exchange.upstream
        try:
            message = parse_message(event.data)
        except JsonRpcError:
            logger.warning("dropped an invalid SSE message from upstream %s", upstream)
            return b"", False
        if not self._answers(message, flow.request):
            logger.warning("dropped an answer to a request upstream %s was not asked", upstream)
            return b"", False
        answered = flow.request is not None and message.kind in _ANSWER_KINDS
        try:
            replacement = await self._run_server_stages(flow, message)
        except _WithheldError:
            if message.kind not in _ANSWER_KINDS:
                return b"", False
            replacement = error_object(message.id, INTERNAL_ERROR, "Gateway pipeline error")
        if answered:
            flow.obs.answered(replacement if replacement is not None else message.raw)
        if replacement is None:
            return event.raw, answered
        data = dumps(replacement).decode("utf-8")
        return encode_event(data, event=event.event, event_id=event.id), answered

    @staticmethod
    def _answers(message: Message, request_message: Message | None) -> bool:
        """On a POST, a response or error must answer that POST's request.

        An error with a null id is a transport-level refusal (an expired
        session, say) and may come back on any POST.
        """
        if message.kind not in _ANSWER_KINDS or request_message is None:
            return True
        if message.kind is MessageKind.ERROR and message.id is None:
            return True
        return request_message.is_request and message.id == request_message.id

    async def _run_server_stages(self, flow: _Flow, message: Message) -> JSONObject | None:
        """Return the replacement message, or ``None`` to forward the original."""
        if not self._pipeline:
            return None
        ctx = ServerMessageContext(flow.exchange, message, flow.request, flow.annotations)
        try:
            with flow.obs.active():
                outcome = await self._pipeline.server_message(ctx)
        except (StageFailedError, InvalidReplacementError, JsonRpcError) as exc:
            logger.exception(
                "pipeline failed on a message from upstream %s; withheld", flow.exchange.upstream
            )
            raise _WithheldError from exc
        return outcome.message if isinstance(outcome, Replace) else None


async def _rejected(obs: Observation, response: Response, reason: str | None = None) -> Response:
    """Record a request refused before it was understood, and return the refusal."""
    await obs.rejected(response.status_code, reason or bytes(response.body).decode("utf-8", "replace")[:200])
    return response


async def _answered(
    obs: Observation, status: int, error: JSONObject, failure: str, annotations: Annotations | None = None
) -> Response:
    """Answer the client with a gateway error, closing its observation."""
    obs.answered(error)
    await obs.finish(status, failure=failure, annotations=annotations)
    return Response(dumps(error), status_code=status, media_type=JSON_MEDIA_TYPE)
