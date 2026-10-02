"""One :class:`Observation` per HTTP exchange: its spans and its audit events.

The proxy reports what happens (identified, parsed, decided, forwarded,
answered, finished), and the observation turns that into OpenTelemetry spans
and audit events, so the request path reads as request handling and not as
instrumentation.

Spans: one server span per exchange, named after the MCP method and target
(``tools/call transfer_funds``) with MCP and GenAI semantic-convention
attributes; one span per pipeline stage (opened by the pipeline); and one
client span for the upstream exchange, ending when its body or stream does.

Audit: a ``request`` event before a request is forwarded, durable when
configured, so a call the gateway cannot record is refused rather than run;
a ``result`` event when it completes; ``message``, ``transport`` and
``rejected`` events for everything else. See :mod:`mcp_customs.audit.events`.
"""

import logging
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final, Literal

import anyio
from opentelemetry import trace
from opentelemetry.trace import Span, SpanKind, StatusCode
from starlette.requests import Request

from mcp_customs.audit import AuditLog, AuditUnavailableError
from mcp_customs.audit.chain import sha256_of
from mcp_customs.audit.events import event
from mcp_customs.auth import Identity
from mcp_customs.jsonrpc import JSONObject, Message
from mcp_customs.pipeline.base import Annotations, Exchange
from mcp_customs.proxy.routing import name_param
from mcp_customs.telemetry.tracing import parent_context, traceparent_headers

logger = logging.getLogger(__name__)

_KINDS: Final[Mapping[str, str]] = {
    "tools/call": "tool",
    "prompts/get": "prompt",
    "resources/read": "resource",
    "resources/subscribe": "resource",
    "resources/unsubscribe": "resource",
}


@dataclass(frozen=True)
class Instruments:
    tracer: trace.Tracer
    audit: AuditLog | None = None
    durable: bool = True
    record_arguments: bool = False

    @classmethod
    def none(cls) -> "Instruments":
        return cls(trace.NoOpTracer())

    def begin(self, request: Request, upstream: str) -> "Observation":
        return Observation(self, request, upstream)


def outcome_of(answer: JSONObject | None) -> tuple[str, int | None]:
    """``ok``, ``tool_error``, ``error`` (with its code) or ``none``."""
    if answer is None:
        return "none", None
    error = answer.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        return "error", code if isinstance(code, int) else None
    result = answer.get("result")
    if isinstance(result, dict) and result.get("isError") is True:
        return "tool_error", None
    return "ok", None


def _decisions(annotations: Annotations) -> dict[str, Any] | None:
    return {stage: dict(notes) for stage, notes in annotations.items()} or None


type Closing = Literal["result", "message", "transport", "none"]
"""Which event closes an exchange; ``none`` when its opening event already says everything."""


class Observation:
    def __init__(self, instruments: Instruments, request: Request, upstream: str) -> None:
        self._i = instruments
        self._request = request
        self._upstream = upstream
        self._start_ns = time.time_ns()
        self._started = time.perf_counter()
        self._span: Span | None = None
        self._upstream_span: Span | None = None
        self._identity: Identity | None = None
        self._message: Message | None = None
        self._exchange: Exchange | None = None
        self._request_event: str | None = None
        self._answer: JSONObject | None = None
        self._closing: Closing = "none"
        self._finished = False

    # -- spans ------------------------------------------------------------------------------------

    @property
    def span(self) -> Span:
        """The exchange's server span, started (backdated to arrival) the first time it is needed."""
        if self._span is None:
            meta = self._message.params.get("_meta") if self._message is not None else None
            request = self._request
            self._span = self._i.tracer.start_span(
                f"{request.method} /mcp/{self._upstream}",
                context=parent_context(meta, request.headers),
                kind=SpanKind.SERVER,
                start_time=self._start_ns,
                attributes={
                    "http.request.method": request.method,
                    "url.path": request.url.path,
                    "customs.upstream": self._upstream,
                },
            )
        return self._span

    @contextmanager
    def active(self) -> Iterator[None]:
        """Make the exchange span current, so pipeline stage spans nest under it."""
        with trace.use_span(self.span, end_on_exit=False):
            yield

    @property
    def trace_id(self) -> str | None:
        context = self.span.get_span_context()
        return trace.format_trace_id(context.trace_id) if context.is_valid else None

    # -- what the proxy reports -------------------------------------------------------------------

    def identified(self, identity: Identity | None) -> None:
        self._identity = identity

    def parsed(self, message: Message, exchange: Exchange) -> None:
        self._message, self._exchange = message, exchange
        method = message.method or message.kind.value
        target = name_param(message)
        span = self.span  # created now, so it can join the trace named in _meta
        span.update_name(f"{method} {target}" if isinstance(target, str) else method)
        attributes: dict[str, Any] = {"mcp.method.name": method}
        if exchange.protocol_version:
            attributes["mcp.protocol.version"] = exchange.protocol_version
        if exchange.session_id:
            attributes["mcp.session.id"] = exchange.session_id
        if message.id is not None:
            attributes["jsonrpc.request.id"] = str(message.id)
        if self._identity is not None:
            attributes["customs.agent"] = self._identity.agent
            if self._identity.task:
                attributes["customs.task"] = self._identity.task
        if isinstance(target, str):
            match message.method:
                case "tools/call":
                    attributes |= {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": target}
                case "prompts/get":
                    attributes["gen_ai.prompt.name"] = target
                case _:
                    attributes["mcp.resource.uri"] = target
        span.set_attributes(attributes)

    async def forwarding(self, annotations: Annotations) -> None:
        """Record a message about to be forwarded.

        A request's event is written first, durably if so configured, so this
        raises :class:`AuditUnavailableError` when the call cannot be recorded
        and must not be forwarded. Notifications and answers are recorded when
        they complete.
        """
        self.span.set_attribute("customs.decision", "forwarded")
        if self._message is None or not self._message.is_request:
            self._closing = "message"
            return
        body = self._request_body("forwarded", annotations)
        self._request_event, self._closing = body["id"], "result"
        await self._audit(body, durable=self._i.durable)

    async def stopped(
        self,
        decision: str,
        reply: JSONObject | None,
        stage: str | None,
        annotations: Annotations,
        reason: str,
    ) -> None:
        """A parsed message the gateway answered itself: ``denied`` by a stage, or an ``error``."""
        self._answer = reply
        self._closing = "none"
        self.span.set_attribute("customs.decision", decision)
        if self._message is None or not self._message.is_request:
            return
        notes = annotations.get(stage, {}) if stage else {}
        body = self._request_body(
            decision, annotations, stage=stage, rule=notes.get("rule"), reason=notes.get("reason", reason)
        )
        self._request_event = body["id"]
        await self._best_effort(body)

    def transport(self) -> None:
        """A GET or DELETE about to be forwarded."""
        self._closing = "transport"

    def upstream_headers(self) -> dict[str, str]:
        """Start the upstream client span; return the W3C headers that carry it."""
        self._upstream_span = self._i.tracer.start_span(
            f"{self._request.method} {self._upstream}",
            context=trace.set_span_in_context(self.span),
            kind=SpanKind.CLIENT,
            attributes={"customs.upstream": self._upstream, "http.request.method": self._request.method},
        )
        return traceparent_headers(trace.set_span_in_context(self._upstream_span))

    def upstream_responded(self, status: int) -> None:
        if self._upstream_span is not None:
            self._upstream_span.set_attribute("http.response.status_code", status)

    def answered(self, answer: JSONObject) -> None:
        self._answer = answer

    async def rejected(self, status: int, reason: str) -> None:
        """A request refused before its message was read, or with no message at all."""
        self._closing = "none"
        body = event(
            "rejected",
            self._upstream,
            http_method=self._request.method,
            http_status=status,
            reason=reason,
            agent=self._identity.agent if self._identity else None,
            client=self._client,
            trace_id=self.trace_id,
        )
        await self._best_effort(body)
        await self.finish(status, failure=reason)

    async def finish(
        self, status: int, failure: str | None = None, annotations: Annotations | None = None
    ) -> None:
        """End the exchange: write its closing event and end its spans. Safe to call twice."""
        if self._finished:
            return
        self._finished = True
        duration_ms = round((time.perf_counter() - self._started) * 1000, 3)
        outcome, error_code = outcome_of(self._answer)
        if failure is not None and outcome == "none":
            outcome = "refused" if status == 503 else "failed"
        self._finish_span(status, failure, outcome, error_code)

        closing: dict[str, Any] | None = None
        identity, exchange = self._identity, self._exchange
        common: dict[str, Any] = {"status": status, "failure": failure, "trace_id": self.trace_id}
        match self._closing:
            case "result":
                closing = event(
                    "result",
                    self._upstream,
                    request=self._request_event,
                    outcome=outcome,
                    error_code=error_code,
                    result_sha256=self._answer_digest(),
                    duration_ms=duration_ms,
                    stages=_decisions(annotations or {}),
                    **common,
                )
            case "message" if self._message is not None:
                closing = event(
                    "message",
                    self._upstream,
                    kind=self._message.kind.value,
                    method=self._message.method,
                    jsonrpc_id=str(self._message.id) if self._message.id is not None else None,
                    agent=identity.agent if identity else None,
                    session=exchange.session_id if exchange else None,
                    **common,
                )
            case "transport":
                closing = event(
                    "transport",
                    self._upstream,
                    http_method=self._request.method,
                    agent=identity.agent if identity else None,
                    client=self._client,
                    duration_ms=duration_ms,
                    **common,
                )
            case _:
                pass
        if closing is not None:
            with anyio.CancelScope(shield=True):
                await self._best_effort(closing)

    def _finish_span(self, status: int, failure: str | None, outcome: str, error_code: int | None) -> None:
        span = self.span
        span.set_attribute("http.response.status_code", status)
        if outcome == "tool_error":
            span.set_attribute("error.type", "tool_error")
        if error_code is not None:
            span.set_attributes({"rpc.response.status_code": str(error_code), "error.type": str(error_code)})
        if failure is not None or status >= 500:
            span.set_status(StatusCode.ERROR, failure)
        if self._upstream_span is not None:
            self._upstream_span.end()
        span.end()

    # -- helpers ----------------------------------------------------------------------------------

    @property
    def _client(self) -> str | None:
        client = self._request.client
        return f"{client.host}:{client.port}" if client else None

    def _answer_digest(self) -> str | None:
        if self._answer is None:
            return None
        return sha256_of(self._answer.get("result", self._answer.get("error")))

    def _request_body(self, decision: str, annotations: Annotations, **extra: Any) -> dict[str, Any]:
        message, exchange, identity = self._message, self._exchange, self._identity
        if message is None or exchange is None:
            raise RuntimeError("a request event needs a parsed message")
        target = name_param(message)
        arguments = (
            message.params.get("arguments") if message.method in ("tools/call", "prompts/get") else None
        )
        return event(
            "request",
            self._upstream,
            agent=identity.agent if identity else None,
            roles=sorted(identity.roles) if identity and identity.roles else None,
            task=identity.task if identity else None,
            client=self._client,
            session=exchange.session_id,
            protocol=exchange.protocol_version,
            jsonrpc_id=str(message.id) if message.id is not None else None,
            method=message.method,
            kind=_KINDS.get(message.method or ""),
            target=target if isinstance(target, str) else None,
            arguments_sha256=sha256_of(arguments) if arguments is not None else None,
            arguments=arguments if self._i.record_arguments else None,
            decision=decision,
            stages=_decisions(annotations),
            trace_id=self.trace_id,
            **extra,
        )

    async def _audit(self, body: dict[str, Any], *, durable: bool) -> None:
        if self._i.audit is not None:
            await self._i.audit.record(body, durable=durable)

    async def _best_effort(self, body: dict[str, Any]) -> None:
        try:
            await self._audit(body, durable=False)
        except AuditUnavailableError:
            logger.error("audit log unavailable; %s event %s not recorded", body["type"], body["id"])  # noqa: TRY400
