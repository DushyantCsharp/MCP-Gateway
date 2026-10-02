"""The ordered stage pipeline every message passes through.

A stage sees each client-to-server message on the way out and each
server-to-client message on the way back, and returns an outcome:

* :data:`CONTINUE` forwards the message as it is.
* :class:`Replace` forwards a modified message, for example with secrets
  redacted. Later stages see the replacement.
* :class:`Respond` (client direction only) stops the message at the gateway
  and sends the given reply to the client instead, for example a denial.

Stages run in the order they are configured, in both directions. A stage
that raises fails the message closed: it is not forwarded, and the client
gets an error in its place.

A stage explains itself by writing ``ctx.annotations[<stage name>]``, a dict
of scalars (for the policy stage: the decision, rule and reason). The
gateway copies annotations onto the stage's span and into the audit log.
Each stage runs inside its own span.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar

from opentelemetry import trace

from mcp_customs.auth.identity import Identity
from mcp_customs.jsonrpc import JSONObject, Message, MessageKind, classify
from mcp_customs.proxy.routing import name_param


@dataclass(frozen=True, slots=True)
class Exchange:
    """The HTTP exchange a message travels in."""

    upstream: str
    http_method: str
    headers: Mapping[str, str]
    """The client's request headers, case-insensitive."""
    protocol_version: str | None
    session_id: str | None
    """The upstream's session id (handshake era), as the upstream issued it."""
    identity: Identity | None = None
    """The authenticated caller; ``None`` when the gateway runs without authentication."""


type Annotations = dict[str, dict[str, Any]]
"""Stage name -> what that stage decided, as scalar values."""


@dataclass(frozen=True, slots=True)
class ClientMessageContext:
    exchange: Exchange
    message: Message
    annotations: Annotations = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ServerMessageContext:
    exchange: Exchange
    message: Message
    request: Message | None
    """The client request this message answers or belongs to; ``None`` on a server-initiated stream."""
    annotations: Annotations = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Continue:
    pass


CONTINUE = Continue()


@dataclass(frozen=True, slots=True)
class Replace:
    message: JSONObject


@dataclass(frozen=True, slots=True)
class Respond:
    message: JSONObject
    stage: str | None = None
    """Filled in by the pipeline: which stage answered."""


type ClientOutcome = Continue | Replace | Respond
type ServerOutcome = Continue | Replace


class StageFailedError(RuntimeError):
    def __init__(self, stage: str) -> None:
        super().__init__(f"pipeline stage {stage!r} failed")
        self.stage = stage


class InvalidReplacementError(ValueError):
    """A stage replaced a message with one that changes what is being called or answered."""


class Stage:
    """Base class for pipeline stages. Override either hook or both."""

    name: ClassVar[str] = "stage"

    async def on_client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        return CONTINUE

    async def on_server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        return CONTINUE


def _check_client_replacement(original: Message, replacement: Message) -> None:
    # Routing must not change: modern clients mirror method and name into
    # HTTP headers, and the policy decision was made on the original.
    if (replacement.kind, replacement.id, replacement.method) != (
        original.kind,
        original.id,
        original.method,
    ):
        raise InvalidReplacementError("a replacement may not change the message kind, id or method")
    if name_param(replacement) != name_param(original):
        raise InvalidReplacementError(
            "a replacement may not change the tool, prompt or resource being called"
        )


def _check_server_replacement(original: Message, replacement: Message) -> None:
    answers = {MessageKind.RESPONSE, MessageKind.ERROR}
    if original.kind in answers:
        if replacement.kind not in answers or replacement.id != original.id:
            raise InvalidReplacementError("a replaced response must stay a response to the same request")
    elif (replacement.kind, replacement.id, replacement.method) != (
        original.kind,
        original.id,
        original.method,
    ):
        raise InvalidReplacementError("a replaced server request or notification may only change its params")


def _record(span: trace.Span, stage: str, outcome: object, annotations: Annotations) -> None:
    span.set_attribute("customs.stage.outcome", type(outcome).__name__.lower())
    for key, value in annotations.get(stage, {}).items():
        if isinstance(value, str | bool | int | float):
            span.set_attribute(f"customs.{stage}.{key}", value)


class Pipeline:
    def __init__(self, stages: Sequence[Stage] = (), *, tracer: trace.Tracer | None = None) -> None:
        self._stages = tuple(stages)
        self.tracer: trace.Tracer = tracer or trace.NoOpTracer()

    @property
    def stages(self) -> tuple[Stage, ...]:
        return self._stages

    def __bool__(self) -> bool:
        return bool(self._stages)

    async def client_message(self, ctx: ClientMessageContext) -> ClientOutcome:
        current = ctx
        for stage in self._stages:
            with self.tracer.start_as_current_span(f"stage {stage.name}") as span:
                try:
                    outcome = await stage.on_client_message(current)
                except Exception as exc:
                    raise StageFailedError(stage.name) from exc
                _record(span, stage.name, outcome, ctx.annotations)
            match outcome:
                case Respond():
                    return replace(outcome, stage=stage.name)
                case Replace(message=raw):
                    replacement = classify(raw)
                    _check_client_replacement(ctx.message, replacement)
                    current = replace(current, message=replacement)
                case Continue():
                    pass
        return CONTINUE if current is ctx else Replace(current.message.raw)

    async def server_message(self, ctx: ServerMessageContext) -> ServerOutcome:
        current = ctx
        # Answers get spans; the notifications that may stream ahead of them
        # (progress, logs) would only bury the trace.
        traced = ctx.message.kind in (MessageKind.RESPONSE, MessageKind.ERROR)
        for stage in self._stages:
            span = self.tracer.start_span(f"stage {stage.name} (answer)") if traced else trace.INVALID_SPAN
            try:
                with trace.use_span(span, end_on_exit=True):
                    outcome = await stage.on_server_message(current)
                    _record(span, stage.name, outcome, ctx.annotations)
            except Exception as exc:
                raise StageFailedError(stage.name) from exc
            if isinstance(outcome, Replace):
                replacement = classify(outcome.message)
                _check_server_replacement(ctx.message, replacement)
                current = replace(current, message=replacement)
        return CONTINUE if current is ctx else Replace(current.message.raw)
