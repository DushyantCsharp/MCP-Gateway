"""Tracing set-up, and how the gateway joins the caller's trace.

Spans follow the OpenTelemetry semantic conventions for MCP and GenAI, pinned
to schema 1.44.0 because those conventions are still evolving. Each gateway
app owns its tracer provider instead of installing a global one, so several
gateways can run in one process (as the tests do) without sharing spans.

MCP carries trace context in the message body, ``params._meta.traceparent``
(SEP-414), and the official SDKs read it there. The gateway reads it too, so
its spans join the agent's trace, and leaves the body untouched. The upstream
server's span is therefore a sibling of the gateway's span under the agent's,
not its child. Rewriting ``_meta`` to nest it would make the relay
byte-unfaithful, so a W3C ``traceparent`` header is sent upstream instead,
for HTTP-level instrumentation.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from opentelemetry import propagate, trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
from opentelemetry.semconv.schemas import Schemas

from mcp_customs import __version__
from mcp_customs.config import TelemetryConfig

SCHEMA_URL: Final = Schemas.V1_44_0.value
INSTRUMENTATION: Final = "mcp_customs"


@dataclass(frozen=True)
class Telemetry:
    tracer: trace.Tracer
    provider: TracerProvider | None = None

    @classmethod
    def disabled(cls) -> "Telemetry":
        return cls(trace.NoOpTracer())

    @classmethod
    def from_config(cls, config: TelemetryConfig, exporter: SpanExporter | None = None) -> "Telemetry":
        resource = Resource.create(
            {"service.name": config.service_name, "service.version": __version__}, schema_url=SCHEMA_URL
        )
        provider = TracerProvider(
            resource=resource, sampler=ParentBased(TraceIdRatioBased(config.sample_ratio))
        )
        if exporter is None:
            endpoint = f"{str(config.otlp_endpoint).rstrip('/')}/v1/traces" if config.otlp_endpoint else None
            exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        return cls(provider.get_tracer(INSTRUMENTATION, __version__, schema_url=SCHEMA_URL), provider)

    def shutdown(self) -> None:
        if self.provider is not None:
            self.provider.shutdown()


def parent_context(meta: Any, headers: Mapping[str, str]) -> Context | None:
    """The caller's trace context: from ``_meta`` (SEP-414) if valid, else the HTTP ``traceparent``."""
    for carrier in (meta, headers):
        if isinstance(carrier, Mapping) and carrier:
            try:
                context = propagate.extract(carrier)
            except (ValueError, TypeError):
                continue
            if trace.get_current_span(context).get_span_context().is_valid:
                return context
    return None


def traceparent_headers(context: Context | None = None) -> dict[str, str]:
    """W3C trace headers for an outgoing request, for the given (or current) context."""
    carrier: dict[str, str] = {}
    propagate.inject(carrier, context=context)
    return carrier
