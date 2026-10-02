"""Capturing the gateway's spans in memory."""

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from mcp_customs.telemetry import SCHEMA_URL, Telemetry


class CapturedSpans:
    def __init__(self) -> None:
        self.exporter = InMemorySpanExporter()
        provider = TracerProvider(resource=Resource.create({"service.name": "mcp-customs-test"}))
        provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.telemetry = Telemetry(provider.get_tracer("mcp_customs", schema_url=SCHEMA_URL), provider)

    @property
    def spans(self) -> tuple[ReadableSpan, ...]:
        return tuple(self.exporter.get_finished_spans())

    def in_trace(self, trace_id: int) -> list[ReadableSpan]:
        return [span for span in self.spans if span.context is not None and span.context.trace_id == trace_id]

    def named(self, name: str) -> list[ReadableSpan]:
        return [span for span in self.spans if span.name == name]

    def clear(self) -> None:
        self.exporter.clear()
