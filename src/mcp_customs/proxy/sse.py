"""Incremental Server-Sent Events parsing that keeps each event's original bytes.

The relay must look inside every event (to inspect the JSON-RPC message it
carries) without changing what it does not need to change. Each parsed
:class:`SseEvent` keeps the exact bytes it was read from, so an unmodified
event is forwarded byte for byte, ``id:`` fields for resumption included.

Parsing follows the WHATWG event-stream rules: lines end in CRLF, LF or a lone
CR; a blank line ends an event; lines starting with ``:`` are comments.
"""

import re
from dataclasses import dataclass, field
from typing import Final

_LINE_END: Final = re.compile(rb"\r\n|\r|\n")
DEFAULT_MAX_EVENT_BYTES: Final = 16 * 1024 * 1024


class SseError(ValueError):
    """The upstream event stream cannot be relayed safely."""


@dataclass(slots=True)
class SseEvent:
    raw: bytes
    event: str | None = None
    data: str | None = None
    id: str | None = None
    retry: int | None = None

    @property
    def has_data(self) -> bool:
        return self.data is not None


@dataclass(slots=True)
class _Pending:
    raw: bytearray = field(default_factory=bytearray)
    event: str | None = None
    data_lines: list[str] = field(default_factory=list)
    id: str | None = None
    retry: int | None = None
    has_fields: bool = False

    def build(self) -> SseEvent:
        data = "\n".join(self.data_lines) if self.data_lines else None
        return SseEvent(bytes(self.raw), event=self.event, data=data, id=self.id, retry=self.retry)


class SseParser:
    """Feed it chunks as they arrive; it returns each event once its blank line is seen."""

    def __init__(self, max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES) -> None:
        self._max_event_bytes = max_event_bytes
        self._buffer = bytearray()
        self._pending = _Pending()

    def feed(self, chunk: bytes) -> list[SseEvent]:
        self._buffer += chunk
        return self._drain(eof=False)

    def close(self) -> list[SseEvent]:
        """End of stream.

        Comment bytes left over are passed through. A half-received event would
        be silently discarded by a conforming client, which could hide a lost
        JSON-RPC response, so it raises instead and the relay reports it.
        """
        events = self._drain(eof=True)
        partial_line = bytes(self._buffer)
        pending = self._pending
        self._buffer.clear()
        self._pending = _Pending()
        if pending.has_fields or (partial_line and not partial_line.startswith(b":")):
            raise SseError("Event stream ended inside an unterminated event")
        tail = bytes(pending.raw) + partial_line
        if tail:
            events.append(SseEvent(tail))
        return events

    def _drain(self, *, eof: bool) -> list[SseEvent]:
        events: list[SseEvent] = []
        start = 0
        while (match := _LINE_END.search(self._buffer, start)) is not None:
            # A CR as the final buffered byte may be the first half of a CRLF.
            if not eof and match.group() == b"\r" and match.end() == len(self._buffer):
                break
            line = bytes(self._buffer[start : match.start()])
            self._pending.raw += self._buffer[start : match.end()]
            start = match.end()
            if line:
                self._field(line)
            else:
                events.append(self._pending.build())
                self._pending = _Pending()
        del self._buffer[:start]
        if len(self._buffer) + len(self._pending.raw) > self._max_event_bytes:
            raise SseError(f"SSE event exceeds {self._max_event_bytes} bytes")
        return events

    def _field(self, line: bytes) -> None:
        if line.startswith(b":"):
            return
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SseError("SSE line is not valid UTF-8") from exc
        name, sep, value = text.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        pending = self._pending
        match name:
            case "data":
                pending.data_lines.append(value)
            case "event":
                pending.event = value
            case "id":
                if "\0" not in value:
                    pending.id = value
            case "retry":
                if value.isascii() and value.isdigit():
                    pending.retry = int(value)
            case _:
                return
        pending.has_fields = True


def encode_event(data: str, *, event: str | None = None, event_id: str | None = None) -> bytes:
    """Serialise one event; multi-line data becomes multiple ``data:`` lines."""
    lines: list[str] = []
    if event is not None:
        lines.append(f"event: {event}")
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.extend(f"data: {line}" for line in data.split("\n"))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")
