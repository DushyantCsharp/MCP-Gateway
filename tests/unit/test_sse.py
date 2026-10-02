import pytest

from mcp_customs.proxy.sse import SseError, SseEvent, SseParser, encode_event

STREAM = (
    b": keepalive\r\n\r\n"
    b'event: message\r\nid: 41\r\ndata: {"a":1}\r\n\r\n'
    b"data: line one\ndata: line two\n\n"
    b"retry: 2500\rdata: cr only\r\r"
    b"event: message\r\ndata:no-space\r\nunknown: ignored\r\n\r\n"
)


def parse_all(chunks: list[bytes]) -> list[SseEvent]:
    parser = SseParser()
    events = [event for chunk in chunks for event in parser.feed(chunk)]
    return events + parser.close()


def test_fields_are_parsed() -> None:
    events = [event for event in parse_all([STREAM]) if event.has_data]
    assert [(e.event, e.id, e.data, e.retry) for e in events] == [
        ("message", "41", '{"a":1}', None),
        (None, None, "line one\nline two", None),
        (None, None, "cr only", 2500),
        ("message", None, "no-space", None),
    ]


def test_comment_only_events_carry_no_data() -> None:
    first = parse_all([STREAM])[0]
    assert first.raw == b": keepalive\r\n\r\n"
    assert not first.has_data


def test_raw_bytes_reassemble_the_stream_exactly() -> None:
    assert b"".join(event.raw for event in parse_all([STREAM])) == STREAM


@pytest.mark.parametrize("split", range(1, len(STREAM)))
def test_any_chunk_boundary_gives_the_same_events(split: int) -> None:
    assert parse_all([STREAM[:split], STREAM[split:]]) == parse_all([STREAM])


def test_byte_at_a_time_gives_the_same_events() -> None:
    assert parse_all([bytes([b]) for b in STREAM]) == parse_all([STREAM])


def test_a_trailing_cr_waits_for_a_possible_lf() -> None:
    parser = SseParser()
    assert parser.feed(b"data: x\r\n\r") == []
    assert [e.raw for e in parser.feed(b"\n")] == [b"data: x\r\n\r\n"]


def test_an_unterminated_event_at_end_of_stream_is_an_error() -> None:
    parser = SseParser()
    parser.feed(b'data: {"jsonrpc":')
    with pytest.raises(SseError):
        parser.close()


def test_an_unterminated_comment_at_end_of_stream_passes_through() -> None:
    parser = SseParser()
    assert parser.feed(b": bye") == []
    assert [e.raw for e in parser.close()] == [b": bye"]


def test_oversized_events_are_refused() -> None:
    parser = SseParser(max_event_bytes=64)
    with pytest.raises(SseError):
        parser.feed(b"data: " + b"x" * 100)


def test_invalid_utf8_is_refused() -> None:
    with pytest.raises(SseError):
        SseParser().feed(b"data: \xff\n\n")


def test_ids_containing_nul_are_ignored() -> None:
    (event,) = SseParser().feed(b"id: a\x00b\ndata: x\n\n")
    assert event.id is None


def test_encode_round_trips() -> None:
    encoded = encode_event("one\ntwo", event="message", event_id="7")
    assert encoded == b"event: message\r\nid: 7\r\ndata: one\r\ndata: two\r\n\r\n"
    (event,) = SseParser().feed(encoded)
    assert (event.event, event.id, event.data) == ("message", "7", "one\ntwo")
