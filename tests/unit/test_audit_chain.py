import dataclasses

import pytest

from mcp_customs.audit import GENESIS, AuditRow, ChainHead, Hasher, canonical_json, verify_chain


def bodies(n: int) -> list[str]:
    return [canonical_json({"n": i, "text": "é"}) for i in range(n)]


def test_canonical_json_is_stable() -> None:
    assert canonical_json({"b": 1, "a": [1.5, "é"]}) == '{"a":[1.5,"é"],"b":1}'
    with pytest.raises(ValueError, match="Out of range"):
        canonical_json({"x": float("inf")})


def test_rows_link_from_genesis() -> None:
    rows = Hasher().extend("gw-1", ChainHead(), bodies(3))
    assert [row.seq for row in rows] == [1, 2, 3]
    assert rows[0].prev_hash == GENESIS
    assert rows[1].prev_hash == rows[0].hash
    assert rows[2].prev_hash == rows[1].hash
    assert verify_chain("gw-1", rows, Hasher()).ok


def test_extending_from_a_head_continues_the_chain() -> None:
    hasher = Hasher()
    first = hasher.extend("gw-1", ChainHead(), bodies(2))
    more = hasher.extend("gw-1", ChainHead(first[-1].seq, first[-1].hash), bodies(2))
    report = verify_chain("gw-1", first + more, hasher)
    assert (report.ok, report.rows, report.head.seq) == (True, 4, 4)


def tamper(rows: list[AuditRow], index: int, **changes: object) -> list[AuditRow]:
    return [*rows[:index], dataclasses.replace(rows[index], **changes), *rows[index + 1 :]]  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("mutate", "problem"),
    [
        (lambda rows: tamper(rows, 2, body='{"n":99}'), "row 3 has been altered"),
        (lambda rows: rows[:2] + rows[3:], "row 3 is missing"),
        (lambda rows: [rows[1], rows[0], *rows[2:]], "row 1 is missing"),
        (lambda rows: tamper(rows, 2, prev_hash="f" * 64), "row 3 does not link to row 2"),
        (lambda rows: tamper(rows, 0, seq=0), "row 1 is missing"),
    ],
    ids=["edited", "deleted", "reordered", "relinked", "renumbered"],
)
def test_tampering_is_detected(mutate: object, problem: str) -> None:
    rows = Hasher().extend("gw-1", ChainHead(), bodies(5))
    assert callable(mutate)
    report = verify_chain("gw-1", mutate(rows), Hasher())
    assert report.problem is not None
    assert report.problem.startswith(problem)


def test_rewriting_a_plain_chain_consistently_is_not_detected() -> None:
    """The documented limit of an unkeyed chain: recompute everything and it verifies."""
    hasher = Hasher()
    rows = hasher.extend("gw-1", ChainHead(), bodies(3))
    forged = hasher.extend("gw-1", ChainHead(), [rows[0].body, '{"n":"forged"}', rows[2].body])
    assert verify_chain("gw-1", forged, hasher).ok


def test_a_keyed_chain_cannot_be_rewritten_without_the_key() -> None:
    keyed = Hasher(b"audit-key")
    rows = keyed.extend("gw-1", ChainHead(), bodies(3))
    assert verify_chain("gw-1", rows, keyed).ok
    forged = Hasher(b"guessed-key").extend("gw-1", ChainHead(), bodies(3))
    assert verify_chain("gw-1", forged, keyed).problem == "row 1 has been altered"


def test_downgrading_a_keyed_chain_is_detected() -> None:
    plain_forgery = Hasher().extend("gw-1", ChainHead(), bodies(2))
    report = verify_chain("gw-1", plain_forgery, Hasher(b"audit-key"))
    assert report.problem is not None
    assert "possible downgrade" in report.problem


def test_a_keyed_chain_needs_the_key_to_verify() -> None:
    rows = Hasher(b"audit-key").extend("gw-1", ChainHead(), bodies(1))
    report = verify_chain("gw-1", rows, Hasher())
    assert report.problem is not None
    assert "pass the audit key" in report.problem


def test_rows_from_another_chain_do_not_verify() -> None:
    rows = Hasher().extend("gw-1", ChainHead(), bodies(2))
    assert verify_chain("gw-2", rows, Hasher()).problem == "row 1 has been altered"


def test_row_events_decode() -> None:
    (row,) = Hasher().extend("gw-1", ChainHead(), [canonical_json({"type": "request"})])
    assert row.event == {"type": "request"}
