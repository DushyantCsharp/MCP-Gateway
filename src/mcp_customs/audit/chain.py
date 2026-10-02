"""The hash chain: what makes the audit log tamper-evident.

Each row stores an event as canonical JSON and a hash over its chain name,
its sequence number, the previous row's hash and the event itself. Changing,
reordering or removing any row breaks every later link, which
:func:`verify_chain` reports.

With a key the hash is HMAC-SHA256, and rewriting history consistently needs
the key as well as write access to the database. Without one it is plain
SHA-256, which catches accidents and careless edits but not someone who
recomputes every later hash. Neither form detects the newest rows being cut
off the end, unless the head is also recorded somewhere else: this is a
tamper-evident log, not a ledger.
"""

import hashlib
import hmac
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

GENESIS: Final = "0" * 64
type Algorithm = Literal["sha256", "hmac-sha256"]


def canonical_json(value: Any) -> str:
    """Sorted keys, no whitespace, UTF-8 kept: one byte string per value, on every platform."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_of(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditRow:
    chain: str
    seq: int
    alg: Algorithm
    prev_hash: str
    hash: str
    body: str
    """Canonical JSON of the event: exactly the bytes that were hashed."""

    @property
    def event(self) -> Any:
        return json.loads(self.body)


@dataclass(frozen=True, slots=True)
class ChainHead:
    seq: int = 0
    hash: str = GENESIS


class Hasher:
    def __init__(self, key: bytes | None = None) -> None:
        self._key = key
        self.alg: Algorithm = "hmac-sha256" if key else "sha256"

    def link(self, chain: str, seq: int, prev_hash: str, body: str) -> str:
        material = f"{chain}\n{seq}\n{prev_hash}\n{body}".encode()
        if self._key is None:
            return hashlib.sha256(material).hexdigest()
        return hmac.new(self._key, material, hashlib.sha256).hexdigest()

    def extend(self, chain: str, head: ChainHead, bodies: Sequence[str]) -> list[AuditRow]:
        rows: list[AuditRow] = []
        seq, prev = head.seq, head.hash
        for body in bodies:
            seq += 1
            digest = self.link(chain, seq, prev, body)
            rows.append(AuditRow(chain, seq, self.alg, prev, digest, body))
            prev = digest
        return rows


@dataclass(frozen=True, slots=True)
class ChainReport:
    chain: str
    rows: int
    head: ChainHead
    problem: str | None = None
    """``None`` when every link checks out; otherwise the first break, with its sequence number."""

    @property
    def ok(self) -> bool:
        return self.problem is None


def verify_chain(chain: str, rows: Iterable[AuditRow], hasher: Hasher) -> ChainReport:
    """Check one chain's rows, which must be in sequence order. Stops at the first break."""
    head = ChainHead()
    count = 0
    for row in rows:
        count += 1
        problem: str | None = None
        if row.seq != head.seq + 1:
            problem = f"row {head.seq + 1} is missing (next row is {row.seq})"
        elif row.prev_hash != head.hash:
            problem = f"row {row.seq} does not link to row {head.seq}"
        elif row.alg != hasher.alg:
            problem = f"row {row.seq} uses {row.alg} but the chain is verified with {hasher.alg}" + (
                " (pass the audit key)" if row.alg == "hmac-sha256" else " (possible downgrade)"
            )
        elif not hmac.compare_digest(row.hash, hasher.link(chain, row.seq, row.prev_hash, row.body)):
            problem = f"row {row.seq} has been altered"
        if problem is not None:
            return ChainReport(chain, count, head, problem)
        head = ChainHead(row.seq, row.hash)
    return ChainReport(chain, count, head)
