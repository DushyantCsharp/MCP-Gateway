"""The sample format shared by the dataset build and the detection harness.

One JSON object per line, in ``build/attack.jsonl`` and ``build/benign.jsonl``.
``group`` is what must never be split across ``dev`` and ``test``: for
InjecAgent, the attacker instruction (each one appears in 17 templates), for
benign samples, the template, document or module they came from. Rules and
thresholds are chosen on ``dev`` only; ``test`` is reported, never tuned on.
"""

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

type Label = Literal["attack", "benign"]
type Split = Literal["dev", "test"]

TEST_SHARE = 3  # out of 10 groups


def split_for(group: str) -> Split:
    """Deterministic, by group: about 30% of groups (and all their samples) go to test."""
    bucket = int(hashlib.sha256(group.encode()).hexdigest(), 16) % 10
    return "test" if bucket < TEST_SHARE else "dev"


@dataclass(frozen=True)
class Sample:
    id: str
    text: str
    label: Label
    category: str
    group: str
    source: str
    licence: str
    variant: str = "default"
    subcategory: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def split(self) -> Split:
        return split_for(self.group)

    def to_json(self) -> str:
        return json.dumps({**asdict(self), "split": self.split}, ensure_ascii=False, sort_keys=True)


def write_jsonl(path: Path, samples: Iterable[Sample]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as out:
        for sample in samples:
            out.write(sample.to_json() + "\n")
            count += 1
    return count


def read_jsonl(path: Path) -> Iterator[Sample]:
    with path.open(encoding="utf-8") as lines:
        for line in lines:
            if line.strip():
                data = json.loads(line)
                data.pop("split", None)
                yield Sample(**data)
