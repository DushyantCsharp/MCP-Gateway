"""The detector contract."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Detection:
    score: float
    """0 means clean, 1 means certainly an injection. Thresholds are chosen per detector."""
    detector: str
    rules: tuple[str, ...] = ()
    """Names of the rules that fired, for detectors that have rules."""
    spans: tuple[tuple[int, int], ...] = ()
    """``[start, end)`` character ranges of the suspicious text, when known."""


class Detector(Protocol):
    name: str

    def detect(self, text: str) -> Detection: ...
