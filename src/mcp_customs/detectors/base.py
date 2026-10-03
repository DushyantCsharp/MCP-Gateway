"""The detector contract."""

from dataclasses import dataclass, replace
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
    @property
    def name(self) -> str: ...

    def detect(self, text: str) -> Detection: ...


@dataclass
class Calibrated:
    """Rescales a detector's score so that its own decision point lands on 0.5.

    Detectors disagree about what a score means: the classifier's useful
    cut-off can sit at 0.997, the hidden-text checks at 0.6. Rescaling each
    one piecewise-linearly (``threshold`` maps to 0.5, 0 to 0, 1 to 1) lets a
    layered detector and the injection stage use one threshold, 0.5, meaning
    "at least one detector is at its own decision point".
    """

    detector: Detector
    threshold: float

    @property
    def name(self) -> str:
        return self.detector.name

    def detect(self, text: str) -> Detection:
        detection = self.detector.detect(text)
        score, cut = detection.score, self.threshold
        if score < cut:
            scaled = 0.5 * score / cut if cut > 0 else 0.5
        else:
            scaled = 0.5 + 0.5 * (score - cut) / (1 - cut) if cut < 1 else 1.0
        return replace(detection, score=min(1.0, max(0.0, scaled)))
