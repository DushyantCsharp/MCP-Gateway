"""Detectors for prompt injection in tool output.

A detector looks at one piece of text and returns a :class:`Detection`: a
score from 0 (clean) to 1 (injection), and, when it can say, which rules fired
and where. The gateway's injection stage and the benchmark harness both call
:meth:`Detector.detect`, so any implementation plugs into both.
"""

from mcp_customs.detectors.base import Calibrated, Detection, Detector

__all__ = ["Calibrated", "Detection", "Detector"]
