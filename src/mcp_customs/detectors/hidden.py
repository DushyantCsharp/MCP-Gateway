"""Cheap, deterministic checks for text a human reviewer would not see.

These do not judge what text says, only whether some of it is hidden:

``unicode_tags``
    Characters from the Unicode tag block (U+E0000 to U+E007F). They render as
    nothing, can spell out any ASCII text, and have no legitimate use in tool
    output.
``bidi_controls``
    Direction overrides and isolates (U+202A to U+202E, U+2066 to U+2069),
    which reorder what is displayed relative to what is stored.
``invisible_characters``
    Zero-width and other invisible characters inside Latin words: two or more
    in one text. Zero-width joiners between emoji or in scripts that need them
    are left alone.
``mixed_script``
    A word that mixes Latin letters with Cyrillic or Greek look-alikes.
``encoded_text``
    A long base64 run that decodes to readable text.

Each check reports where it fired, so the injection stage's ``strip`` mode can
remove just that part. They run in microseconds, on every result, whatever
its length.
"""

import base64
import binascii
import re
import unicodedata
from typing import Final

from mcp_customs.detectors.base import Detection, Detector

_TAGS: Final = re.compile("[\U000e0000-\U000e007f]+")
_BIDI: Final = re.compile("[\u202a-\u202e\u2066-\u2069]+")
_INVISIBLE: Final = frozenset("\u200b\u200c\u200d\u2060\u180e\ufeff")
_WORD: Final = re.compile(r"\w{3,}")
_BASE64: Final = re.compile(r"[A-Za-z0-9+/]{48,}={0,2}")
_LOOKALIKE_SCRIPTS: Final = ("CYRILLIC", "GREEK")

WEIGHTS: Final = {
    "unicode_tags": 1.0,
    "bidi_controls": 0.9,
    "invisible_characters": 0.8,
    "mixed_script": 0.7,
    "encoded_text": 0.6,
}


def _script(char: str) -> str | None:
    if not char.isalpha():
        return None
    name = unicodedata.name(char, "")
    if name.startswith("LATIN"):
        return "LATIN"
    return next((script for script in _LOOKALIKE_SCRIPTS if name.startswith(script)), None)


def _mixed(word: str) -> bool:
    scripts = {script for char in word if (script := _script(char))}
    return "LATIN" in scripts and len(scripts) > 1


def _invisible_inside_latin(text: str) -> list[tuple[int, int]]:
    spans = []
    for index, char in enumerate(text):
        if char not in _INVISIBLE or index == 0 or index == len(text) - 1:
            continue
        before, after = text[index - 1], text[index + 1]
        if before.isascii() and before.isalpha() and after.isascii() and after.isalpha():
            spans.append((index, index + 1))
    return spans


def _readable(data: bytes) -> bool:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(char.isprintable() or char in "\n\t" for char in decoded)
    return printable >= 0.9 * len(decoded) and len(decoded.split()) >= 4


class HiddenTextDetector:
    name = "hidden"

    def detect(self, text: str) -> Detection:
        found: dict[str, list[tuple[int, int]]] = {}
        if spans := [match.span() for match in _TAGS.finditer(text)]:
            found["unicode_tags"] = spans
        if spans := [match.span() for match in _BIDI.finditer(text)]:
            found["bidi_controls"] = spans
        if len(spans := _invisible_inside_latin(text)) >= 2:
            found["invisible_characters"] = spans
        mixed = [match.span() for match in _WORD.finditer(text) if _mixed(match.group())]
        if mixed:
            found["mixed_script"] = mixed
        encoded = []
        for match in _BASE64.finditer(text):
            try:
                data = base64.b64decode(match.group(), validate=True)
            except (binascii.Error, ValueError):
                continue
            if _readable(data):
                encoded.append(match.span())
        if encoded:
            found["encoded_text"] = encoded
        if not found:
            return Detection(0.0, self.name)
        rules = tuple(sorted(found, key=lambda rule: -WEIGHTS[rule]))
        where = tuple(sorted(span for spans_of_rule in found.values() for span in spans_of_rule))
        return Detection(max(WEIGHTS[rule] for rule in found), self.name, rules=rules, spans=where)


class LayeredDetector:
    """Runs detectors in order and keeps the strongest finding.

    A layer scoring at or above ``decisive`` ends the run early, so an
    expensive classifier is skipped when a cheap check is already certain.
    """

    def __init__(self, layers: list[Detector], *, decisive: float = 0.95, name: str = "layered") -> None:
        self.layers = layers
        self.decisive = decisive
        self.name = name

    def detect(self, text: str) -> Detection:
        best = Detection(0.0, self.name)
        rules: list[str] = []
        spans: list[tuple[int, int]] = []
        for layer in self.layers:
            detection = layer.detect(text)
            rules += [f"{layer.name}:{rule}" for rule in detection.rules]
            spans += detection.spans
            if detection.score > best.score:
                best = detection
            if detection.score >= self.decisive:
                break
        return Detection(best.score, self.name, rules=tuple(rules), spans=tuple(sorted(set(spans))))
