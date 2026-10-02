"""The hidden-text checks. Inputs are built from code points at runtime, and say nothing harmful."""

import base64

import pytest

from mcp_customs.detectors import Calibrated, Detection
from mcp_customs.detectors.hidden import HiddenTextDetector, LayeredDetector

DETECTOR = HiddenTextDetector()
SENTENCE = "The quarterly report is attached and ready for review by Friday."


def tags(text: str) -> str:
    """Spell ``text`` in invisible Unicode tag characters."""
    return "".join(chr(0xE0000 + ord(char)) for char in text)


def rules(text: str) -> tuple[str, ...]:
    return DETECTOR.detect(text).rules


def test_plain_text_is_clean() -> None:
    assert DETECTOR.detect(SENTENCE) == Detection(0.0, "hidden")


def test_tag_characters_are_found_with_their_span() -> None:
    text = "Meeting notes." + tags("hello") + " End."
    detection = DETECTOR.detect(text)
    assert detection.rules == ("unicode_tags",)
    assert detection.score == 1.0
    start, end = detection.spans[0]
    assert text[:start] == "Meeting notes."
    assert text[end:] == " End."


def test_direction_overrides_are_found() -> None:
    assert rules("invoice\u202egnp.exe") == ("bidi_controls",)


def test_invisible_characters_inside_words_are_found() -> None:
    assert rules("rep\u200bort and sum\u200bmary") == ("invisible_characters",)
    assert rules("one rep\u200bort only") == ()  # a single stray character is not enough


@pytest.mark.parametrize(
    "text",
    [
        "family \U0001f468\u200d\U0001f469\u200d\U0001f467 photo",  # emoji joined by ZWJ
        "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",  # Persian, where ZWNJ is spelling
        "\ufeffA byte-order mark at the start",
    ],
)
def test_legitimate_invisible_characters_are_left_alone(text: str) -> None:
    assert rules(text) == ()


def test_lookalike_letters_inside_latin_words_are_found() -> None:
    assert rules("log in at p\u0430ypal today") == ("mixed_script",)  # Cyrillic a


@pytest.mark.parametrize(
    "text", ["\u041c\u043e\u0441\u043a\u0432\u0430 is a city", "\u0391\u03b8\u03ae\u03bd\u03b1 2026"]
)
def test_whole_words_in_other_scripts_are_fine(text: str) -> None:
    assert rules(text) == ()


def test_base64_that_decodes_to_text_is_found() -> None:
    blob = base64.b64encode(SENTENCE.encode()).decode()
    assert rules(f"attachment: {blob}") == ("encoded_text",)


def test_base64_of_binary_is_not_flagged() -> None:
    blob = base64.b64encode(bytes(range(256)) * 2).decode()
    assert rules(f"image data {blob}") == ()


def test_findings_are_ordered_by_weight() -> None:
    blob = base64.b64encode(SENTENCE.encode()).decode()
    detection = DETECTOR.detect(f"{blob} and {tags('x')}")
    assert detection.rules == ("unicode_tags", "encoded_text")
    assert detection.score == 1.0


class Expensive:
    name = "expensive"
    calls = 0

    def detect(self, text: str) -> Detection:
        Expensive.calls += 1
        return Detection(0.7, self.name, rules=("model",))


def test_layers_keep_the_strongest_and_skip_work_once_certain() -> None:
    layered = LayeredDetector([HiddenTextDetector(), Expensive()])
    Expensive.calls = 0
    certain = layered.detect("notes" + tags("x"))
    assert (certain.score, Expensive.calls) == (1.0, 0)
    combined = layered.detect("plain text")
    assert (combined.score, combined.rules, Expensive.calls) == (0.7, ("expensive:model",), 1)


class Fixed:
    name = "fixed"

    def __init__(self, score: float) -> None:
        self.score = score

    def detect(self, text: str) -> Detection:
        return Detection(self.score, self.name)


@pytest.mark.parametrize(
    ("raw", "cut", "scaled"),
    [(0.0, 0.997, 0.0), (0.997, 0.997, 0.5), (1.0, 0.997, 1.0), (0.4985, 0.997, 0.25), (0.75, 0.5, 0.75)],
)
def test_calibration_puts_each_detectors_decision_point_at_one_half(
    raw: float, cut: float, scaled: float
) -> None:
    assert Calibrated(Fixed(raw), cut).detect("x").score == pytest.approx(scaled)


def test_a_high_classifier_cut_does_not_silence_the_cheap_checks() -> None:
    layered = LayeredDetector([HiddenTextDetector(), Calibrated(Fixed(0.99), 0.997)])
    assert layered.detect("plain").score < 0.5  # the classifier is below its own cut
    assert layered.detect("log in at p\u0430ypal").score >= 0.5  # a cheap check still counts
