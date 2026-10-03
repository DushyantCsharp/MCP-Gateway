"""Finding secrets and personal data in text, so the gateway can keep them from crossing.

Each kind of value has a pattern, and where the format allows one, a check:
card numbers must pass the Luhn checksum, IBANs the mod-97 check, South
African ID numbers a valid date and the Luhn checksum, US SSNs the issuance
rules. Checks are what keep a run of digits in a log from being redacted as
a card. Where a match has a label and a value (``password=...``,
``user:pass@`` in a URL), only the value is reported.

Kinds are grouped into two categories, ``secrets`` and ``pii``, so a
configuration can name either a category or individual kinds.
"""

import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Final, Literal

type Category = Literal["secrets", "pii"]


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    category: Category
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class _Pattern:
    kind: str
    category: Category
    regex: re.Pattern[str]
    check: Callable[[str], bool] | None = None
    group: str | int = 0
    """The part of the match to report: the whole match, or a named group holding the value."""


def luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def _card(text: str) -> bool:
    digits = re.sub(r"[ -]", "", text)
    return 13 <= len(digits) <= 19 and len(set(digits)) > 1 and luhn(digits)


def _iban(text: str) -> bool:
    compact = text.replace(" ", "").upper()
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return 15 <= len(compact) <= 34 and int(numeric) % 97 == 1


def _za_id(text: str) -> bool:
    """YYMMDD, then gender and sequence, citizenship (0 or 1), a digit, and a Luhn check digit."""
    if not luhn(text) or text[10] not in "01":
        return False
    year, month, day = int(text[:2]), int(text[2:4]), int(text[4:6])
    for century in (1900, 2000):
        try:
            date(century + year, month, day)
        except ValueError:
            continue
        return True
    return False


def _ssn(text: str) -> bool:
    area, group, serial = text.split("-")
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def _phone(text: str) -> bool:
    return 8 <= sum(char.isdigit() for char in text) <= 15


# The labels that precede secrets, not a secret.
_SECRET_LABEL: Final = (
    r"(?:password|passwd|pwd|passphrase|secret|client[_-]?secret|api[_-]?key|access[_-]?key|"  # noqa: S105
    r"secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token)"
)

# Order matters on ties: where two kinds match the same span, the earlier one
# wins, so stricter formats (a South African ID needs a valid date as well as a
# Luhn check) come before looser ones (any 13 to 19 digits that pass Luhn).
PATTERNS: Final[tuple[_Pattern, ...]] = (
    _Pattern(
        "private_key",
        "secrets",
        re.compile(
            r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]{16,}?-----END (?:[A-Z]+ )*PRIVATE KEY-----"
        ),
    ),
    _Pattern("aws_access_key", "secrets", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Pattern(
        "github_token",
        "secrets",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
    ),
    _Pattern("slack_token", "secrets", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    _Pattern("stripe_key", "secrets", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    _Pattern("google_api_key", "secrets", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    _Pattern("ai_api_key", "secrets", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b")),
    _Pattern(
        "jwt", "secrets", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    ),
    _Pattern(
        "bearer_token",
        "secrets",
        re.compile(r"(?i)\bbearer\s+(?P<value>[A-Za-z0-9._~+/-]{20,}=*)"),
        group="value",
    ),
    _Pattern(
        "url_credentials",
        "secrets",
        re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<value>[^\s/@]{3,})@"),
        group="value",
    ),
    _Pattern(
        "assigned_secret",
        "secrets",
        re.compile(rf"(?i)\b{_SECRET_LABEL}\b[\"']?\s*[:=]\s*[\"']?(?P<value>[^\s\"',;{{}}]{{6,}})"),
        group="value",
    ),
    _Pattern("email", "pii", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    _Pattern(
        "iban", "pii", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"), _iban
    ),
    _Pattern("za_id", "pii", re.compile(r"\b\d{13}\b"), _za_id),
    _Pattern("card", "pii", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), _card),
    _Pattern("us_ssn", "pii", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), _ssn),
    _Pattern("phone", "pii", re.compile(r"(?<![\w+])\+\d[\d ().-]{6,18}\d\b"), _phone),
    _Pattern("phone", "pii", re.compile(r"\b0[6-8]\d[ -]?\d{3}[ -]?\d{4}\b")),
)

KINDS: Final = frozenset(pattern.kind for pattern in PATTERNS)
CATEGORIES: Final[dict[str, frozenset[str]]] = {
    category: frozenset(p.kind for p in PATTERNS if p.category == category) for category in ("secrets", "pii")
}


def expand(names: Iterable[str]) -> frozenset[str]:
    """Kinds named directly or through a category. Raises ``ValueError`` for an unknown name."""
    kinds: set[str] = set()
    for name in names:
        if name in CATEGORIES:
            kinds |= CATEGORIES[name]
        elif name in KINDS:
            kinds.add(name)
        else:
            raise ValueError(f"unknown kind {name!r}; expected one of {sorted({*KINDS, *CATEGORIES})}")
    return frozenset(kinds)


class SensitiveScanner:
    def __init__(self, kinds: Iterable[str] = ("secrets", "pii"), *, allow: Sequence[str] = ()) -> None:
        self.kinds = expand(kinds)
        self._patterns = [p for p in PATTERNS if p.kind in self.kinds]
        self._allow = [re.compile(pattern) for pattern in allow]

    def find(self, text: str, kinds: frozenset[str] | None = None) -> list[Finding]:
        """Non-overlapping findings, earliest first; where two overlap, the longer wins."""
        candidates: list[Finding] = []
        for pattern in self._patterns:
            if kinds is not None and pattern.kind not in kinds:
                continue
            for match in pattern.regex.finditer(text):
                value = match.group(pattern.group)
                if not value or (pattern.check is not None and not pattern.check(value)):
                    continue
                if any(allowed.fullmatch(value) for allowed in self._allow):
                    continue
                start, end = match.span(pattern.group)
                candidates.append(Finding(pattern.kind, pattern.category, start, end))
        chosen: list[Finding] = []
        for finding in sorted(candidates, key=lambda f: (f.start, -(f.end - f.start))):
            if not chosen or finding.start >= chosen[-1].end:
                chosen.append(finding)
        return chosen


def redact(text: str, findings: Iterable[Finding]) -> str:
    out: list[str] = []
    last = 0
    for finding in sorted(findings, key=lambda f: f.start):
        out += [text[last : finding.start], f"[REDACTED:{finding.kind}]"]
        last = finding.end
    return "".join([*out, text[last:]])


def strings(value: object, path: tuple[str | int, ...] = ()) -> Iterator[tuple[tuple[str | int, ...], str]]:
    """Every string inside a JSON value, with its path."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, (*path, index))
