"""The sensitive-data scanner.

Every secret here is fake and is assembled at runtime from parts, so no
literal in this file looks like a real credential to secret scanners or to
the private-key pre-commit hook. Personal data uses documented test values
(test card numbers, the standard example IBAN) or numbers generated to pass
their checksums.
"""

from itertools import pairwise

import pytest

from mcp_customs.detectors.sensitive import CATEGORIES, SensitiveScanner, expand, luhn, redact

ALL = SensitiveScanner()


def kinds(text: str, scanner: SensitiveScanner = ALL) -> list[str]:
    return [finding.kind for finding in scanner.find(text)]


def luhn_complete(prefix: str) -> str:
    """Append the check digit that makes ``prefix`` pass the Luhn test."""
    return next(prefix + str(d) for d in range(10) if luhn(prefix + str(d)))


FAKE = {
    "aws_access_key": "AKIA" + "Q" * 4 + "7" * 4 + "EXAMPLE1",
    "github_token": "gh" + "p_" + "a1B2" * 9,
    "slack_token": "xo" + "xb-" + "1234567890-abcdefghij",
    "stripe_key": "sk" + "_live_" + "Z" * 24,
    "google_api_key": "AI" + "za" + "x" * 35,
    "ai_api_key": "sk" + "-ant-" + "k" * 40,
    "jwt": "ey" + "J" + "a" * 12 + ".ey" + "J" + "b" * 12 + "." + "c" * 16,
}


@pytest.mark.parametrize(("kind", "value"), FAKE.items(), ids=FAKE.keys())
def test_secret_formats_are_found(kind: str, value: str) -> None:
    assert kinds(f"config: {value} end") == [kind]


def test_private_key_blocks_are_found_whole() -> None:
    begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
    text = f"key:\n{begin}\nMIIEowIBAAKCAQEA{'x' * 64}\n{end}\nafter"
    (finding,) = ALL.find(text)
    assert finding.kind == "private_key"
    assert text[finding.start : finding.end].startswith(begin)
    assert redact(text, [finding]) == "key:\n[REDACTED:private_key]\nafter"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("password = hunter2-but-longer", "hunter2-but-longer"),
        ('{"api_key": "abc123xyz789"}', "abc123xyz789"),
        ("Authorization: Bearer " + "t0k3n" * 5, "t0k3n" * 5),
        ("postgres://customs:" + "s3cret-pw" + "@db:5432/customs", "s3cret-pw"),
    ],
    ids=["assignment", "json-key", "bearer", "url"],
)
def test_only_the_value_is_redacted_where_there_is_a_label(text: str, secret: str) -> None:
    (finding,) = ALL.find(text)
    assert text[finding.start : finding.end] == secret
    assert secret not in redact(text, [finding])


@pytest.mark.parametrize(
    "text",
    [
        "the password field is required",
        "set your api_key in the dashboard",
        "postgres://db:5432/customs",
        "token: short",
        "skip_live_traffic is a flag",
    ],
)
def test_secret_lookalikes_are_not_found(text: str) -> None:
    assert kinds(text, SensitiveScanner(["secrets"])) == []


def test_cards_must_pass_luhn() -> None:
    assert kinds("card 4111 1111 1111 1111 on file") == ["card"]
    assert kinds("card 4111-1111-1111-1111 on file") == ["card"]
    assert kinds("order 4111 1111 1111 1112 shipped") == []
    assert kinds("000000000000000000") == []


def test_ibans_must_pass_mod_97() -> None:
    assert kinds("pay GB82 WEST 1234 5698 7654 32 today") == ["iban"]
    assert kinds("pay GB82WEST12345698765432 today") == ["iban"]
    assert kinds("pay GB82 WEST 1234 5698 7654 33 today") == []


def test_south_african_id_numbers_need_a_date_and_a_checksum() -> None:
    valid = luhn_complete("880211500908")  # 1988-02-11, citizen
    assert kinds(f"ID {valid}") == ["za_id"]
    bad_date = luhn_complete("881311500908")  # month 13: not an ID, but still Luhn-valid digits
    assert kinds(f"ID {bad_date}") == ["card"]
    bad_check = valid[:-1] + str((int(valid[-1]) + 1) % 10)
    assert kinds(f"ID {bad_check}") == []


def test_us_ssns_follow_issuance_rules() -> None:
    assert kinds("SSN 123-45-6789") == ["us_ssn"]
    assert kinds("SSN 000-12-3456, 666-12-3456, 912-34-5678, 123-00-4567") == []


def test_emails_and_phones() -> None:
    assert kinds("write to jane.doe+ap@example.co.za") == ["email"]
    assert kinds("call +27 82 555 0123 or 082 555 0123") == ["phone", "phone"]
    assert kinds("version 1.2.3, build 20261002, port 8000") == []


def test_overlaps_keep_the_longest_match() -> None:
    text = "postgres://ap@example.com:" + "pw-12345" + "@db/x"
    found = ALL.find(text)
    assert all(a.end <= b.start for a, b in pairwise(found))


def test_allow_list_skips_known_values() -> None:
    scanner = SensitiveScanner(["pii"], allow=[r".*@acme\.example"])
    assert kinds("ap@acme.example and x@evil.example", scanner) == ["email"]


def test_scanners_can_be_narrowed_per_call() -> None:
    text = "jane@example.com " + FAKE["aws_access_key"]
    assert [f.kind for f in ALL.find(text, frozenset({"email"}))] == ["email"]


def test_category_names_expand() -> None:
    assert expand(["secrets"]) == CATEGORIES["secrets"]
    assert expand(["email", "card"]) == {"email", "card"}
    with pytest.raises(ValueError, match="unknown kind"):
        expand(["passport"])
