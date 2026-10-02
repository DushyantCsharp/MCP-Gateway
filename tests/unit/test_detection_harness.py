import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bench" / "datasets"))
sys.path.insert(0, str(ROOT / "bench" / "harness"))

from build import fill_in_entries  # noqa: E402
from detection import Scored, rates, wilson  # noqa: E402
from schema import Label, Sample, read_jsonl, split_for, write_jsonl  # noqa: E402


@pytest.mark.parametrize(
    ("hits", "n", "low", "high"),
    [(8, 10, 0.4902, 0.9433), (0, 10, 0.0, 0.2775), (10, 10, 0.7225, 1.0), (50, 100, 0.4038, 0.5962)],
)
def test_wilson_matches_published_values(hits: int, n: int, low: float, high: float) -> None:
    got = wilson(hits, n)
    assert got == pytest.approx((low, high), abs=1e-4)


def test_wilson_of_nothing_is_uninformative() -> None:
    assert wilson(0, 0) == (0.0, 1.0)


def test_splits_are_deterministic_and_roughly_thirty_percent() -> None:
    groups = [f"group-{i}" for i in range(2000)]
    assert [split_for(g) for g in groups] == [split_for(g) for g in groups]
    share = Counter(split_for(g) for g in groups)["test"] / len(groups)
    assert 0.27 < share < 0.33


def sample(identifier: str, group: str, label: Label = "benign", category: str = "code") -> Sample:
    return Sample(
        id=identifier, text="x", label=label, category=category, group=group, source="s", licence="l"
    )


def test_samples_of_one_group_share_a_split() -> None:
    assert len({sample(f"s{i}", "same-group").split for i in range(20)}) == 1


def test_jsonl_round_trip(tmp_path: Path) -> None:
    samples = [sample("a", "g1"), sample("b", "g2", "attack", "exfiltration")]
    write_jsonl(tmp_path / "s.jsonl", samples)
    assert list(read_jsonl(tmp_path / "s.jsonl")) == samples


def test_fill_in_entries_skip_blank_lines_and_keep_numbers(tmp_path: Path) -> None:
    sheet = tmp_path / "fill-in.md"
    sheet.write_text(
        "# Sheet\n\n1. not in a section\n\n## ToolA | field: body\n\n1. first\n2. \n3.   third  \n\n"
        "## ToolB | field: bio\n\n1. other\n"
    )
    assert list(fill_in_entries(sheet)) == [
        ("ToolA", 1, "first"),
        ("ToolA", 3, "third"),
        ("ToolB", 1, "other"),
    ]


def test_rates_count_flags_per_category_and_split() -> None:
    scored = [
        Scored(sample("a1", "g-a"), 0.9, 0.01),
        Scored(sample("a2", "g-a"), 0.2, 0.01),
        Scored(sample("b1", "g-b", category="docs"), 0.7, 0.01),
    ]
    by_group = {(r.group, r.split): r for r in rates(scored, 0.5, "category")}
    code = next(r for (group, _), r in by_group.items() if group == "code")
    assert (code.hits, code.n) == (1, 2)
    totals = [r for (group, _), r in by_group.items() if group == "all"]
    assert sum(r.n for r in totals) == 3
    assert sum(r.hits for r in totals) == 2
