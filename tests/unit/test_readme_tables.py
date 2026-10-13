import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bench" / "harness"))

from readme_tables import README, tables, update  # noqa: E402


def test_readme_tables_match_the_newest_results() -> None:
    readme = README.read_text()
    assert update(readme, tables()) == readme, "stale: run uv run python bench/harness/readme_tables.py"


def test_update_fills_an_empty_block_and_replaces_a_stale_one() -> None:
    empty = "a\n<!-- generated:t -->\n<!-- /generated:t -->\nb\n"
    filled = update(empty, {"t": "| x |"})
    assert filled == "a\n<!-- generated:t -->\n| x |\n<!-- /generated:t -->\nb\n"
    assert update(filled, {"t": "| y |"}) == filled.replace("| x |", "| y |")


def test_update_refuses_a_readme_without_the_block() -> None:
    with pytest.raises(SystemExit, match="no <!-- generated:t --> block"):
        update("no markers here", {"t": "| x |"})
