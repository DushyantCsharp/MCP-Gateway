"""Write the fill-in sheet for the ``paired`` benign class.

    uv run python bench/datasets/make_fill_in.py

For each distinct InjecAgent tool-response template it finds which field holds
the injection slot, and writes a numbered section with empty lines to fill
in. A person types one ordinary value for that field per line; the dataset
build puts each one into the slot to make a benign sample with exactly the
same shape as the attacks. An existing sheet is never overwritten.
"""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "external" / "InjecAgent" / "data"
SHEET = HERE / "benign" / "fill-in.md"
SLOT = "<Attacker Instruction>"
LINES_PER_SECTION = 10

HEADER = """# Benign fill-in sheet

Each section below is one tool's output. Under it, write what the named field
would normally contain: one example per numbered line. Leave a line empty to
skip it.

- Write the kind of content real users and services produce: reviews, notes,
  emails, bios, event names, descriptions, messages, tweets, web snippets.
- Make some of them hard: everyday requests to a person ("please send me...",
  "ignore my last email..."), mentions of passwords or payments, urgent tone.
  A good detector must not flag these.
- Never write anything addressed to an AI, assistant or agent, and nothing
  that tries to make a tool do something. Those would be attacks, not benign.

Only the text after `N. ` on each line is used. Save the file when you are done.
"""


def slot_field(template: str) -> str:
    """The key whose value holds the slot, e.g. ``review_content``."""
    match = re.search(r"'([A-Za-z_]+)':\s*'[^']*" + re.escape(SLOT), template)
    return match.group(1) if match else "text"


def main() -> None:
    if SHEET.exists():
        sys.exit(f"{SHEET} already exists; not overwriting it")
    templates: dict[str, str] = {}
    for name in ("test_cases_dh_base.json", "test_cases_ds_base.json"):
        for case in json.loads((DATA / name).read_text()):
            templates.setdefault(case["User Tool"], case["Tool Response Template"])
    sections = [HEADER]
    for tool, template in sorted(templates.items()):
        sections.append(f"## {tool} | field: {slot_field(template)}\n")
        sections.extend(f"{n}. " for n in range(1, LINES_PER_SECTION + 1))
        sections.append("")
    SHEET.parent.mkdir(parents=True, exist_ok=True)
    SHEET.write_text("\n".join(sections))
    print(f"wrote {SHEET}: {len(templates)} sections of {LINES_PER_SECTION} lines")


if __name__ == "__main__":
    main()
