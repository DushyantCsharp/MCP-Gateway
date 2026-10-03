"""Build the detection benchmark's datasets from pinned sources.

    uv run python bench/datasets/build.py

Writes ``build/attack.jsonl``, ``build/benign.jsonl`` and ``build/manifest.json``
(counts, file hashes and the exact inputs used). The JSONL files are
regenerated, not committed; the manifest is committed, so a result can be
tied to the data it was measured on. Only counts are printed.

Attack samples come from InjecAgent (see ``SOURCES.md``). Benign samples come
from four classes, described in ``DATASHEET.md``; ``paired`` comes from the
hand-written ``benign/fill-in.md``, the rest are generated here.
"""

import ast
import hashlib
import json
import platform
import random
import re
import shutil
import subprocess
import sysconfig
from collections import Counter
from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from schema import Sample, write_jsonl

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INJECAGENT = HERE / "external" / "InjecAgent"
FILL_IN = HERE / "benign" / "fill-in.md"
OUT = HERE / "build"
SLOT = "<Attacker Instruction>"
SEED = 20261002

ATTACK_FILES = {
    ("dh", "base"): "test_cases_dh_base.json",
    ("dh", "enhanced"): "test_cases_dh_enhanced.json",
    ("ds", "base"): "test_cases_ds_base.json",
    ("ds", "enhanced"): "test_cases_ds_enhanced.json",
}
CATEGORY = {"dh": "tool_hijack", "ds": "exfiltration"}


def short_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


# -- attacks ------------------------------------------------------------------------------------


def injecagent_samples() -> Iterator[Sample]:
    for (kind, variant), name in ATTACK_FILES.items():
        for index, case in enumerate(json.loads((INJECAGENT / "data" / name).read_text())):
            yield Sample(
                id=f"injecagent-{kind}-{variant}-{index:04d}",
                text=case["Tool Response"],
                label="attack",
                category=CATEGORY[kind],
                subcategory=case["Attack Type"],
                variant=variant,
                group=f"injecagent-{kind}-{short_hash(case['Attacker Instruction'])}",
                source="InjecAgent",
                licence="MIT",
                meta={"user_tool": case["User Tool"], "attacker_tools": case["Attacker Tools"]},
            )


def injecagent_templates() -> dict[str, str]:
    templates: dict[str, str] = {}
    for name in ("test_cases_dh_base.json", "test_cases_ds_base.json"):
        for case in json.loads((INJECAGENT / "data" / name).read_text()):
            templates.setdefault(case["User Tool"], case["Tool Response Template"])
    return templates


# -- benign: paired -----------------------------------------------------------------------------

_SECTION = re.compile(r"^## (\S+) \|")
_ENTRY = re.compile(r"^\d+\.\s?(.*)$")


def fill_in_entries(path: Path) -> Iterator[tuple[str, int, str]]:
    """(tool, line number, text) for every non-empty numbered line in the sheet."""
    tool: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if section := _SECTION.match(line):
            tool = section.group(1)
        elif tool and (entry := _ENTRY.match(line.strip())) and entry.group(1).strip():
            number = int(line.strip().split(".", 1)[0])
            yield tool, number, entry.group(1).strip()


def paired_samples() -> Iterator[Sample]:
    templates = injecagent_templates()
    for tool, number, text in fill_in_entries(FILL_IN):
        if tool not in templates:
            continue
        yield Sample(
            id=f"paired-{tool}-{number:02d}",
            text=templates[tool].replace(SLOT, text),
            label="benign",
            category="paired",
            group=f"paired-{tool}",
            source="InjecAgent templates + benign/fill-in.md",
            licence="MIT (templates); project (fillers)",
        )


# -- benign: security docs ----------------------------------------------------------------------

DOCS = [
    "README.md",
    "docs/architecture.md",
    "docs/policy-reference.md",
    "docs/build-notes.md",
    "bench/README.md",
]


DOCS_REF = "d2edc42"
"""The commit the documents are read at. The docs keep changing; the dataset must not change with them."""


def doc_at(ref: str, relative: str) -> str:
    git = shutil.which("git") or "git"
    shown = subprocess.run(  # noqa: S603 - fixed arguments
        [git, "show", f"{ref}:{relative}"], capture_output=True, text=True, check=True, cwd=ROOT
    )
    return shown.stdout


def doc_samples() -> Iterator[Sample]:
    for relative in DOCS:
        paragraphs = re.split(r"\n\s*\n", doc_at(DOCS_REF, relative))
        for index, paragraph in enumerate(p.strip() for p in paragraphs):
            if len(paragraph) >= 200:
                yield Sample(
                    id=f"docs-{relative.replace('/', '-')}-{index:03d}",
                    text=paragraph,
                    label="benign",
                    category="security_docs",
                    group=f"docs-{relative}",
                    source=f"mcp-customs {relative}",
                    licence="Apache-2.0",
                )


# -- benign: code -------------------------------------------------------------------------------

MODULES = [
    "argparse.py", "base64.py", "configparser.py", "ftplib.py", "getpass.py", "hmac.py",
    "imaplib.py", "logging/__init__.py", "secrets.py", "shutil.py", "smtplib.py", "socket.py",
    "ssl.py", "subprocess.py", "tarfile.py", "urllib/request.py", "http/client.py", "zipfile/__init__.py",
]  # fmt: skip
KEYWORDS = re.compile(
    r"ignore|override|password|send|execute|token|secret|delete|upload|instruction", re.IGNORECASE
)
PER_MODULE = 6


def code_samples() -> Iterator[Sample]:
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    for relative in MODULES:
        path = stdlib / relative
        if not path.exists():
            continue
        source = path.read_text(encoding="utf-8")
        kept = 0
        for node in ast.walk(ast.parse(source)):
            if kept >= PER_MODULE or not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            segment = ast.get_source_segment(source, node) or ""
            if 300 <= len(segment) <= 4000 and KEYWORDS.search(segment):
                kept += 1
                yield Sample(
                    id=f"code-{relative.replace('/', '-')}-{node.name}",
                    text=segment,
                    label="benign",
                    category="code",
                    group=f"code-{relative}",
                    source=f"CPython {platform.python_version()} Lib/{relative}",
                    licence="PSF-2.0",
                )


# -- benign: long outputs -----------------------------------------------------------------------

COUNTERPARTIES = [
    "Northwind Logistics", "Cloud hosting", "Payroll run", "Customer receipts", "Office supplies",
    "Contoso Ltd", "Fabrikam Inc", "Tailspin Toys", "Electricity", "Insurance premium",
]  # fmt: skip
TOPICS = [
    "budget",
    "invoice",
    "policy",
    "runbook",
    "roadmap",
    "contract",
    "audit",
    "release",
    "hiring",
    "travel",
]
KINDS = ["notes", "summary", "draft", "v2", "final"]
PATHS = [
    "/",
    "/login",
    "/api/orders",
    "/api/orders/{n}",
    "/static/app.js",
    "/reports/q3",
    "/health",
    "/search",
]


def ledger(rng: random.Random, rows: int) -> dict[str, Any]:
    start = date(2026, 1, 1)
    return {
        "account_id": "ACC-OPERATING",
        "transactions": [
            {
                "id": f"txn-{i:05d}",
                "booked": (start + timedelta(days=rng.randrange(270))).isoformat(),
                "counterparty": rng.choice(COUNTERPARTIES),
                "amount": round(rng.uniform(-25000, 25000), 2),
                "memo": f"{rng.choice(['INV', 'PO', 'REF'])}-{rng.randrange(1000, 9999)}",
            }
            for i in range(rows)
        ],
    }


def search_results(rng: random.Random, rows: int) -> dict[str, Any]:
    return {
        "results": [
            {
                "id": f"doc-{rng.randrange(10**6):06d}",
                "title": f"{rng.choice(TOPICS).title()} {rng.choice(KINDS)}",
                "snippet": " ".join(rng.choice(TOPICS) for _ in range(12)),
                "score": round(rng.random(), 3),
            }
            for _ in range(rows)
        ]
    }


def access_log(rng: random.Random, rows: int) -> str:
    lines = []
    for i in range(rows):
        path = rng.choice(PATHS).replace("{n}", str(rng.randrange(1, 9999)))
        status = rng.choice([200, 200, 200, 201, 204, 301, 304, 400, 401, 404, 500])
        ip = f"10.0.{rng.randrange(256)}.{rng.randrange(256)}"
        stamp = f"02/Oct/2026:10:{i // 60 % 60:02d}:{i % 60:02d} +0000"
        size = rng.randrange(80, 90000)
        lines.append(f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} {size}')
    return "\n".join(lines)


def long_output_samples(per_kind: int = 30) -> Iterator[Sample]:
    rng = random.Random(SEED)  # noqa: S311 - reproducible test data, not cryptography
    for index in range(per_kind):
        for kind, text in (
            ("ledger", json.dumps(ledger(rng, rng.randrange(80, 250)))),
            ("search", json.dumps(search_results(rng, rng.randrange(20, 60)))),
            ("access-log", access_log(rng, rng.randrange(100, 300))),
        ):
            sample_id = f"long-{kind}-{index:02d}"
            yield Sample(
                id=sample_id,
                text=text,
                label="benign",
                category="long_outputs",
                group=sample_id,
                source="generated (seeded)",
                licence="Apache-2.0",
            )


# -- build --------------------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarise(samples: list[Sample]) -> dict[str, Any]:
    by = Counter((s.category, s.variant, s.split) for s in samples)
    return {
        "total": len(samples),
        "groups": len({s.group for s in samples}),
        "by_category_variant_split": {f"{c}/{v}/{sp}": n for (c, v, sp), n in sorted(by.items())},
    }


def main() -> None:
    attacks = list(injecagent_samples())
    benign = [*paired_samples(), *doc_samples(), *code_samples(), *long_output_samples()]
    for samples in (attacks, benign):
        ids = [s.id for s in samples]
        if len(ids) != len(set(ids)):
            raise SystemExit("duplicate sample ids")
    overlap = {s.group for s in attacks if s.split == "dev"} & {s.group for s in attacks if s.split == "test"}
    if overlap:
        raise SystemExit(f"groups in both splits: {sorted(overlap)[:3]}")
    if any(SLOT in s.text for s in benign):
        raise SystemExit("a benign sample still contains the injection slot")

    write_jsonl(OUT / "attack.jsonl", attacks)
    write_jsonl(OUT / "benign.jsonl", benign)
    git = shutil.which("git") or "git"
    commit = subprocess.run(  # noqa: S603 - fixed arguments
        [git, "-C", str(INJECAGENT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    manifest: dict[str, Any] = {
        "built": date.today().isoformat(),
        "inputs": {
            "injecagent_commit": commit,
            "fill_in_sha256": sha256_file(FILL_IN),
            "python_stdlib": platform.python_version(),
            "docs_ref": DOCS_REF,
            "seed": SEED,
        },
        "files": {name: sha256_file(OUT / name) for name in ("attack.jsonl", "benign.jsonl")},
        "attack": summarise(attacks),
        "benign": summarise(benign),
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"attack": manifest["attack"]["total"], "benign": manifest["benign"]["total"]}))
    for label in ("attack", "benign"):
        for key, count in manifest[label]["by_category_variant_split"].items():
            print(f"  {label:6} {key:40} {count}")


if __name__ == "__main__":
    main()
