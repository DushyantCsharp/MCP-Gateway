"""Regenerate the README's targets-vs-measured and cost tables from the newest published results.

    uv run python bench/harness/readme_tables.py          # rewrite the tables in README.md
    uv run python bench/harness/readme_tables.py --check  # exit 1 if README.md is out of date

Each table sits between ``<!-- generated:<name> -->`` and ``<!-- /generated:<name> -->``
in the README, and every row names the report it came from, with that report's
commit and date. Only files directly in ``bench/results/`` count, so a
reproduction run (``bench/results/reproduced/``) never lands in the README. A
unit test makes the same comparison as ``--check``, so a results file committed
without regenerating the README fails CI.
"""

import argparse
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from detection import threshold_for_scores, wilson
from latency import MAX_P50_OVERHEAD_MS

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "bench" / "results"
README = ROOT / "README.md"
REPOSITORY = "https://github.com/DushyantCsharp/MCP-Gateway"

TARGET_DEV_FPR = 0.05
"""The dev false-positive rate the documented alternative ``classifier_threshold`` (about 0.997) targets."""
DETECTION_THREADS = 5
"""ONNX threads in the published detection run: the harness default, half the M4's 10 cores."""

PRICE_INSTANCE = "AWS EC2 c7g.large (2 vCPU, Graviton3), Linux on-demand, us-east-1"
PRICE_USD_PER_HOUR = 0.0725
PRICE_VCPUS = 2
PRICE_DATE = "2026-10-13"
PRICE_SOURCE = "https://instances.vantage.sh/aws/ec2/c7g.large"


@dataclass(frozen=True)
class Report:
    path: Path
    data: dict[str, Any]

    @property
    def date(self) -> str:
        return str(self.data["environment"]["date"])[:10]

    def cells(self) -> str:
        """The report, commit and date columns of a row."""
        commit = str(self.data["environment"]["commit"])
        name = self.path.with_suffix(".md").name
        return f"[{name}](bench/results/{name}) | [`{commit}`]({REPOSITORY}/commit/{commit}) | {self.date}"


def newest(pattern: str, accept: Callable[[dict[str, Any]], bool] = lambda _: True) -> Report:
    reports = [Report(path, json.loads(path.read_text())) for path in sorted(RESULTS.glob(pattern))]
    reports = [report for report in reports if accept(report.data)]
    if not reports:
        raise SystemExit(f"no results matching {pattern} in {RESULTS}")
    return max(reports, key=lambda report: str(report.data["environment"]["date"]))


def layered(data: dict[str, Any]) -> bool:
    return bool(data["environment"]["detector"] == "layered")


def interval(hits: int, n: int) -> str:
    low, high = wilson(hits, n)
    return f"{hits / n:.1%} [{low:.1%}\N{EN DASH}{high:.1%}] ({hits}/{n})"


def on_test_split(data: dict[str, Any], key: str) -> str:
    row = next(r for r in data[key] if r["group"] == "all" and r["split"] == "test")
    return interval(int(row["hits"]), int(row["n"]))


def targets_table() -> str:
    detection = newest("detection-*.json", layered)
    latency = newest("latency-*.json")
    budget = newest("budget-*.json")

    scores = detection.data["scores"]
    threshold = threshold_for_scores(
        [s["score"] for s in scores if s["label"] == "benign" and s["split"] == "dev"], TARGET_DEV_FPR
    )
    attacks = [s for s in scores if s["split"] == "test" and s["label"] == "attack"]
    benign = [s for s in scores if s["split"] == "test" and s["label"] == "benign"]
    caught = sum(s["score"] >= threshold for s in attacks)
    flagged = sum(s["score"] >= threshold for s in benign)
    met_fpr = "yes" if flagged / len(benign) <= TARGET_DEV_FPR else "no"
    if met_fpr == "yes" and wilson(flagged, len(benign))[1] > TARGET_DEV_FPR:
        met_fpr = "yes, but its interval reaches past it"

    chosen = f"threshold {threshold:.3f} chosen on dev"
    rows = [
        ("Attacks flagged, model's default threshold", "none set",
         on_test_split(detection.data, "detection"), "-", detection),
        ("Legitimate output flagged, model's default threshold", "none set",
         on_test_split(detection.data, "false_positives"), "-", detection),
        (f"Legitimate output flagged, {chosen}", f"≤ {TARGET_DEV_FPR:.0%}",
         interval(flagged, len(benign)), met_fpr, detection),
        (f"Attacks flagged, {chosen}", "none set", interval(caught, len(attacks)), "-", detection),
    ]  # fmt: skip

    results = latency.data["results"]
    direct = {r["concurrency"]: r for r in results if r["variant"] == "direct"}
    for r in sorted((r for r in results if r["variant"] == "full"), key=lambda r: int(r["concurrency"])):
        base = direct[r["concurrency"]]
        p50, p99 = r["p50_ms"] - base["p50_ms"], r["p99_ms"] - base["p99_ms"]
        clients = "1 client" if r["concurrency"] == 1 else f"{r['concurrency']} clients"
        rows.append((
            f"p50 latency added, full pipeline, {clients}",
            f"≤ {MAX_P50_OVERHEAD_MS:g} ms",
            f"+{p50:.2f} ms (p99 {p99:+.2f} ms)",
            "yes" if p50 <= MAX_P50_OVERHEAD_MS and not r["errors"] else "no",
            latency,
        ))  # fmt: skip

    for scenario, what in (("rate", "Calls"), ("spend", "Amount")):
        outcomes = sorted(
            (o for o in budget.data["outcomes"] if o["scenario"] == scenario and o["store"] == "redis"),
            key=lambda o: int(o["gateways"]),
        )
        rows.append((
            f"{what} past a per-agent limit of {int(outcomes[0]['limit'].split()[0]):,}, "
            "Redis counters",
            "0",
            ", ".join(f"{o['slipped']} through {o['gateways']} gateway{'s' * (o['gateways'] > 1)}"
                      for o in outcomes),
            "yes" if all(o["slipped"] == "0" and not o["errors"] for o in outcomes) else "no",
            budget,
        ))  # fmt: skip

    lines = [
        "| Metric | Target | Measured | Met | Report | Commit | Date |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        *(f"| {metric} | {target} | {measured} | {met} | {report.cells()} |"
          for metric, target, measured, met, report in rows),
    ]  # fmt: skip
    return "\n".join(lines)


def usd(amount: float) -> str:
    return f"${amount:.2f}" if amount >= 1 else f"${amount:.2g}"


def cost_table() -> str:
    detection = newest("detection-*.json", layered)
    latency = newest("latency-*.json")
    per_vcpu_second = PRICE_USD_PER_HOUR / PRICE_VCPUS / 3600

    rows = []
    at_ten = {r["variant"]: r for r in latency.data["results"] if r["concurrency"] == 10}
    for variant, label in (("passthrough", "pass-through"), ("full", "full pipeline")):
        rate = float(at_ten[variant]["throughput_rps"])
        rows.append((
            f"One tool call, {label}",
            f"{1000 / rate:.2f} ms of one gateway process ({rate:,.0f} calls/s at 10 clients)",
            usd(1_000_000 / rate * per_vcpu_second),
            latency,
        ))  # fmt: skip

    ms = sorted(float(s["ms"]) for s in detection.data["scores"])
    mean = sum(ms) / len(ms)
    core_seconds = mean / 1000 * DETECTION_THREADS
    rows.append((
        "Injection check of one tool result (classifier on CPU)",
        f"{ms[len(ms) // 2]:.1f} ms median, {mean:.0f} ms mean, on {DETECTION_THREADS} threads: "
        f"up to {core_seconds:.2f} vCPU-seconds",
        f"up to {usd(1_000_000 * core_seconds * per_vcpu_second)}",
        detection,
    ))  # fmt: skip

    lines = [
        "| Unit of work | Model tokens billed | API spend | Compute, measured | "
        "Compute per million, at the price sheet | Report | Commit | Date |",
        "| --- | ---: | ---: | --- | ---: | --- | --- | --- |",
        *(f"| {unit} | 0 | $0 | {compute} | {cost} | {report.cells()} |"
          for unit, compute, cost, report in rows),
        "",
        f"Price sheet: {PRICE_INSTANCE}, ${PRICE_USD_PER_HOUR} an hour "
        f"(${per_vcpu_second * 3600:.5f} per vCPU-hour), as listed on {PRICE_DATE} "
        f"([source]({PRICE_SOURCE})).",
    ]  # fmt: skip
    return "\n".join(lines)


def update(readme: str, tables: dict[str, str]) -> str:
    """Replace each named block's contents in ``readme`` with its table."""
    for name, table in tables.items():
        block = re.search(rf"<!-- generated:{name} -->\n(.*?)<!-- /generated:{name} -->", readme, re.DOTALL)
        if block is None:
            raise SystemExit(f"README.md has no <!-- generated:{name} --> block")
        readme = readme[: block.start(1)] + table + "\n" + readme[block.end(1) :]
    return readme


def tables() -> dict[str, str]:
    return {"targets": targets_table(), "cost": cost_table()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if README.md is out of date")
    args = parser.parse_args()
    current = README.read_text()
    updated = update(current, tables())
    if args.check:
        if updated != current:
            sys.exit("README.md tables are out of date: run uv run python bench/harness/readme_tables.py")
        return
    README.write_text(updated)
    print("README.md tables regenerated" if updated != current else "README.md tables already current")


if __name__ == "__main__":
    main()
