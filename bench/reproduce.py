"""Reproduce the published numbers from a fresh clone, with one command.

    uv sync --group bench
    uv run --group bench python bench/reproduce.py

Needs git, a full (not shallow) clone, and Docker running, for the Postgres
and Redis containers. It takes about 15 minutes on an Apple M4 laptop; the
first run also downloads the 740 MB classifier. Steps:

1. Fetch InjecAgent (MIT) at its pinned commit into ``bench/datasets/external/``.
2. Rebuild benchmark v2 and check that its hashes match the published manifest:
   the same data, byte for byte.
3. Score it with the layered detector, and compare detection and false-positive
   rates on the test split with the published ones.
4. Measure budget accuracy (a Redis container): nothing may slip past a limit.
5. Measure latency overhead (a Postgres container), briefly. Absolute numbers
   depend on the machine; the published ones say which machine they came from.

Results go to ``bench/results/reproduced/`` (git-ignored), never over the
published files. The exit status is 0 when every comparison holds.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "bench" / "results" / "reproduced"
PUBLISHED = ROOT / "bench" / "results"
INJECAGENT = ROOT / "bench" / "datasets" / "external" / "InjecAgent"
INJECAGENT_URL = "https://github.com/uiuc-kang-lab/InjecAgent.git"
INJECAGENT_COMMIT = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
DETECTION = PUBLISHED / "detection-v2-2026-10-02-layered.json"
BUDGET = PUBLISHED / "budget-v1-2026-10-03.json"
LATENCY = PUBLISHED / "latency-2026-10-02.json"
TOLERANCE = 2
"""Samples a rate may differ by: floating point varies slightly across CPUs, so a score right at the
threshold can land either side of it."""


def step(title: str) -> float:
    print(f"\n== {title}", flush=True)
    return time.perf_counter()


def run(*args: str, cwd: Path = ROOT) -> None:
    subprocess.run(args, cwd=cwd, check=True)  # noqa: S603 - fixed commands


def check_prerequisites() -> None:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required")
    shallow = subprocess.run(  # noqa: S603
        [git, "rev-parse", "--is-shallow-repository"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    if shallow.stdout.strip() == "true":
        raise SystemExit("this is a shallow clone; run `git fetch --unshallow` (the build reads pinned docs)")
    docker = shutil.which("docker")
    running = (
        docker is not None
        and subprocess.run([docker, "info"], capture_output=True, check=False).returncode == 0  # noqa: S603
    )
    if not running:
        raise SystemExit(
            "Docker must be running: the budget and latency runs start Postgres and Redis containers"
        )


def fetch_injecagent() -> None:
    git = shutil.which("git") or "git"
    if not INJECAGENT.exists():
        run(git, "clone", "--quiet", INJECAGENT_URL, str(INJECAGENT))
    run(git, "-C", str(INJECAGENT), "checkout", "--quiet", INJECAGENT_COMMIT)


def newest(pattern: str) -> Path:
    matches = sorted(OUT.glob(pattern), key=lambda path: path.stat().st_mtime)
    if not matches:
        raise SystemExit(f"no results matching {pattern} in {OUT}")
    return matches[-1]


def rates(results: dict[str, Any], key: str) -> tuple[int, int]:
    row = next(r for r in results[key] if r["group"] == "all" and r["split"] == "test")
    return int(row["hits"]), int(row["n"])


def compare_detection() -> list[str]:
    published = json.loads(DETECTION.read_text())
    reproduced = json.loads(newest("detection-v2-*-layered.json").read_text())
    problems = []
    for key, label in (("detection", "attacks flagged"), ("false_positives", "benign output flagged")):
        (hits, n), (again, n_again) = rates(published, key), rates(reproduced, key)
        verdict = "same" if (hits, n) == (again, n_again) else f"differs by {abs(hits - again)}"
        print(
            f"  {label:24} published {hits}/{n} ({100 * hits / n:.1f}%), "
            f"reproduced {again}/{n_again}: {verdict}"
        )
        if n != n_again or abs(hits - again) > TOLERANCE:
            problems.append(f"{label}: {hits}/{n} published, {again}/{n_again} reproduced")
    return problems


def compare_budget() -> list[str]:
    published = {
        (o["scenario"], o["store"], o["gateways"]): o for o in json.loads(BUDGET.read_text())["outcomes"]
    }
    reproduced = json.loads(newest("budget-v1-*.json").read_text())["outcomes"]
    problems = []
    for outcome in reproduced:
        key = (outcome["scenario"], outcome["store"], outcome["gateways"])
        before = published[key]["slipped"]
        print(
            f"  {key[0]:5} {key[1]:6} x{key[2]}: slipped {before} published, {outcome['slipped']} reproduced"
        )
        if key[1] == "redis" and outcome["slipped"] != "0":
            problems.append(f"budget {key}: {outcome['slipped']} slipped past the limit with Redis")
    return problems


def compare_latency() -> None:
    def overheads(path: Path) -> dict[str, float]:
        results = json.loads(path.read_text())["results"]
        direct = {r["concurrency"]: r["p50_ms"] for r in results if r["variant"] == "direct"}
        return {
            r["variant"]: round(r["p50_ms"] - direct[r["concurrency"]], 2)
            for r in results
            if r["variant"] != "direct" and r["concurrency"] == 10
        }

    published, reproduced = overheads(LATENCY), overheads(newest("latency-*.json"))
    machine = json.loads(LATENCY.read_text())["environment"]["cpu"]
    print(f"  p50 overhead at 10 clients (published on {machine}):")
    for variant, value in reproduced.items():
        print(
            f"    {variant:12} published {published.get(variant, float('nan')):6.2f} ms, "
            f"reproduced {value:6.2f} ms"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--skip-latency", action="store_true", help="skip the latency run")
    args = parser.parse_args()
    started = time.perf_counter()
    check_prerequisites()
    OUT.mkdir(parents=True, exist_ok=True)
    python = sys.executable

    t = step("1. Fetch InjecAgent at its pinned commit")
    fetch_injecagent()
    print(f"  done in {time.perf_counter() - t:.0f}s")

    t = step("2. Rebuild benchmark v2 and check it is the published data")
    run(python, "bench/datasets/build.py")
    changed = subprocess.run(  # noqa: S603
        [shutil.which("git") or "git", "diff", "--quiet", "--", "bench/datasets/build/manifest.json"],
        cwd=ROOT,
        check=False,
    )
    if changed.returncode != 0:
        raise SystemExit(
            "the rebuilt dataset differs from the published manifest (git diff bench/datasets/build)"
        )
    print(f"  identical to the published manifest, in {time.perf_counter() - t:.0f}s")

    problems: list[str] = []
    t = step("3. Detection: the layered detector on benchmark v2")
    run(
        python,
        "bench/harness/detection.py",
        "--detector",
        "layered",
        "--max-chars",
        "16000",
        "--out",
        str(OUT),
        "--force",
    )
    problems += compare_detection()
    print(f"  done in {time.perf_counter() - t:.0f}s")

    t = step("4. Budget accuracy (Redis container)")
    run(python, "bench/harness/budget.py", "--out", str(OUT), "--force")
    problems += compare_budget()
    print(f"  done in {time.perf_counter() - t:.0f}s")

    if not args.skip_latency:
        t = step("5. Latency overhead, briefly (Postgres container)")
        latency = ("--concurrency", "10", "--requests", "1000", "--warmup", "200")
        run(python, "bench/harness/latency.py", *latency, "--out", str(OUT))
        compare_latency()
        print(f"  done in {time.perf_counter() - t:.0f}s")

    minutes = (time.perf_counter() - started) / 60
    print(f"\nReproduced in {minutes:.1f} minutes. Results: {OUT.relative_to(ROOT)}/")
    if problems:
        print("Did not reproduce:\n  " + "\n  ".join(problems))
        raise SystemExit(1)
    print("Every comparison holds.")


if __name__ == "__main__":
    main()
