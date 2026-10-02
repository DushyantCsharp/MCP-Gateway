"""Detection benchmark: detection rate per attack category, false-positive rate per benign class.

    uv run python bench/datasets/build.py                    # build the datasets first
    uv run --group bench python bench/harness/detection.py   # score them, write bench/results/

Every rate comes with a Wilson 95% interval. The ``test`` split is the
headline; ``dev`` is reported beside it, and is the only split any threshold
may be chosen on. Misses and false positives are listed by sample id and
score, never by text, so a results file can be shared without republishing
the attacks.
"""

import argparse
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DATASETS = ROOT / "bench" / "datasets"
sys.path.insert(0, str(DATASETS))

from mcp_customs.detectors import Detector  # noqa: E402
from schema import Sample, read_jsonl  # noqa: E402 - the datasets folder is not a package

Z95 = 1.959963984540054


def wilson(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion: honest at small n and near 0 or 1."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass
class Rate:
    group: str
    split: str
    hits: int
    n: int
    rate: float
    low: float
    high: float


@dataclass
class Scored:
    sample: Sample
    score: float
    seconds: float

    def flagged(self, threshold: float) -> bool:
        return self.score >= threshold


def make_detector(name: str, threads: int) -> Detector:
    if name == "classifier":
        from mcp_customs.detectors.classifier import OnnxClassifier

        classifier = OnnxClassifier(threads=threads)
        classifier.load()
        return classifier
    raise SystemExit(f"unknown detector {name!r}")


def score(detector: Detector, samples: list[Sample]) -> list[Scored]:
    scored: list[Scored] = []
    for index, sample in enumerate(samples, start=1):
        started = time.perf_counter()
        detection = detector.detect(sample.text)
        scored.append(Scored(sample, detection.score, time.perf_counter() - started))
        if index % 250 == 0:
            print(f"  scored {index}/{len(samples)}", flush=True)
    return scored


def rates(scored: list[Scored], threshold: float, key: str) -> list[Rate]:
    """Share flagged, per (group, split): detection rate for attacks, false-positive rate for benign."""
    buckets: dict[tuple[str, str], list[Scored]] = defaultdict(list)
    for item in scored:
        sample = item.sample
        group = sample.category if key == "category" else f"{sample.category}/{sample.variant}"
        buckets[(group, sample.split)].append(item)
        buckets[("all", sample.split)].append(item)
    out = []
    for (group, split), items in sorted(buckets.items()):
        hits = sum(item.flagged(threshold) for item in items)
        low, high = wilson(hits, len(items))
        out.append(Rate(group, split, hits, len(items), hits / len(items), low, high))
    return out


def threshold_for_fpr(benign: list[Scored], max_fpr: float) -> float:
    """The lowest threshold at which at most ``max_fpr`` of dev benign samples are flagged."""
    scores = sorted((item.score for item in benign if item.sample.split == "dev"), reverse=True)
    allowed = int(max_fpr * len(scores))
    if allowed >= len(scores):
        return 0.0
    # Flag only scores strictly above the (allowed+1)-th highest benign score.
    return min(1.0, scores[allowed] + 1e-9)


def operating_points(
    attacks: list[Scored], benign: list[Scored], targets: tuple[float, ...]
) -> list[dict[str, Any]]:
    points = []
    for target in targets:
        threshold = threshold_for_fpr(benign, target)
        detected = [r for r in rates(attacks, threshold, "category") if r.group == "all"]
        flagged = [r for r in rates(benign, threshold, "category") if r.group == "all"]
        by_split = {r.split: r for r in detected}, {r.split: r for r in flagged}
        points.append(
            {"target_dev_fpr": target, "threshold": threshold, "detection": by_split[0], "fpr": by_split[1]}
        )
    return points


def environment(detector: Detector) -> dict[str, Any]:
    git = shutil.which("git") or "git"
    commit = subprocess.run([git, "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT)  # noqa: S603
    dirty = subprocess.run(  # noqa: S603 - fixed arguments
        [git, "status", "--porcelain", "--", "src", "bench/harness", "bench/datasets"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    manifest = json.loads((DATASETS / "build" / "manifest.json").read_text())
    return {
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "commit": commit.stdout.strip() + ("+dirty" if dirty.stdout.strip() else ""),
        "detector": detector.name,
        "detector_config": {
            key: getattr(detector, key)
            for key in ("model", "revision", "subfolder")
            if hasattr(detector, key)
        },
        "data": {
            "version": manifest.get("version", 1),
            "built": manifest["built"],
            "files": manifest["files"],
            "inputs": manifest["inputs"],
        },
        "os": platform.platform(),
        "python": platform.python_version(),
        "versions": {pkg: version(pkg) for pkg in ("mcp-customs", "onnxruntime", "tokenizers")},
    }


def percent(rate: Rate) -> str:
    return f"{rate.rate:6.1%} [{rate.low:.1%}, {rate.high:.1%}] ({rate.hits}/{rate.n})"


def markdown(env: dict[str, Any], threshold: float, attacks: list[Scored], benign: list[Scored]) -> str:
    detection = {(r.group, r.split): r for r in rates(attacks, threshold, "variant")}
    detection |= {(r.group, r.split): r for r in rates(attacks, threshold, "category")}
    false_positives = {(r.group, r.split): r for r in rates(benign, threshold, "category")}
    seconds = [item.seconds * 1000 for item in [*attacks, *benign]]
    mean_chars = statistics.fmean(len(item.sample.text) for item in [*attacks, *benign])
    lines = [
        f"# Detection results: {env['detector']}",
        "",
        f"Measured {env['date']} at commit `{env['commit']}`, detector `{env['detector']}` "
        f"{env['detector_config']}, threshold {threshold}. Benchmark v{env['data'].get('version', 1)}, "
        f"built {env['data']['built']} "
        f"(`manifest.json` hashes {', '.join(f'{k} {v[:12]}' for k, v in env['data']['files'].items())}).",
        "",
        "Rates are the share of samples flagged, with Wilson 95% intervals. **Test is the headline**: no "
        "threshold or rule was chosen on it. The split is by group, so test attacks use attacker "
        "instructions never seen in dev.",
        "",
        "## Detection rate (attacks flagged)",
        "",
        "| Category | Test | Dev |",
        "| --- | --- | --- |",
    ]
    groups = sorted({g for g, _ in detection}, key=lambda g: (g == "all", g))
    for group in groups:
        test, dev = detection.get((group, "test")), detection.get((group, "dev"))
        lines.append(f"| {group} | {percent(test) if test else '-'} | {percent(dev) if dev else '-'} |")
    lines += [
        "",
        "## False-positive rate (benign flagged)",
        "",
        "| Class | Test | Dev |",
        "| --- | --- | --- |",
    ]
    for group in sorted({g for g, _ in false_positives}, key=lambda g: (g == "all", g)):
        test, dev = false_positives.get((group, "test")), false_positives.get((group, "dev"))
        lines.append(f"| {group} | {percent(test) if test else '-'} | {percent(dev) if dev else '-'} |")
    quantiles = statistics.quantiles(seconds, n=100) if len(seconds) > 1 else [seconds[0]] * 99
    lines += [
        "",
        "## Thresholds chosen on dev",
        "",
        "The default threshold above is the model's own. Here the threshold is instead chosen on the dev "
        "split's benign samples for a target false-positive rate, then applied unchanged to test.",
        "",
        "| Target dev FPR | Threshold | Test detection | Test FPR | Dev detection | Dev FPR |",
        "| ---: | ---: | --- | --- | --- | --- |",
    ]
    for point in operating_points(attacks, benign, (0.01, 0.05, 0.10, 0.20)):
        detection, fpr = point["detection"], point["fpr"]
        lines.append(
            f"| {point['target_dev_fpr']:.0%} | {point['threshold']:.4f} | {percent(detection['test'])} | "
            f"{percent(fpr['test'])} | {percent(detection['dev'])} | {percent(fpr['dev'])} |"
        )
    lines += [
        "",
        "## Cost",
        "",
        f"Per sample: p50 {statistics.median(seconds):.1f} ms, p99 {quantiles[98]:.1f} ms, "
        f"over {len(seconds)} samples (mean {mean_chars:.0f} characters).",
        "",
        "## Known misses (test split)",
        "",
        "Attacks not flagged, by id. The text is in the dataset build, not here.",
        "",
    ]
    misses = [i for i in attacks if i.sample.split == "test" and not i.flagged(threshold)]
    lines += [f"- `{i.sample.id}` ({i.sample.subcategory}), score {i.score:.3f}" for i in misses[:60]] or [
        "- none"
    ]
    if len(misses) > 60:
        lines.append(f"- ... and {len(misses) - 60} more (full list in the JSON file)")
    lines += ["", "## False positives (test split)", ""]
    flagged = [i for i in benign if i.sample.split == "test" and i.flagged(threshold)]
    lines += [f"- `{i.sample.id}` ({i.sample.category}), score {i.score:.3f}" for i in flagged] or ["- none"]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--detector", default="classifier")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--threads", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--out", type=Path, default=ROOT / "bench" / "results")
    parser.add_argument(
        "--scores",
        type=Path,
        help="reuse the scores in an earlier results JSON instead of running the detector",
    )
    args = parser.parse_args()

    attacks = list(read_jsonl(DATASETS / "build" / "attack.jsonl"))
    benign = list(read_jsonl(DATASETS / "build" / "benign.jsonl"))
    if args.scores:
        earlier = json.loads(args.scores.read_text())
        if (
            earlier["environment"]["data"]["files"]
            != json.loads((DATASETS / "build" / "manifest.json").read_text())["files"]
        ):
            raise SystemExit("those scores were measured on different data; rebuild or re-run the detector")
        cached = {row["id"]: (row["score"], row.get("ms", 0.0) / 1000) for row in earlier["scores"]}
        scored_attacks = [Scored(s, *cached[s.id]) for s in attacks]
        scored_benign = [Scored(s, *cached[s.id]) for s in benign]
        env = {**earlier["environment"], "rescored_from": args.scores.name}
        detector_name = env["detector"]
    else:
        detector = make_detector(args.detector, args.threads)
        print(
            f"scoring {len(attacks)} attack and {len(benign)} benign samples with {detector.name}", flush=True
        )
        scored_attacks, scored_benign = score(detector, attacks), score(detector, benign)
        env = environment(detector)
        detector_name = detector.name

    args.out.mkdir(parents=True, exist_ok=True)
    stem = f"detection-{env['date'][:10]}-{detector_name}"
    (args.out / f"{stem}.md").write_text(markdown(env, args.threshold, scored_attacks, scored_benign))
    payload = {
        "environment": env,
        "threshold": args.threshold,
        "detection": [asdict(r) for r in rates(scored_attacks, args.threshold, "variant")],
        "false_positives": [asdict(r) for r in rates(scored_benign, args.threshold, "category")],
        "scores": [
            {
                "id": i.sample.id,
                "label": i.sample.label,
                "split": i.sample.split,
                "score": round(i.score, 5),
                "ms": round(i.seconds * 1000, 2),
            }
            for i in [*scored_attacks, *scored_benign]
        ],
    }
    (args.out / f"{stem}.json").write_text(json.dumps(payload, indent=2) + "\n")
    for rate in rates(scored_attacks, args.threshold, "category"):
        print(f"detection {rate.split:4} {rate.group:16} {percent(rate)}")
    for rate in rates(scored_benign, args.threshold, "category"):
        print(f"false-pos {rate.split:4} {rate.group:16} {percent(rate)}")
    print(f"wrote {args.out / stem}.md")


if __name__ == "__main__":
    main()
