"""Eval harness — run all detectors against generated datasets and compute metrics.

Usage:
    # Generate datasets first:
    python -m eval.generators.gen_css_attacks
    python -m eval.generators.gen_unicode_attacks
    python -m eval.generators.gen_image_attacks

    # Then run eval:
    python -m eval.eval_runner
    python -m eval.eval_runner --suite css
    python -m eval.eval_runner --suite unicode
    python -m eval.eval_runner --suite images
    python -m eval.eval_runner --suite cloaking --port 15780
    python -m eval.eval_runner --out eval/results/run_latest.json
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal, Optional

DATA_DIR = Path(__file__).parent / "data"
RESULTS_DIR = Path(__file__).parent / "results"


# ── Metrics ───────────────────────────────────────────────────────────────────

@dataclass
class MetricSet:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0

    @property
    def specificity(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) > 0 else 0.0

    @property
    def mean_latency_ms(self) -> float:
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p95_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_lat = sorted(self.latencies_ms)
        idx = max(0, int(len(sorted_lat) * 0.95) - 1)
        return sorted_lat[idx]

    def summary(self) -> dict:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "specificity": round(self.specificity, 4),
            "mean_latency_ms": round(self.mean_latency_ms, 2),
            "p95_latency_ms": round(self.p95_latency_ms, 2),
            "n_samples": self.tp + self.fp + self.tn + self.fn,
        }


@dataclass
class SampleResult:
    file: str
    category: str
    expected_safe: bool
    predicted_safe: bool
    threat_types: list[str]
    latency_ms: float
    correct: bool
    notes: str = ""


# ── CSS eval ──────────────────────────────────────────────────────────────────

def _run_css_eval(data_dir: Path) -> tuple[MetricSet, list[SampleResult]]:
    from agentshield.detectors.css_hidden_text import detect

    css_dir = data_dir / "css"
    if not css_dir.exists():
        raise FileNotFoundError(f"CSS eval data not found at {css_dir}. Run gen_css_attacks.py first.")

    manifest = json.loads((css_dir / "manifest.json").read_text())
    metrics = MetricSet()
    samples: list[SampleResult] = []

    for entry in manifest:
        html_path = css_dir / entry["file"]
        if not html_path.exists():
            continue
        html = html_path.read_text(encoding="utf-8")
        expected_safe = entry["expected_safe"]

        t0 = time.perf_counter()
        result = detect(html)
        latency_ms = (time.perf_counter() - t0) * 1000

        predicted_safe = len(result.threats) == 0
        threat_types = [t.type for t in result.threats]

        correct = predicted_safe == expected_safe
        if not expected_safe and not predicted_safe:
            metrics.tp += 1
        elif not expected_safe and predicted_safe:
            metrics.fn += 1
        elif expected_safe and not predicted_safe:
            metrics.fp += 1
        else:
            metrics.tn += 1
        metrics.latencies_ms.append(latency_ms)

        samples.append(SampleResult(
            file=entry["file"],
            category=entry.get("category", ""),
            expected_safe=expected_safe,
            predicted_safe=predicted_safe,
            threat_types=threat_types,
            latency_ms=round(latency_ms, 3),
            correct=correct,
            notes=entry.get("notes", ""),
        ))

    return metrics, samples


# ── Unicode eval ──────────────────────────────────────────────────────────────

def _run_unicode_eval(data_dir: Path) -> tuple[MetricSet, list[SampleResult]]:
    from agentshield.detectors.unicode_stego import detect

    uni_dir = data_dir / "unicode"
    if not uni_dir.exists():
        raise FileNotFoundError(f"Unicode eval data not found at {uni_dir}. Run gen_unicode_attacks.py first.")

    manifest = json.loads((uni_dir / "manifest.json").read_text())
    metrics = MetricSet()
    samples: list[SampleResult] = []

    for entry in manifest:
        txt_path = uni_dir / entry["file"]
        if not txt_path.exists():
            continue
        text = txt_path.read_text(encoding="utf-8")
        expected_safe = entry["expected_safe"]

        t0 = time.perf_counter()
        result = detect(text)
        latency_ms = (time.perf_counter() - t0) * 1000

        predicted_safe = len(result.threats) == 0
        threat_types = [t.type for t in result.threats]

        correct = predicted_safe == expected_safe
        if not expected_safe and not predicted_safe:
            metrics.tp += 1
        elif not expected_safe and predicted_safe:
            metrics.fn += 1
        elif expected_safe and not predicted_safe:
            metrics.fp += 1
        else:
            metrics.tn += 1
        metrics.latencies_ms.append(latency_ms)

        samples.append(SampleResult(
            file=entry["file"],
            category=entry.get("category", ""),
            expected_safe=expected_safe,
            predicted_safe=predicted_safe,
            threat_types=threat_types,
            latency_ms=round(latency_ms, 3),
            correct=correct,
            notes=entry.get("notes", ""),
        ))

    return metrics, samples


# ── Image eval ────────────────────────────────────────────────────────────────

def _run_image_eval(data_dir: Path) -> tuple[MetricSet, list[SampleResult]]:
    from agentshield.detectors.image_triage import detect

    img_dir = data_dir / "images"
    if not img_dir.exists():
        raise FileNotFoundError(f"Image eval data not found at {img_dir}. Run gen_image_attacks.py first.")

    manifest = json.loads((img_dir / "manifest.json").read_text())
    metrics = MetricSet()
    samples: list[SampleResult] = []

    for entry in manifest:
        img_path = img_dir / entry["file"]
        if not img_path.exists():
            continue
        img_bytes = img_path.read_bytes()
        expected_safe = entry["expected_safe"]

        t0 = time.perf_counter()
        result = detect(img_bytes, filename=entry["file"])
        latency_ms = (time.perf_counter() - t0) * 1000

        predicted_safe = not result.is_suspicious
        threat_types = [t.type for t in result.threats]

        correct = predicted_safe == expected_safe
        if not expected_safe and not predicted_safe:
            metrics.tp += 1
        elif not expected_safe and predicted_safe:
            metrics.fn += 1
        elif expected_safe and not predicted_safe:
            metrics.fp += 1
        else:
            metrics.tn += 1
        metrics.latencies_ms.append(latency_ms)

        samples.append(SampleResult(
            file=entry["file"],
            category=entry.get("category", ""),
            expected_safe=expected_safe,
            predicted_safe=predicted_safe,
            threat_types=threat_types,
            latency_ms=round(latency_ms, 3),
            correct=correct,
            notes=entry.get("notes", ""),
        ))

    return metrics, samples


# ── Cloaking eval ─────────────────────────────────────────────────────────────

def _run_cloaking_eval(port: int = 15780) -> tuple[MetricSet, list[SampleResult]]:
    from agentshield.detectors.cloaking import detect
    from eval.generators.gen_cloaking_server import CLOAKING_EVAL_CASES, start_background_server

    thread = start_background_server(port=port)
    metrics = MetricSet()
    samples: list[SampleResult] = []

    for case in CLOAKING_EVAL_CASES:
        url = f"http://127.0.0.1:{port}{case['endpoint']}"
        expected_safe = case["expected_safe"]

        t0 = time.perf_counter()
        try:
            result = detect(url)
            latency_ms = (time.perf_counter() - t0) * 1000
            predicted_safe = len(result.threats) == 0
            threat_types = [t.type for t in result.threats]
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            predicted_safe = True
            threat_types = []

        correct = predicted_safe == expected_safe
        if not expected_safe and not predicted_safe:
            metrics.tp += 1
        elif not expected_safe and predicted_safe:
            metrics.fn += 1
        elif expected_safe and not predicted_safe:
            metrics.fp += 1
        else:
            metrics.tn += 1
        metrics.latencies_ms.append(latency_ms)

        samples.append(SampleResult(
            file=case["endpoint"],
            category=case["category"],
            expected_safe=expected_safe,
            predicted_safe=predicted_safe,
            threat_types=threat_types,
            latency_ms=round(latency_ms, 3),
            correct=correct,
            notes=case.get("notes", ""),
        ))

    return metrics, samples


# ── Full run ──────────────────────────────────────────────────────────────────

def run_all(
    suites: list[str] = ("css", "unicode", "images"),
    data_dir: Path = DATA_DIR,
    cloaking_port: int = 15780,
) -> dict:
    suite_runners = {
        "css":      lambda: _run_css_eval(data_dir),
        "unicode":  lambda: _run_unicode_eval(data_dir),
        "images":   lambda: _run_image_eval(data_dir),
        "cloaking": lambda: _run_cloaking_eval(cloaking_port),
    }

    report: dict = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "suites": {},
    }

    aggregate = MetricSet()

    for suite in suites:
        if suite not in suite_runners:
            print(f"Unknown suite: {suite!r}. Valid: {list(suite_runners)}")
            continue

        print(f"\n{'─'*60}")
        print(f"  Suite: {suite.upper()}")
        print(f"{'─'*60}")

        try:
            metrics, samples = suite_runners[suite]()
        except FileNotFoundError as exc:
            print(f"  SKIP: {exc}")
            continue

        m = metrics.summary()
        print(f"  Samples : {m['n_samples']}")
        print(f"  TP/FP/TN/FN : {m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}")
        print(f"  Precision   : {m['precision']:.4f}")
        print(f"  Recall      : {m['recall']:.4f}")
        print(f"  F1          : {m['f1']:.4f}")
        print(f"  Accuracy    : {m['accuracy']:.4f}")
        print(f"  Specificity : {m['specificity']:.4f}")
        print(f"  Latency     : {m['mean_latency_ms']:.2f}ms mean / {m['p95_latency_ms']:.2f}ms p95")

        # Print misclassifications
        wrong = [s for s in samples if not s.correct]
        if wrong:
            print(f"\n  Misclassified ({len(wrong)}):")
            for s in wrong:
                direction = "FP" if s.predicted_safe is False and s.expected_safe else "FN"
                print(f"    [{direction}] {s.file}  ({s.category})  threats={s.threat_types}")

        report["suites"][suite] = {
            "metrics": m,
            "samples": [asdict(s) for s in samples],
        }

        # Accumulate for aggregate
        aggregate.tp += metrics.tp
        aggregate.fp += metrics.fp
        aggregate.tn += metrics.tn
        aggregate.fn += metrics.fn
        aggregate.latencies_ms.extend(metrics.latencies_ms)

    report["aggregate"] = aggregate.summary()

    print(f"\n{'═'*60}")
    print("  AGGREGATE")
    print(f"{'═'*60}")
    ag = report["aggregate"]
    print(f"  Total samples : {ag['n_samples']}")
    print(f"  Precision     : {ag['precision']:.4f}")
    print(f"  Recall        : {ag['recall']:.4f}")
    print(f"  F1            : {ag['f1']:.4f}")
    print(f"  Accuracy      : {ag['accuracy']:.4f}")

    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="GogglesAI eval harness")
    parser.add_argument(
        "--suite",
        nargs="+",
        default=["css", "unicode", "images"],
        choices=["css", "unicode", "images", "cloaking"],
        help="Which eval suites to run",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Path to write JSON report (default: eval/results/run_<timestamp>.json)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=15780,
        help="Port for the cloaking mock server (default: 15780)",
    )
    args = parser.parse_args()

    report = run_all(suites=args.suite, cloaking_port=args.port)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = report["timestamp"].replace(":", "-").replace("T", "_")
    out_path = Path(args.out) if args.out else RESULTS_DIR / f"run_{ts}.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\nReport saved → {out_path}")


if __name__ == "__main__":
    main()
