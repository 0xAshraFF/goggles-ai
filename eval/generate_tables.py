"""Generate LaTeX and CSV tables from eval and benchmark reports.

Usage:
    python -m eval.generate_tables --eval eval/results/run_latest.json
    python -m eval.generate_tables --bench eval/results/bench_latest.json
    python -m eval.generate_tables --eval <path> --bench <path> --out eval/tables/

Output files:
    tables/metrics_table.tex     — LaTeX booktabs table (precision/recall/F1/accuracy)
    tables/latency_table.tex     — LaTeX booktabs table (mean/p95/p99 per detector)
    tables/metrics_table.csv     — CSV metrics
    tables/latency_table.csv     — CSV latency
    tables/confusion_matrix.tex  — Per-suite TP/FP/TN/FN
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

TABLES_DIR = Path(__file__).parent / "tables"


# ── LaTeX helpers ─────────────────────────────────────────────────────────────

def _pct(v: float) -> str:
    """Format a 0–1 float as a percentage string."""
    return f"{v * 100:.1f}\\%"


def _ms(v: float) -> str:
    return f"{v:.2f}"


def _escape(s: str) -> str:
    return s.replace("_", r"\_")


def _booktabs_table(
    caption: str,
    label: str,
    headers: list[str],
    rows: list[list[str]],
) -> str:
    col_spec = "l" + "r" * (len(headers) - 1)
    header_row = " & ".join(f"\\textbf{{{h}}}" for h in headers) + " \\\\"
    data_rows = "\n".join("  " + " & ".join(row) + " \\\\" for row in rows)
    return f"""\\begin{{table}}[ht]
\\centering
\\caption{{{caption}}}
\\label{{{label}}}
\\begin{{tabular}}{{{col_spec}}}
\\toprule
{header_row}
\\midrule
{data_rows}
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""


# ── Metrics table ─────────────────────────────────────────────────────────────

def _metrics_table_latex(report: dict) -> str:
    headers = ["Suite", "Prec.", "Recall", "F1", "Acc.", "Spec.", "N"]
    rows = []
    suites = report.get("suites", {})
    for suite, data in suites.items():
        m = data["metrics"]
        rows.append([
            _escape(suite),
            _pct(m["precision"]),
            _pct(m["recall"]),
            _pct(m["f1"]),
            _pct(m["accuracy"]),
            _pct(m["specificity"]),
            str(m["n_samples"]),
        ])
    # Aggregate row
    ag = report.get("aggregate", {})
    if ag:
        rows.append([
            "\\textit{Aggregate}",
            _pct(ag["precision"]),
            _pct(ag["recall"]),
            _pct(ag["f1"]),
            _pct(ag["accuracy"]),
            _pct(ag["specificity"]),
            str(ag["n_samples"]),
        ])
    return _booktabs_table(
        "goggles-ai Detection Metrics by Suite",
        "tab:metrics",
        headers,
        rows,
    )


def _metrics_table_csv(report: dict) -> str:
    headers = ["suite", "precision", "recall", "f1", "accuracy", "specificity", "n_samples"]
    lines = [",".join(headers)]
    suites = report.get("suites", {})
    for suite, data in suites.items():
        m = data["metrics"]
        lines.append(",".join([
            suite,
            str(m["precision"]),
            str(m["recall"]),
            str(m["f1"]),
            str(m["accuracy"]),
            str(m["specificity"]),
            str(m["n_samples"]),
        ]))
    ag = report.get("aggregate", {})
    if ag:
        lines.append(",".join([
            "aggregate",
            str(ag["precision"]),
            str(ag["recall"]),
            str(ag["f1"]),
            str(ag["accuracy"]),
            str(ag["specificity"]),
            str(ag["n_samples"]),
        ]))
    return "\n".join(lines) + "\n"


# ── Confusion matrix table ────────────────────────────────────────────────────

def _confusion_table_latex(report: dict) -> str:
    headers = ["Suite", "TP", "FP", "TN", "FN", "FPR", "FNR"]
    rows = []
    suites = report.get("suites", {})
    for suite, data in suites.items():
        m = data["metrics"]
        fpr = m["fp"] / (m["fp"] + m["tn"]) if (m["fp"] + m["tn"]) > 0 else 0.0
        fnr = m["fn"] / (m["fn"] + m["tp"]) if (m["fn"] + m["tp"]) > 0 else 0.0
        rows.append([
            _escape(suite),
            str(m["tp"]),
            str(m["fp"]),
            str(m["tn"]),
            str(m["fn"]),
            _pct(fpr),
            _pct(fnr),
        ])
    return _booktabs_table(
        "goggles-ai Confusion Matrix by Suite",
        "tab:confusion",
        headers,
        rows,
    )


# ── Latency table ─────────────────────────────────────────────────────────────

_TIER_BUDGET = {
    "css_hidden_text": 50,
    "unicode_stego": 50,
    "html_injection": 50,
    "image_triage": 500,
    "scan_full_html": 50,
    "scan_full_image": 500,
    "tier1": 50,
    "tier2": 500,
}


def _latency_table_latex(bench: dict) -> str:
    headers = ["Detector", "Mean (ms)", "Median (ms)", "P95 (ms)", "P99 (ms)", "Budget", "Pass?"]
    rows = []
    for r in bench.get("results", []):
        budget = _TIER_BUDGET.get(r["detector"], 500)
        passes = r["p95_ms"] <= budget
        check = "\\checkmark" if passes else "\\texttimes"
        rows.append([
            _escape(r["detector"]),
            _ms(r["mean_ms"]),
            _ms(r["median_ms"]),
            _ms(r["p95_ms"]),
            _ms(r["p99_ms"]),
            f"{budget}ms",
            check,
        ])
    return _booktabs_table(
        "goggles-ai Detector Latency (n=100)",
        "tab:latency",
        headers,
        rows,
    )


def _latency_table_csv(bench: dict) -> str:
    headers = ["detector", "suite", "n_samples", "mean_ms", "median_ms", "p95_ms", "p99_ms", "min_ms", "max_ms"]
    lines = [",".join(headers)]
    for r in bench.get("results", []):
        lines.append(",".join(str(r.get(h, "")) for h in headers))
    return "\n".join(lines) + "\n"


# ── Sample-level CSV (misclassifications) ─────────────────────────────────────

def _samples_csv(report: dict) -> str:
    headers = ["suite", "file", "category", "expected_safe", "predicted_safe", "correct", "threat_types", "latency_ms", "notes"]
    lines = [",".join(headers)]
    for suite, data in report.get("suites", {}).items():
        for s in data.get("samples", []):
            threat_str = "|".join(s.get("threat_types", []))
            lines.append(",".join([
                suite,
                s.get("file", ""),
                s.get("category", ""),
                str(s.get("expected_safe", "")),
                str(s.get("predicted_safe", "")),
                str(s.get("correct", "")),
                threat_str,
                str(s.get("latency_ms", "")),
                s.get("notes", "").replace(",", ";"),
            ]))
    return "\n".join(lines) + "\n"


# ── Main ──────────────────────────────────────────────────────────────────────

def generate(
    eval_report_path: Path | None = None,
    bench_report_path: Path | None = None,
    out_dir: Path = TABLES_DIR,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []

    if eval_report_path and eval_report_path.exists():
        report = json.loads(eval_report_path.read_text())

        p = out_dir / "metrics_table.tex"
        p.write_text(_metrics_table_latex(report))
        generated.append(str(p))

        p = out_dir / "metrics_table.csv"
        p.write_text(_metrics_table_csv(report))
        generated.append(str(p))

        p = out_dir / "confusion_matrix.tex"
        p.write_text(_confusion_table_latex(report))
        generated.append(str(p))

        p = out_dir / "samples.csv"
        p.write_text(_samples_csv(report))
        generated.append(str(p))

    if bench_report_path and bench_report_path.exists():
        bench = json.loads(bench_report_path.read_text())

        p = out_dir / "latency_table.tex"
        p.write_text(_latency_table_latex(bench))
        generated.append(str(p))

        p = out_dir / "latency_table.csv"
        p.write_text(_latency_table_csv(bench))
        generated.append(str(p))

    if generated:
        print(f"Generated {len(generated)} table files:")
        for f in generated:
            print(f"  {f}")
    else:
        print("No reports found. Pass --eval and/or --bench paths.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate LaTeX/CSV tables from eval reports")
    parser.add_argument("--eval", type=Path, default=None, help="Path to eval_runner JSON report")
    parser.add_argument("--bench", type=Path, default=None, help="Path to benchmark JSON report")
    parser.add_argument("--out", type=Path, default=TABLES_DIR, help="Output directory")

    # Auto-discover most recent results if not specified
    args = parser.parse_args()
    results_dir = Path(__file__).parent / "results"

    eval_path = args.eval
    bench_path = args.bench

    if eval_path is None and results_dir.exists():
        runs = sorted(results_dir.glob("run_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if runs:
            eval_path = runs[0]
            print(f"Auto-discovered eval report: {eval_path}")

    if bench_path is None and results_dir.exists():
        benches = sorted(results_dir.glob("bench_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if benches:
            bench_path = benches[0]
            print(f"Auto-discovered bench report: {bench_path}")

    generate(eval_path, bench_path, args.out)


if __name__ == "__main__":
    main()
