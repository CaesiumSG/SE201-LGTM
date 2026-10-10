#!/usr/bin/env python3
"""LGTM benchmark evaluation harness.

For every case in labels.json:
1. Copy the benchmark app + policy docs into a temp git repo (base branch).
2. Apply the case patch on a ``pr`` branch and commit it.
3. Index the docs and run the LGTM pipeline in the chosen mode.
4. Score the predicted verdict against ground truth.

Metrics: precision / recall / F1 (overall and per category), false-positive
rate on safe controls, evidence grounding rate, possible- and
insufficient-evidence rates, median latency, and estimated tokens per PR.

Usage:
    python benchmark/evaluate.py --mode lgtm
    python benchmark/evaluate.py --mode sast-only --cases sqli_01_vulnerable
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
REPO_ROOT = BENCH.parent

sys.path.insert(0, str(REPO_ROOT / "src"))

from lgtm.config import LGTMConfig, setup_logging  # noqa: E402
from lgtm.pipeline import ReviewPipeline  # noqa: E402
from lgtm.rag.indexer import index_repo_docs  # noqa: E402


def run(cmd: list[str], cwd: Path) -> str:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{result.stderr}")
    return result.stdout


def build_case_repo(tmp: Path, patch_path: Path) -> None:
    """Create a git repo with the base app and the patch applied on ``pr``."""
    shutil.copytree(BENCH / "app", tmp / "app")
    for doc in ("security-policy.md", "api-spec.md", "README.md"):
        shutil.copy(BENCH / doc, tmp / doc)
    run(["git", "init", "-q", "-b", "main"], tmp)
    run(["git", "config", "user.email", "bench@lgtm.local"], tmp)
    run(["git", "config", "user.name", "LGTM Bench"], tmp)
    run(["git", "add", "-A"], tmp)
    run(["git", "commit", "-q", "-m", "base"], tmp)
    run(["git", "checkout", "-q", "-b", "pr"], tmp)
    run(["git", "apply", str(patch_path)], tmp)
    run(["git", "add", "-A"], tmp)
    run(["git", "commit", "-q", "-m", "pr change"], tmp)
    run(["git", "checkout", "-q", "main"], tmp)


def predict_case_verdict(findings: list[dict], category: str) -> str:
    """Collapse per-finding verdicts into one case-level prediction.

    Only findings of the case's own category count (a case tests one task);
    uncategorized findings count for either.
    """
    relevant = [
        f for f in findings
        if f.get("category") in (category, "", "sast", None)
    ] or findings
    verdicts = [f.get("verdict") for f in relevant]
    if "vulnerable" in verdicts:
        return "vulnerable"
    if "possible" in verdicts:
        return "possible"
    if verdicts and all(v == "insufficient_evidence" for v in verdicts):
        return "insufficient_evidence"
    return "safe"


def estimate_tokens(findings: list[dict], meta: dict) -> int:
    """Rough token estimate (chars/4) from finding content; a proxy only."""
    chars = 0
    for f in findings:
        chars += len(json.dumps(f, default=str))
    return chars // 4


def evaluate_case(case: dict, config: LGTMConfig) -> dict:
    patch_path = BENCH / case["patch_file"]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f"lgtm-eval-{case['id']}-") as tmpdir:
        tmp = Path(tmpdir)
        build_case_repo(tmp, patch_path)
        if config.mode != "sast-only":
            index_repo_docs(tmp, config)
        pipeline = ReviewPipeline(tmp, config)
        result = pipeline.run("main", "pr", output_dir=None)
    latency = time.monotonic() - started

    findings = [f.model_dump(exclude={"raw_response"}) for f in result.findings]
    predicted = predict_case_verdict(findings, case["category"])
    expected = case["expected_verdict"]

    # Binary scoring: "did the tool flag this PR as vulnerable?"
    flagged = predicted == "vulnerable"
    is_vuln = expected == "vulnerable"
    outcome = (
        "TP" if flagged and is_vuln
        else "FN" if not flagged and is_vuln
        else "FP" if flagged and not is_vuln
        else "TN"
    )

    grounded = [f for f in findings if f.get("evidence_valid")]
    return {
        "id": case["id"],
        "category": case["category"],
        "expected": expected,
        "predicted": predicted,
        "outcome": outcome,
        "correct": outcome in ("TP", "TN"),
        "n_findings": len(findings),
        "verdicts": [f["verdict"] for f in findings],
        "grounded": len(grounded),
        "grounding_rate": round(len(grounded) / len(findings), 3) if findings else None,
        "latency_seconds": round(latency, 2),
        "est_tokens": estimate_tokens(findings, {}),
        "findings": findings,
    }


def summarize(results: list[dict]) -> dict:
    def metrics(rows: list[dict]) -> dict:
        tp = sum(1 for r in rows if r["outcome"] == "TP")
        fp = sum(1 for r in rows if r["outcome"] == "FP")
        fn = sum(1 for r in rows if r["outcome"] == "FN")
        tn = sum(1 for r in rows if r["outcome"] == "TN")
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision and recall
            else (0.0 if precision is not None and recall is not None else None)
        )
        safe_rows = [r for r in rows if r["expected"] == "safe"]
        fpr = (
            sum(1 for r in safe_rows if r["outcome"] == "FP") / len(safe_rows)
            if safe_rows
            else None
        )
        return {
            "cases": len(rows),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "false_positive_rate_on_safe": round(fpr, 3) if fpr is not None else None,
            "accuracy": round(
                sum(1 for r in rows if r["correct"]) / len(rows), 3
            ) if rows else None,
        }

    all_findings = [f for r in results for f in r["findings"]]
    grounded = sum(1 for f in all_findings if f.get("evidence_valid"))
    possible = sum(1 for r in results if r["predicted"] == "possible")
    insufficient = sum(1 for r in results if r["predicted"] == "insufficient_evidence")
    latencies = [r["latency_seconds"] for r in results]
    tokens = [r["est_tokens"] for r in results]

    return {
        "overall": metrics(results),
        "per_category": {
            cat: metrics([r for r in results if r["category"] == cat])
            for cat in sorted({r["category"] for r in results})
        },
        "evidence_grounding_rate": (
            round(grounded / len(all_findings), 3) if all_findings else None
        ),
        "possible_rate": round(possible / len(results), 3) if results else None,
        "insufficient_evidence_rate": (
            round(insufficient / len(results), 3) if results else None
        ),
        "median_latency_seconds": (
            round(statistics.median(latencies), 2) if latencies else None
        ),
        "median_est_tokens_per_pr": (
            int(statistics.median(tokens)) if tokens else None
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate LGTM on the benchmark")
    parser.add_argument(
        "--mode", choices=["lgtm", "sast-only", "llm-only"], default="lgtm"
    )
    parser.add_argument("--model", default=None, help="Ollama model override")
    parser.add_argument(
        "--cases", nargs="*", default=None, help="Subset of case ids to run"
    )
    parser.add_argument(
        "--output", default=None, help="Results dir (default benchmark/results/<mode>)"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    config = LGTMConfig()
    config.mode = args.mode
    if args.model:
        config.ollama_model = args.model

    labels = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))
    cases = labels["cases"]
    if args.cases:
        wanted = set(args.cases)
        cases = [c for c in cases if c["id"] in wanted]
        missing = wanted - {c["id"] for c in cases}
        if missing:
            parser.error(f"unknown case ids: {sorted(missing)}")

    out_dir = Path(args.output) if args.output else BENCH / "results" / args.mode
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    for i, case in enumerate(cases, 1):
        print(f"[{i}/{len(cases)}] {case['id']} ...", end=" ", flush=True)
        try:
            result = evaluate_case(case, config)
        except Exception as exc:  # noqa: BLE001 - one bad case must not kill the run
            print(f"ERROR: {exc}")
            result = {
                "id": case["id"],
                "category": case["category"],
                "expected": case["expected_verdict"],
                "predicted": "error",
                "outcome": "FN" if case["expected_verdict"] == "vulnerable" else "TN",
                "correct": case["expected_verdict"] != "vulnerable",
                "error": str(exc),
                "n_findings": 0, "verdicts": [], "grounded": 0,
                "grounding_rate": None, "latency_seconds": 0.0,
                "est_tokens": 0, "findings": [],
            }
        else:
            print(
                f"{result['outcome']} (expected {result['expected']}, "
                f"predicted {result['predicted']}, {result['latency_seconds']}s)"
            )
        results.append(result)
        (out_dir / f"{case['id']}.json").write_text(
            json.dumps(result, indent=2, default=str), encoding="utf-8"
        )

    summary = summarize(results)
    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps({"mode": args.mode, "model": config.ollama_model,
                    "summary": summary}, indent=2),
        encoding="utf-8",
    )

    print("\n=== Summary ===")
    print(json.dumps(summary, indent=2))
    print(f"\nResults written to {out_dir}")


if __name__ == "__main__":
    main()
