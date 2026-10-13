#!/usr/bin/env python3
"""LGTM benchmark evaluation harness.

For every case in labels.json:
1. Copy the benchmark app + policy docs into a temp git repo (base branch).
2. Apply the case patch on a ``pr`` branch and commit it.
3. Index the docs and run the LGTM pipeline in the chosen mode.
4. Score the predicted verdict against ground truth.

Metrics: precision / recall / F1 (overall, per category, and per dev/eval
split), false-positive rate on safe controls, evidence grounding rate,
"grounded" metrics that only count a detection when its evidence validated,
possible- and insufficient-evidence rates, median latency, and estimated
tokens per PR.

Usage:
    python benchmark/evaluate.py --mode lgtm
    python benchmark/evaluate.py --mode sast-only --cases sqli_01_vulnerable
    python benchmark/evaluate.py --mode lgtm --rescore   # re-score saved run
"""

from __future__ import annotations

import argparse
import datetime
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


def predict_case_verdict(
    findings: list[dict], category: str, require_grounded: bool = False
) -> str:
    """Collapse per-finding verdicts into one case-level prediction.

    Only findings of the case's own category count (a case tests one task);
    uncategorized findings count for either. With ``require_grounded``, a
    "vulnerable" finding only counts if its evidence passed validation —
    an ungrounded accusation is treated as "possible".
    """
    relevant = [
        f for f in findings
        if f.get("category") in (category, "", "sast", None)
    ]
    if require_grounded:
        relevant = [
            {**f, "verdict": "possible"}
            if f.get("verdict") == "vulnerable" and not f.get("evidence_valid")
            else f
            for f in relevant
        ]
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


def outcome_for(predicted: str, expected: str) -> str:
    """Binary scoring: did the tool flag this PR as vulnerable?"""
    flagged = predicted == "vulnerable"
    is_vuln = expected == "vulnerable"
    return (
        "TP" if flagged and is_vuln
        else "FN" if not flagged and is_vuln
        else "FP" if flagged and not is_vuln
        else "TN"
    )


def score_case(result: dict) -> dict:
    """(Re)compute predictions and outcomes from a result's findings."""
    findings = result["findings"]
    result["predicted"] = predict_case_verdict(findings, result["category"])
    result["outcome"] = outcome_for(result["predicted"], result["expected"])
    result["correct"] = result["outcome"] in ("TP", "TN")
    result["predicted_grounded"] = predict_case_verdict(
        findings, result["category"], require_grounded=True
    )
    result["outcome_grounded"] = outcome_for(
        result["predicted_grounded"], result["expected"]
    )
    return result


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
    grounded = [f for f in findings if f.get("evidence_valid")]
    return score_case({
        "id": case["id"],
        "category": case["category"],
        "split": case.get("split", "eval"),
        "expected": case["expected_verdict"],
        "n_findings": len(findings),
        "verdicts": [f["verdict"] for f in findings],
        "grounded": len(grounded),
        "grounding_rate": round(len(grounded) / len(findings), 3) if findings else None,
        "latency_seconds": round(latency, 2),
        "est_tokens": estimate_tokens(findings, {}),
        "findings": findings,
    })


def summarize(results: list[dict]) -> dict:
    def metrics(rows: list[dict], key: str = "outcome") -> dict:
        tp = sum(1 for r in rows if r[key] == "TP")
        fp = sum(1 for r in rows if r[key] == "FP")
        fn = sum(1 for r in rows if r[key] == "FN")
        tn = sum(1 for r in rows if r[key] == "TN")
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        if precision and recall:
            f1 = 2 * precision * recall / (precision + recall)
        elif tp + fn:
            f1 = 0.0  # positives exist but none were detected
        else:
            f1 = None
        safe_rows = [r for r in rows if r["expected"] == "safe"]
        fpr = (
            sum(1 for r in safe_rows if r[key] == "FP") / len(safe_rows)
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
            "accuracy": round((tp + tn) / len(rows), 3) if rows else None,
        }

    def off_category(r: dict) -> bool:
        # A "vulnerable" verdict in the category the case does NOT test. The
        # benchmark PRs are single-flaw, so these are unlabelled (and, on
        # inspection, spurious) alarms that case-level scoring cannot see.
        return any(
            f.get("verdict") == "vulnerable"
            and f.get("category") not in (r["category"], "", "sast", None)
            for f in r["findings"]
        )

    all_findings = [f for r in results for f in r["findings"]]
    grounded = sum(1 for f in all_findings if f.get("evidence_valid"))
    possible = sum(1 for r in results if r["predicted"] == "possible")
    insufficient = sum(1 for r in results if r["predicted"] == "insufficient_evidence")
    latencies = [r["latency_seconds"] for r in results]
    tokens = [r["est_tokens"] for r in results]

    def by(field: str, key: str = "outcome") -> dict:
        return {
            val: metrics([r for r in results if r.get(field) == val], key)
            for val in sorted({r.get(field) for r in results if r.get(field)})
        }

    return {
        "overall": metrics(results),
        "per_category": by("category"),
        "per_split": by("split"),
        # Same scoring, but a "vulnerable" verdict only counts as a detection
        # when the evidence validator accepted its citations.
        "grounded_only": {
            "overall": metrics(results, "outcome_grounded"),
            "per_category": by("category", "outcome_grounded"),
            "per_split": by("split", "outcome_grounded"),
        },
        "off_category_alarm_rate": (
            round(sum(1 for r in results if off_category(r)) / len(results), 3)
            if results else None
        ),
        "off_category_alarms": sorted(r["id"] for r in results if off_category(r)),
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
        "--mode",
        choices=["lgtm", "sast-only", "llm-only", "lgtm-no-sast"],
        default="lgtm",
    )
    parser.add_argument("--model", default=None, help="Ollama model override")
    parser.add_argument(
        "--cases", nargs="*", default=None, help="Subset of case ids to run"
    )
    parser.add_argument(
        "--split",
        choices=["dev", "eval", "all"],
        default="all",
        help="Run only the development set, the held-out evaluation set, "
        "or everything (default). Tune on dev; report on eval.",
    )
    parser.add_argument(
        "--output", default=None, help="Results dir (default benchmark/results/<mode>)"
    )
    parser.add_argument(
        "--require-tool-use", action="store_true",
        help="Experiment: push back once when an agent answers without tools.",
    )
    parser.add_argument(
        "--static-facts", action="store_true",
        help="Experiment: give agents deterministic AST facts + triage policy context.",
    )
    parser.add_argument(
        "--authz-role-guidance", action="store_true",
        help="Experiment: role-scope guidance in the authz prompt.",
    )
    parser.add_argument(
        "--rescore",
        action="store_true",
        help="Do not run the pipeline; re-score the per-case JSON files "
        "already in the results dir with the current scoring rules.",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    config = LGTMConfig()
    config.mode = args.mode
    if args.model:
        config.ollama_model = args.model
    config.require_tool_use = args.require_tool_use
    config.static_facts = args.static_facts
    config.authz_role_guidance = args.authz_role_guidance

    labels = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))
    cases = labels["cases"]
    if args.split != "all":
        cases = [c for c in cases if c.get("split", "eval") == args.split]
    if args.cases:
        wanted = set(args.cases)
        cases = [c for c in cases if c["id"] in wanted]
        missing = wanted - {c["id"] for c in cases}
        if missing:
            parser.error(f"unknown case ids: {sorted(missing)}")

    suffix = f"-{args.split}" if args.split != "all" else ""
    out_dir = (
        Path(args.output) if args.output else BENCH / "results" / f"{args.mode}{suffix}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.rescore:
        rescore(out_dir, cases, args.mode)
        return

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
                "split": case.get("split", "eval"),
                "expected": case["expected_verdict"],
                "predicted": "error",
                "outcome": "FN" if case["expected_verdict"] == "vulnerable" else "TN",
                "correct": case["expected_verdict"] != "vulnerable",
                "predicted_grounded": "error",
                "outcome_grounded": (
                    "FN" if case["expected_verdict"] == "vulnerable" else "TN"
                ),
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

    model = config.ollama_model if args.mode != "sast-only" else "none"
    write_summary(
        out_dir, results, args.mode, model,
        {"split": args.split, "experiments": {
            "require_tool_use": config.require_tool_use,
            "static_facts": config.static_facts,
            "authz_role_guidance": config.authz_role_guidance,
        }},
    )


def git_commit() -> str:
    try:
        return run(["git", "rev-parse", "--short", "HEAD"], REPO_ROOT).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def write_summary(
    out_dir: Path, results: list[dict], mode: str, model: str, extra: dict | None = None
) -> None:
    payload = {
        "mode": mode,
        "model": model,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "git_commit": git_commit(),
        **(extra or {}),
    }
    _write_payload(out_dir, results, payload)


def _write_payload(out_dir: Path, results: list[dict], payload: dict) -> None:
    summary = summarize(results)
    payload = {
        **payload,
        "outcomes": {r["id"]: r["outcome"] for r in results},
        "summary": summary,
    }
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("\n=== Summary ===")
    print(json.dumps(summary, indent=2))
    print(f"\nResults written to {out_dir}")


def rescore(out_dir: Path, cases: list[dict], mode: str) -> None:
    """Re-apply the current scoring rules to a saved run.

    Run provenance (model, generation time and commit, split, experiment
    flags) is kept from the existing summary; the rescoring time and commit
    are recorded separately. Rescoring a subset of a saved run is refused,
    because it would overwrite the full summary with a partial one.
    """
    old: dict = {}
    if (out_dir / "summary.json").exists():
        old = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    selected = {c["id"] for c in cases if (out_dir / f"{c['id']}.json").exists()}
    saved = set(old.get("outcomes", {}))
    if saved and selected != saved:
        raise SystemExit(
            f"refusing to rescore {out_dir}: the selected cases ({len(selected)}) "
            f"differ from the saved run ({len(saved)}). Match the run's "
            "--split/--cases, or rescore into a copy."
        )

    results = []
    for case in cases:
        path = out_dir / f"{case['id']}.json"
        if not path.exists():
            print(f"skip {case['id']}: no saved result")
            continue
        result = json.loads(path.read_text(encoding="utf-8"))
        result["split"] = case.get("split", "eval")
        if result.get("predicted") == "error":
            # Error results saved before grounded scoring existed
            result.setdefault("predicted_grounded", "error")
            result.setdefault("outcome_grounded", result["outcome"])
        else:
            result = score_case(result)
        path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        results.append(result)

    payload = {k: v for k, v in old.items() if k not in ("outcomes", "summary")}
    payload.setdefault("mode", mode)
    payload.setdefault("model", "none" if mode == "sast-only" else "unknown")
    payload.pop("rescored_from_run_at", None)  # superseded key from earlier versions
    payload["rescored_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    payload["rescored_at_commit"] = git_commit()
    _write_payload(out_dir, results, payload)


if __name__ == "__main__":
    main()
