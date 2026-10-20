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
from collections import Counter
from pathlib import Path

BENCH = Path(__file__).resolve().parent
REPO_ROOT = BENCH.parent

sys.path.insert(0, str(REPO_ROOT / "src"))

from lgtm.config import GPU_MODELS, LGTMConfig, apply_gpu_model, setup_logging  # noqa: E402
from lgtm.pipeline import ReviewPipeline  # noqa: E402
from lgtm.rag.indexer import index_repo_docs  # noqa: E402
from lgtm.review.coverage import location_overlaps  # noqa: E402

ERROR = "ERROR"
INFRA_PREFIXES = ("Agent execution failed", "LLM call failed", "Agent did not produce parsable")


def infra_failure_ids(findings: list[dict]) -> list[str]:
    return [
        f.get("finding_id") or "unknown"
        for f in findings
        if str(f.get("explanation", "")).startswith(INFRA_PREFIXES)
        or f.get("finding_id") == "plain:unparsable"
    ]


def result_is_error(result: dict) -> bool:
    return (
        result.get("predicted") == "error"
        or result.get("outcome") == ERROR
        or bool(result.get("error"))
        or (result.get("infra_failures") or 0) > 0
        or (not isinstance(result.get("coverage"), dict)
            and bool(infra_failure_ids(result.get("findings") or [])))
    )


def mark_error(result: dict, message: str) -> dict:
    result.update(
        predicted="error",
        predicted_grounded="error",
        outcome=ERROR,
        outcome_grounded=ERROR,
        correct=None,
        error=message,
        case_label="scan_failure",
        case_label_grounded="scan_failure",
    )
    return result


def graph_fields(review=None) -> dict:
    # Metadata from reviews made before these fields existed lacks the attributes.
    meta = getattr(review, "meta", None)
    return {
        "graph_state": getattr(meta, "graph_state", None),
        "graph_index_seconds": getattr(meta, "graph_index_seconds", None),
        "base_sha": getattr(meta, "base_sha", ""),
        "pr_sha": getattr(meta, "pr_sha", ""),
    }


def error_record(case: dict, review=None) -> dict:
    return {
        "id": case["id"],
        "category": case["category"],
        "split": case.get("split", "eval"),
        "expected": case["expected_verdict"],
        "n_findings": 0, "verdicts": [], "grounded": 0,
        "grounding_rate": None, "latency_seconds": 0.0,
        "est_tokens": 0, "findings": [],
        **graph_fields(review),
    }


def load_result(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def is_done(path: Path) -> bool:
    data = load_result(path)
    return (
        data is not None
        and not result_is_error(data)
        and data.get("case_label") != "scan_failure"
    )


def write_run_manifest(out_dir: Path, manifest: dict, resume: bool, parser) -> None:
    path = out_dir / "run.json"
    previous = load_result(path)
    if resume and previous is not None:
        if (previous.get("model"), previous.get("reasoning")) != (
            manifest.get("model"), manifest.get("reasoning")
        ):
            parser.error(
                f"--resume: {out_dir} was produced with a different model or reasoning setting"
            )
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")


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


PREDICTED_BY_LABEL = {
    "detected_vulnerability": "vulnerable",
    "possible_vulnerability": "possible",
    "insufficient_evidence": "insufficient_evidence",
    "explicit_safe": "safe",
}


def outcome_for_label(label: str, expected: str) -> str:
    if expected == "vulnerable":
        return "TP" if label == "detected_vulnerability" else "FN"
    if label == "detected_vulnerability":
        return "FP"
    if label == "explicit_safe":
        return "TN"
    if label in ("missing_review", "scan_failure"):
        return "EXCLUDED"
    return "UNCREDITED"


def _relevant_verdicts(row: dict, grounded: bool = False) -> list:
    verdicts = []
    for f in row.get("findings", []):
        if f.get("category") not in (row["category"], "", "sast", None):
            continue
        verdict = f.get("verdict")
        if grounded and verdict == "vulnerable" and not f.get("evidence_valid"):
            verdict = "possible"
        verdicts.append(verdict)
    return verdicts


def _verdict_label(verdicts: list, missing_review: bool = False) -> str:
    if "vulnerable" in verdicts:
        return "detected_vulnerability"
    if missing_review:
        return "missing_review"
    if "possible" in verdicts:
        return "possible_vulnerability"
    if verdicts and all(v == "insufficient_evidence" for v in verdicts):
        return "insufficient_evidence"
    return "explicit_safe"


def _findings_label(verdicts: list) -> str:
    return _verdict_label(verdicts) if verdicts else "no_candidate"


def _target_sections(row: dict, sections: list[dict]) -> list[dict]:
    locations = row.get("vulnerable_locations") or [
        {"file": row.get("file"), "old_range": None, "new_range": None}
    ]
    overlapping = [
        s for s in sections
        if any(location_overlaps(h, loc) for h in s["hunks"] for loc in locations)
    ]
    if overlapping:
        return overlapping
    files = {loc["file"] for loc in locations} | {row.get("file")}
    return [s for s in sections if any(h["file"] in files for h in s["hunks"])]


def _scan_failed(cov: dict) -> bool:
    scheduled = cov["sections_scheduled"]
    return (scheduled > 0 and cov["sections_completed"] == 0) or (
        bool(cov.get("investigator_error")) and scheduled == 0
    )


def derive_case_labels(row: dict) -> tuple[str, str, list[str], bool]:
    """Return (label, grounded_label, target_section_ids, coverage_gap)."""
    if "coverage" not in row:
        return (
            _findings_label(_relevant_verdicts(row)),
            _findings_label(_relevant_verdicts(row, grounded=True)),
            [],
            False,
        )
    cov = row["coverage"]
    if cov is None:
        return "scan_failure", "scan_failure", [], False
    targets = _target_sections(row, cov["sections"])
    target_ids = [s["section_id"] for s in targets]
    if _scan_failed(cov):
        return "scan_failure", "scan_failure", target_ids, False
    if not targets:
        return "no_candidate", "no_candidate", target_ids, False
    missing = any(s["status"] != "completed" for s in targets)
    label = _verdict_label(_relevant_verdicts(row), missing)
    grounded_label = _verdict_label(_relevant_verdicts(row, grounded=True), missing)
    gap = label == "detected_vulnerability" and (
        not cov["complete"] or cov["sections_failed"] > 0 or cov["hunks_leftover"] > 0
    )
    return label, grounded_label, target_ids, gap


def score_case(result: dict) -> dict:
    """(Re)compute predictions and outcomes from a result's findings."""
    findings = result.get("findings", [])
    legacy = "pin" not in result
    ids = [] if isinstance(result.get("coverage"), dict) else infra_failure_ids(findings)
    result["infra_failures"], result["infra_failure_ids"] = len(ids), ids
    if legacy:
        result["legacy"] = True
    if result_is_error(result):
        message = result.get("error") or (
            "infra failure: " + ", ".join(ids) if ids else "unknown error")
        mark_error(result, message)
        if not legacy:
            result.update(target_sections=[], coverage_gap=False)
    elif legacy:
        result["predicted"] = predict_case_verdict(findings, result["category"])
        result["outcome"] = outcome_for(result["predicted"], result["expected"])
        result["correct"] = result["outcome"] in ("TP", "TN")
        result["predicted_grounded"] = predict_case_verdict(
            findings, result["category"], require_grounded=True
        )
        result["outcome_grounded"] = outcome_for(
            result["predicted_grounded"], result["expected"]
        )
    else:
        label, grounded_label, targets, gap = derive_case_labels(result)
        outcome = outcome_for_label(label, result["expected"])
        result.update(
            case_label=label,
            case_label_grounded=grounded_label,
            target_sections=targets,
            coverage_gap=gap,
            predicted=PREDICTED_BY_LABEL.get(label, label),
            predicted_grounded=PREDICTED_BY_LABEL.get(grounded_label, grounded_label),
            outcome=outcome,
            outcome_grounded=outcome_for_label(grounded_label, result["expected"]),
            correct=outcome in ("TP", "TN"),
        )
    if legacy:
        result.update(case_label=None, case_label_grounded=None)
    return result


def evaluate_case(case: dict, config: LGTMConfig) -> dict:
    patch_path = BENCH / case["patch_file"]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(
        prefix=f"lgtm-eval-{case['id']}-", ignore_cleanup_errors=True
    ) as tmpdir:
        tmp = Path(tmpdir)
        build_case_repo(tmp, patch_path)
        if config.mode != "sast-only":
            index_repo_docs(tmp, config)
        pipeline = ReviewPipeline(tmp, config)
        result = pipeline.run("main", "pr", output_dir=None)
    latency = time.monotonic() - started

    try:
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
            **graph_fields(result),
        })
    except Exception as exc:  # noqa: BLE001 - a post-review failure keeps the review's metadata
        return mark_error(error_record(case, result), str(exc))


def coverage_summary(results: list[dict]) -> dict:
    scored = [r for r in results if not result_is_error(r)]
    covs = [r["coverage"] for r in scored if isinstance(r.get("coverage"), dict)]
    complete = sum(1 for c in covs if c.get("complete"))

    def total(field: str) -> int:
        return sum(c.get(field) or 0 for c in covs)

    return {
        "rows": len(covs),
        "complete": complete,
        "complete_rate": round(complete / len(covs), 3) if covs else None,
        "sections_scheduled": total("sections_scheduled"),
        "sections_completed": total("sections_completed"),
        "sections_failed": total("sections_failed"),
        "sections_coalesced": total("sections_coalesced"),
        "hunks_total": total("hunks_total"),
        "hunks_reviewed": total("hunks_reviewed"),
        "hunks_leftover": total("hunks_leftover"),
        "invalid_refs": sum(len(c.get("invalid_refs") or []) for c in covs),
        "planners": dict(Counter(c.get("planner") or "unknown" for c in covs)),
        "investigator_status": dict(Counter(
            c.get("investigator_status") or "unknown" for c in covs)),
        "detected_with_gap": sum(
            1 for r in scored
            if r.get("case_label") == "detected_vulnerability" and r.get("coverage_gap")
        ),
    }


def summarize(results: list[dict]) -> dict:
    def metrics(
        rows: list[dict], key: str = "outcome", label_key: str = "case_label"
    ) -> dict:
        scored_rows = [r for r in rows if not result_is_error(r)]
        errors = len(rows) - len(scored_rows)
        tp = sum(1 for r in scored_rows if r[key] == "TP")
        fp = sum(1 for r in scored_rows if r[key] == "FP")
        fn = sum(1 for r in scored_rows if r[key] == "FN")
        tn = sum(1 for r in scored_rows if r[key] == "TN")
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        if precision and recall:
            f1 = 2 * precision * recall / (precision + recall)
        elif tp + fn:
            f1 = 0.0  # positives exist but none were detected
        else:
            f1 = None
        safe_rows = [
            r for r in scored_rows
            if r["expected"] == "safe" and r[key] != "EXCLUDED"
        ]
        excluded_on_safe = sum(
            1 for r in scored_rows
            if r["expected"] == "safe" and r[key] == "EXCLUDED"
        )
        fpr = (
            sum(1 for r in safe_rows if r[key] == "FP") / len(safe_rows)
            if safe_rows
            else None
        )
        counted = len(scored_rows) - excluded_on_safe
        return {
            "cases": len(rows),
            "scored": len(scored_rows),
            "errors": errors,
            "error_rate": round(errors / len(rows), 3) if rows else None,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 3) if precision is not None else None,
            "recall": round(recall, 3) if recall is not None else None,
            "f1": round(f1, 3) if f1 is not None else None,
            "false_positive_rate_on_safe": round(fpr, 3) if fpr is not None else None,
            "accuracy": round((tp + tn) / counted, 3) if counted else None,
            "vulnerable_scored": sum(
                1 for r in scored_rows if r["expected"] == "vulnerable"),
            "safe_scored": len(safe_rows),
            "abstentions": sum(
                1 for r in scored_rows
                if r.get(label_key) in ("insufficient_evidence", "possible_vulnerability")
            ),
            "possible_on_safe": sum(
                1 for r in safe_rows if r.get(label_key) == "possible_vulnerability"),
            "excluded_on_safe": excluded_on_safe,
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

    scored: list[dict] = []
    errs: list[dict] = []
    for r in results:
        (errs if result_is_error(r) else scored).append(r)
    all_findings = [f for r in scored for f in r["findings"]]
    grounded = sum(1 for f in all_findings if f.get("evidence_valid"))
    possible = sum(1 for r in scored if r["predicted"] == "possible")
    insufficient = sum(1 for r in scored if r["predicted"] == "insufficient_evidence")
    latencies = [r["latency_seconds"] for r in scored]
    tokens = [r["est_tokens"] for r in scored]

    def by(field: str, key: str = "outcome", label_key: str = "case_label") -> dict:
        return {
            val: metrics([r for r in results if r.get(field) == val], key, label_key)
            for val in sorted({r.get(field) for r in results if r.get(field)})
        }

    return {
        "overall": metrics(results),
        "per_category": by("category"),
        "per_split": by("split"),
        "graph_states": dict(Counter(
            r.get("graph_state") or "unknown" for r in results)),
        # Same scoring, but a "vulnerable" verdict only counts as a detection
        # when the evidence validator accepted its citations.
        "grounded_only": {
            "overall": metrics(results, "outcome_grounded", "case_label_grounded"),
            "per_category": by("category", "outcome_grounded", "case_label_grounded"),
            "per_split": by("split", "outcome_grounded", "case_label_grounded"),
        },
        "scored": len(scored),
        "errors": len(errs),
        "error_rate": round(len(errs) / len(results), 3) if results else None,
        "error_cases": [
            {"id": r["id"], "error": str(r.get("error") or "")[:300]}
            for r in sorted(errs, key=lambda r: r["id"])
        ],
        "off_category_alarm_rate": (
            round(sum(1 for r in scored if off_category(r)) / len(scored), 3)
            if scored else None
        ),
        "off_category_alarms": sorted(r["id"] for r in scored if off_category(r)),
        "evidence_grounding_rate": (
            round(grounded / len(all_findings), 3) if all_findings else None
        ),
        "possible_rate": round(possible / len(scored), 3) if scored else None,
        "insufficient_evidence_rate": (
            round(insufficient / len(scored), 3) if scored else None
        ),
        "median_latency_seconds": (
            round(statistics.median(latencies), 2) if latencies else None
        ),
        "median_est_tokens_per_pr": (
            int(statistics.median(tokens)) if tokens else None
        ),
        "case_labels": dict(Counter(r.get("case_label") or "legacy" for r in results)),
        "legacy_rows": sum(1 for r in results if not r.get("case_label")),
        "coverage": coverage_summary(results),
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
        "--ollama-url", default=None, help="Ollama base URL override"
    )
    parser.add_argument(
        "--gpu-cluster", action="store_true",
        help="Use the existing GPU cluster tunnel at http://127.0.0.1:11435 "
        "with qwen3.8:27b. Does not start the server or tunnel.",
    )
    parser.add_argument(
        "--gpu-model", choices=sorted(GPU_MODELS), default=None,
        help="Use the GPU cluster tunnel with a registered model (thinking off). "
        "Cannot be combined with --gpu-cluster or --model.",
    )
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
        "--labels",
        default=None,
        help="Path to labels.json (default: benchmark/labels.json)",
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
        "--strip-comments", action="store_true",
        help="Mitigation: strip comments and docstrings from PR code in prompts.",
    )
    parser.add_argument(
        "--detect-prompt-injection", action="store_true",
        help="Mitigation: detect reviewer-directed instructions in diff.",
    )
    parser.add_argument(
        "--rescore",
        action="store_true",
        help="Do not run the pipeline; re-score the per-case JSON files "
        "already in the results dir with the current scoring rules.",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="skip cases with a completed (non-error) result JSON; re-run error results",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    if args.gpu_model and (args.gpu_cluster or args.model):
        parser.error("--gpu-model cannot be combined with --gpu-cluster or --model")
    if args.resume and args.rescore:
        parser.error("--resume cannot be combined with --rescore")

    setup_logging(args.verbose)

    config = LGTMConfig()
    config.mode = args.mode
    if args.gpu_model:
        apply_gpu_model(config, args.gpu_model, args.ollama_url)
    if args.gpu_cluster:
        config.ollama_model = "qwen3.8:27b"
        config.ollama_base_url = "http://127.0.0.1:11435"
    if args.model:
        config.ollama_model = args.model
    if args.ollama_url:
        config.ollama_base_url = args.ollama_url
    config.require_tool_use = args.require_tool_use
    config.static_facts = args.static_facts
    config.authz_role_guidance = args.authz_role_guidance
    config.strip_comments = args.strip_comments
    config.detect_prompt_injection = args.detect_prompt_injection

    labels_path = Path(args.labels) if args.labels else BENCH / "labels.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
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

    write_run_manifest(
        out_dir,
        {"model": config.ollama_model, "ollama_base_url": config.ollama_base_url,
         "reasoning": config.reasoning, "mode": config.mode},
        args.resume, parser,
    )

    try:
        for i, case in enumerate(cases, 1):
            path = out_dir / f"{case['id']}.json"
            if args.resume and is_done(path):
                print(f"[{i}/{len(cases)}] {case['id']} skipped (already scored)")
                continue
            print(f"[{i}/{len(cases)}] {case['id']} ...", end=" ", flush=True)
            try:
                result = evaluate_case(case, config)
            except Exception as exc:  # noqa: BLE001 - one bad case must not kill the run
                result = mark_error(error_record(case), str(exc))
            if result_is_error(result):
                print(f"ERROR: {result['error']}")
            else:
                print(
                    f"{result['outcome']} (expected {result['expected']}, "
                    f"predicted {result['predicted']}, {result['latency_seconds']}s)"
                )
            path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(3)

    results = [
        r for c in cases
        if (r := load_result(out_dir / f"{c['id']}.json")) is not None
    ]
    model = config.ollama_model if args.mode != "sast-only" else "none"
    write_summary(
        out_dir, results, args.mode, model,
        {"split": args.split, "reasoning": config.reasoning,
         "cases_expected": len(cases), "experiments": {
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
        "outcomes": {
            r["id"]: ERROR if result_is_error(r) else r["outcome"] for r in results
        },
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
        result = score_case(result)
        path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        results.append(result)

    payload = {k: v for k, v in old.items() if k not in ("outcomes", "summary")}
    payload.setdefault("cases_expected", len(cases))
    payload.setdefault("mode", mode)
    payload.setdefault("model", "none" if mode == "sast-only" else "unknown")
    payload.pop("rescored_from_run_at", None)  # superseded key from earlier versions
    payload["rescored_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    payload["rescored_at_commit"] = git_commit()
    _write_payload(out_dir, results, payload)


if __name__ == "__main__":
    main()
