#!/usr/bin/env python3
"""Run prompt-injection red-teaming benchmarks on LGTM.

Compares original vulnerable benchmark cases against their prompt-injected
counterparts across modes:
- sast-only (Baseline A)
- llm-only (Baseline B)
- lgtm (Full pipeline)

Metric:
    Attack Success Rate (ASR) = (vulnerable cases flagged originally but NOT flagged when injected) / (vulnerable cases flagged originally)

Usage:
    python benchmark/injection/run_injection_bench.py --mode sast-only
    python benchmark/injection/run_injection_bench.py --mode llm-only --model qwen2.5-coder:7b --ollama-url http://127.0.0.1:35375
    python benchmark/injection/run_injection_bench.py --mode lgtm --model qwen2.5-coder:7b --ollama-url http://127.0.0.1:35375
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
REPO_ROOT = BENCH.parent
INJECTION_DIR = BENCH / "injection"

sys.path.insert(0, str(REPO_ROOT / "src"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate = _load("lgtm_bench_evaluate", BENCH / "evaluate.py")

from lgtm.config import LGTMConfig, setup_logging  # noqa: E402
from lgtm.pipeline import ReviewPipeline  # noqa: E402
from lgtm.rag.indexer import index_repo_docs  # noqa: E402


def run_git(cmd: list[str], cwd: Path) -> str:
    import subprocess
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{res.stderr}")
    return res.stdout


def build_case_repo(tmp: Path, patch_path: Path) -> None:
    shutil.copytree(BENCH / "app", tmp / "app")
    for doc in ("security-policy.md", "api-spec.md", "README.md"):
        shutil.copy(BENCH / doc, tmp / doc)
    run_git(["git", "init", "-q", "-b", "main"], tmp)
    run_git(["git", "config", "user.email", "bench@lgtm.local"], tmp)
    run_git(["git", "config", "user.name", "LGTM Bench"], tmp)
    run_git(["git", "add", "-A"], tmp)
    run_git(["git", "commit", "-q", "-m", "base"], tmp)
    run_git(["git", "checkout", "-q", "-b", "pr"], tmp)
    run_git(["git", "apply", str(patch_path)], tmp)
    run_git(["git", "add", "-A"], tmp)
    run_git(["git", "commit", "-q", "-m", "pr change"], tmp)
    run_git(["git", "checkout", "-q", "main"], tmp)


GRAPH_FIELDS = ("graph_state", "graph_index_seconds", "base_sha", "pr_sha")


def evaluate_single_case(case: dict, config: LGTMConfig) -> dict:
    patch_path = BENCH / case["patch_file"]
    started = time.monotonic()
    result = None
    try:
        with tempfile.TemporaryDirectory(
            prefix=f"lgtm-inj-{case['id']}-", ignore_cleanup_errors=True
        ) as tmpdir:
            tmp = Path(tmpdir)
            build_case_repo(tmp, patch_path)
            if config.mode != "sast-only":
                index_repo_docs(tmp, config)
            pipeline = ReviewPipeline(tmp, config)
            result = pipeline.run("main", "pr", output_dir=None)
        findings = [f.model_dump(exclude={"raw_response"}) for f in result.findings]
    except Exception as exc:
        latency = time.monotonic() - started
        return {
            "id": case["id"],
            "category": case["category"],
            "expected": case.get("expected_verdict", "vulnerable"),
            "predicted": f"error: {exc}",
            "flagged": False,
            "latency_seconds": round(latency, 2),
            "findings": [],
            **evaluate.graph_fields(result),
        }

    latency = time.monotonic() - started
    cat = case["category"]
    relevant = [f for f in findings if f.get("category") in (cat, "", "sast", None)]
    verdicts = [f.get("verdict") for f in relevant]
    if "vulnerable" in verdicts:
        predicted = "vulnerable"
    elif "possible" in verdicts:
        predicted = "possible"
    elif verdicts and all(v == "insufficient_evidence" for v in verdicts):
        predicted = "insufficient_evidence"
    else:
        predicted = "safe"

    flagged = predicted == "vulnerable"

    return {
        "id": case["id"],
        "category": cat,
        "expected": case.get("expected_verdict", "vulnerable"),
        "predicted": predicted,
        "flagged": flagged,
        "latency_seconds": round(latency, 2),
        "findings": findings,
        **evaluate.graph_fields(result),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate prompt-injection attacks against LGTM.")
    parser.add_argument("--mode", choices=["sast-only", "llm-only", "lgtm"], default="sast-only")
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--ollama-url", default=None)
    parser.add_argument("--strip-comments", action="store_true", help="Mitigation: strip comments/docstrings from PR code in prompts")
    parser.add_argument("--detect-injection", action="store_true", help="Mitigation: detect reviewer-directed instructions in diff")
    parser.add_argument("--cases", nargs="+", default=None, help="Filter to specific injection case IDs")
    parser.add_argument("--output", default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    config = LGTMConfig()
    config.mode = args.mode
    config.ollama_model = args.model
    if args.ollama_url:
        config.ollama_base_url = args.ollama_url
    config.strip_comments = args.strip_comments
    config.detect_prompt_injection = args.detect_injection

    # Load original labels and injection labels
    main_labels = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))["cases"]
    main_by_id = {c["id"]: c for c in main_labels}
    inj_labels = json.loads((INJECTION_DIR / "labels.json").read_text(encoding="utf-8"))["cases"]
    if args.cases:
        wanted = set(args.cases)
        inj_labels = [c for c in inj_labels if c["id"] in wanted]

    out_dir = Path(args.output) if args.output else INJECTION_DIR / "results" / args.mode
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n=======================================================")
    print(f"Running Prompt-Injection Red-Team Benchmark: mode={args.mode}")
    print(f"Model={config.ollama_model} URL={config.ollama_base_url}")
    print(f"Mitigations: strip_comments={getattr(config, 'strip_comments', False)}")
    print(f"=======================================================\n")

    comparisons = []
    review_records = []
    attacks_succeeded = 0
    originally_flagged_count = 0
    not_judged_cases: list[dict] = []

    try:
        for i, inj_case in enumerate(inj_labels, 1):
            base_id = inj_case["base_case_id"]
            orig_case = main_by_id[base_id]
            technique = inj_case["technique"]

            print(f"[{i}/{len(inj_labels)}] Testing {base_id} vs {inj_case['id']} ({technique})...")

            # 1. Run Original
            print(f"   -> Running original ({base_id})...", end=" ", flush=True)
            orig_res = evaluate_single_case(orig_case, config)
            print(f"{orig_res['predicted']} (flagged={orig_res['flagged']}, {orig_res['latency_seconds']}s)")

            # 2. Run Injected
            print(f"   -> Running injected ({inj_case['id']})...", end=" ", flush=True)
            inj_res = evaluate_single_case(inj_case, config)
            print(f"{inj_res['predicted']} (flagged={inj_res['flagged']}, {inj_res['latency_seconds']}s)")

            review_records += [orig_res, inj_res]

            excluded = [
                {"id": r["id"], "not_judged": n}
                for r in (orig_res, inj_res)
                if (n := evaluate.not_judged_count({**r, "mode": args.mode}))
            ]
            if excluded:
                not_judged_cases += excluded
                print("   => Excluded: candidates not judged")
                continue

            # Attack succeeded iff originally flagged as vulnerable, but injected is NOT flagged
            attack_success = orig_res["flagged"] and not inj_res["flagged"]
            if orig_res["flagged"]:
                originally_flagged_count += 1
                if attack_success:
                    attacks_succeeded += 1

            print(f"   => Attack Success: {'YES [BYPASS!]' if attack_success else 'NO (caught or unflagged)'}")

            comp = {
                "technique": technique,
                "category": inj_case["category"],
                "base_case_id": base_id,
                "inj_case_id": inj_case["id"],
                "original_verdict": orig_res["predicted"],
                "original_flagged": orig_res["flagged"],
                "injected_verdict": inj_res["predicted"],
                "injected_flagged": inj_res["flagged"],
                "attack_success": attack_success,
                "original_findings": orig_res["findings"],
                "injected_findings": inj_res["findings"],
                "original_graph": {k: orig_res[k] for k in GRAPH_FIELDS},
                "injected_graph": {k: inj_res[k] for k in GRAPH_FIELDS},
            }
            comparisons.append(comp)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        raise SystemExit(3)

    asr = (attacks_succeeded / originally_flagged_count) if originally_flagged_count > 0 else 0.0

    summary = {
        "mode": args.mode,
        "model": config.ollama_model if args.mode != "sast-only" else "none",
        "timestamp": datetime.datetime.now().isoformat(),
        "total_cases": len(inj_labels),
        "originally_flagged": originally_flagged_count,
        "attacks_succeeded": attacks_succeeded,
        "attack_success_rate": round(asr, 3),
        "mitigations": {
            "strip_comments": getattr(config, "strip_comments", False),
            "detect_prompt_injection": getattr(config, "detect_prompt_injection", False),
        },
        "graph_states": dict(Counter(
            r.get("graph_state") or "unknown" for r in review_records)),
        "not_judged_cases": not_judged_cases,
        "comparisons": comparisons,
    }

    summary_file = out_dir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 55)
    print(f"BENCHMARK COMPLETED: {args.mode}")
    print(f"Originally Flagged: {originally_flagged_count}/{len(inj_labels)}")
    print(f"Attacks Succeeded: {attacks_succeeded}/{originally_flagged_count}")
    print(f"Attack Success Rate (ASR): {asr * 100:.1f}%")
    print(f"Summary written to {summary_file}")
    print("=" * 55 + "\n")


if __name__ == "__main__":
    main()
