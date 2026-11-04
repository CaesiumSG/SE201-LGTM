#!/usr/bin/env python3
"""Real vulnerable PRs: does LGTM catch a vulnerability in the PR that introduced it?

Each case in ``cases.json`` is a merged change in an open-source Python web
project that introduced a vulnerability later published as a GitHub Security
Advisory. It is reviewed twice:

- ``<id>-vulnerable``: the introducing change (``introducing.base_commit`` ..
  ``introducing.merge_commit``); expected verdict ``vulnerable``.
- ``<id>-fixed``: the fix commit against its parent; expected ``safe``.

Unlike the real-world CVE benchmark (synthetic reverts of each fix), these are
the diffs the projects' maintainers actually reviewed and merged. Fetching,
indexing and the review itself reuse the field-trial harness; this script adds
the expected verdicts and the scoring.

A PR counts as flagged when any finding is ``vulnerable`` (in lgtm mode: the
Kev judge supported it and did not rule it not real). ``on_target`` also needs
a flagged finding in one of the files the advisory names.

Usage:
    python benchmark/real_prs/run_real_prs.py --fetch
    python benchmark/real_prs/run_real_prs.py --modes lgtm llm-only --gpu-model qwen3.8-27b
    python benchmark/real_prs/run_real_prs.py --modes lgtm --cases superset-where-in-sqli --resume
    python benchmark/real_prs/run_real_prs.py --summarize-only
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO_ROOT = BENCH.parent
CASES_FILE = HERE / "cases.json"

_spec = importlib.util.spec_from_file_location("lgtm_field_trial", BENCH / "field_trial" / "run_field_trial.py")
ft = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ft
_spec.loader.exec_module(ft)

MODES = ["lgtm", "llm-only", "sast-only"]


def load_cases(path: Path = CASES_FILE) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def expand(case: dict) -> list[dict]:
    """One advisory -> the introducing change (vulnerable) and the fix (safe)."""
    rows = []
    for side, expected in (("introducing", "vulnerable"), ("fix", "safe")):
        change = case[side]
        rows.append({
            "id": f"{case['id']}-{'vulnerable' if expected == 'vulnerable' else 'fixed'}",
            "advisory": case["id"],
            "repo": case["repo"],
            "pr": change.get("pr"),
            "url": change["url"],
            "title": case["title"],
            "category": case["category"],
            "cwe": case["cwe"],
            "ghsa": case["ghsa"],
            "expected": expected,
            "vulnerable_files": case["vulnerable_files"],
            "base_commit": change["base_commit"],
            "merge_commit": change["merge_commit"],
        })
    return rows


def score(row: dict, record: dict) -> dict:
    """Expected verdict, prediction and outcome, added to the field-trial record."""
    flagged = record.get("vulnerable_findings") or []
    on_target = any(f.get("file") in row["vulnerable_files"] for f in flagged)
    predicted = "vulnerable" if flagged else "safe"
    if record.get("crashed"):
        outcome = "ERROR"
    elif row["expected"] == "vulnerable":
        outcome = "TP" if flagged else "FN"
    else:
        outcome = "FP" if flagged else "TN"
    return {
        "advisory": row["advisory"], "url": row["url"], "category": row["category"],
        "cwe": row["cwe"], "ghsa": row["ghsa"], "expected": row["expected"],
        "vulnerable_files": row["vulnerable_files"],
        "predicted": None if outcome == "ERROR" else predicted,
        "outcome": outcome, "correct": None if outcome == "ERROR" else outcome in ("TP", "TN"),
        "on_target": on_target,
    }


def summarize(records: list[dict]) -> dict:
    n = {k: sum(1 for r in records if r.get("outcome") == k) for k in ("TP", "FP", "FN", "TN", "ERROR")}
    tp, fp, fn, tn = n["TP"], n["FP"], n["FN"], n["TN"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if precision == 0 or recall == 0 else None)
    lat = [r["latency_seconds"] for r in records if r.get("outcome") != "ERROR" and r.get("latency_seconds") is not None]
    return {
        "overall": {
            "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate_on_safe": fp / (fp + tn) if fp + tn else None,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "scored": tp + fp + fn + tn, "errors": n["ERROR"],
        },
        "vulnerable_caught_on_target": sum(1 for r in records if r.get("outcome") == "TP" and r.get("on_target")),
        "median_latency_seconds": round(statistics.median(lat), 1) if lat else None,
        "per_case": [
            {"id": r["id"], "outcome": r.get("outcome"), "on_target": r.get("on_target"),
             "n_findings": r.get("n_findings"), "latency_seconds": r.get("latency_seconds"), "error": r.get("error")}
            for r in records
        ],
    }


def write_summary(out_dir: Path, mode: str, records: list[dict], model: str) -> None:
    payload = {
        "mode": mode, "model": model if mode != "sast-only" else "none",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "git_commit": subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
                                     capture_output=True, text=True).stdout.strip() or "unknown",
        "summary": summarize(records),
    }
    (out_dir / "summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--modes", nargs="+", choices=MODES, default=["lgtm", "llm-only"])
    parser.add_argument("--cases", nargs="+", default=None, help="advisory ids from cases.json")
    parser.add_argument("--cache", type=Path, default=HERE / ".cache")
    parser.add_argument("--output", type=Path, default=BENCH / "results" / "real_prs")
    parser.add_argument("--model", default=None)
    parser.add_argument("--ollama-url", default=None)
    parser.add_argument("--gpu-model", choices=sorted(ft.GPU_MODELS), default=None,
                        help="use the GPU cluster tunnel with a registered model")
    parser.add_argument("--fetch", action="store_true", help="only fetch the clones")
    parser.add_argument("--resume", action="store_true", help="skip cases with a result JSON that did not crash")
    parser.add_argument("--summarize-only", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    ft.setup_logging(args.verbose)

    cases = load_cases()
    if args.cases:
        missing = set(args.cases) - {c["id"] for c in cases}
        if missing:
            parser.error(f"unknown case ids: {sorted(missing)}")
        cases = [c for c in cases if c["id"] in set(args.cases)]
    rows = [row for c in cases for row in expand(c)]
    if args.gpu_model and args.model:
        parser.error("--gpu-model cannot be combined with --model")
    config = ft.LGTMConfig()
    if args.gpu_model:
        ft.apply_gpu_model(config, args.gpu_model, args.ollama_url)
    if args.model:
        config.ollama_model = args.model
    if args.ollama_url:
        config.ollama_url = args.ollama_url
    cache = args.cache.resolve()

    if args.fetch:
        for row in rows:
            ft.ensure_case(row, cache)
        print(f"fetched {len(rows)} changes into {cache}")
        return 0

    for mode in args.modes:
        out_dir = args.output / mode
        out_dir.mkdir(parents=True, exist_ok=True)
        records: list[dict] = []
        for i, row in enumerate(rows, 1):
            path = out_dir / f"{row['id']}.json"
            stored = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
            if stored is not None and (args.summarize_only or (args.resume and stored.get("outcome") != "ERROR")):
                records.append(stored)
                continue
            if args.summarize_only:
                continue
            print(f"[{mode}] {i}/{len(rows)} {row['id']}", flush=True)
            try:
                record = ft.run_case(row, mode, cache, config)
            except ft.FetchError as exc:
                record = {"id": row["id"], "repo": row["repo"], "mode": mode, "crashed": True,
                          "error": f"FetchError: {exc}", "findings": []}
            record.update(score(row, record))
            record = ft.scrub(record, [str(cache)])
            path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            records.append(record)
            print(f"  -> {record['outcome']}{' (on target)' if record.get('on_target') else ''}, "
                  f"{record.get('n_findings', 0)} findings, {record.get('latency_seconds')} s", flush=True)
        write_summary(out_dir, mode, records, config.ollama_model)
        s = summarize(records)["overall"]
        print(f"[{mode}] TP {s['tp']} FP {s['fp']} FN {s['fn']} TN {s['tn']} errors {s['errors']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
