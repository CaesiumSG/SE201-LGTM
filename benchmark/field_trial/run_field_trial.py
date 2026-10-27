#!/usr/bin/env python3
"""Field trial: run LGTM on ordinary merged PRs from real open-source projects.

The synthetic (Shoply) and real-world CVE benchmarks measure accuracy on
PRs known to be vulnerable or safe. This harness measures what a user would
see on everyday traffic: does the tool run, how long does it take, and how
many findings does it raise on PRs that were reviewed and merged by the
projects' maintainers (so every ``vulnerable`` verdict is a probable false
alarm until a human says otherwise).

Each case is one merged PR, identified by its merge commit. The PR is the
diff ``merge^1..merge`` (the first parent of the merge commit is the base
the PR was merged onto; for squash merges the merge commit *is* the PR).
Clones are shallow (``git fetch --depth 2 <merge>``) into a git-ignored
cache, so a case costs one tree download, not the project's history.

Usage:
    python benchmark/field_trial/run_field_trial.py --fetch            # clones only
    python benchmark/field_trial/run_field_trial.py --modes sast-only lgtm
    python benchmark/field_trial/run_field_trial.py --modes lgtm --cases mealie-8811 --resume
    python benchmark/field_trial/run_field_trial.py --summarize-only
"""

from __future__ import annotations

import argparse
import datetime
import json
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO_ROOT = BENCH.parent
CASES_FILE = HERE / "cases.json"
sys.path.insert(0, str(REPO_ROOT / "src"))

from lgtm.config import LGTMConfig, setup_logging  # noqa: E402
from lgtm.diff.git_diff import get_pr_diff  # noqa: E402
from lgtm.pipeline import ReviewPipeline  # noqa: E402
from lgtm.rag.indexer import index_repo_docs  # noqa: E402

MODES = ["sast-only", "llm-only", "lgtm"]


class FetchError(RuntimeError):
    pass


def load_cases(path: Path = CASES_FILE) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def project_of(case: dict) -> str:
    return case["repo"].split("/")[-1]


def git(repo: Path, *args: str, check: bool = True, timeout: int = 600) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )
    if check and result.returncode != 0:
        raise FetchError(f"git {' '.join(args)} failed in {repo}:\n{result.stderr.strip()}")
    return result.stdout


def has_commit(repo: Path, sha: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
    ).returncode == 0


def ensure_case(case: dict, cache: Path) -> tuple[str, str]:
    """Shallow-fetch the merge commit and its parent; return (base, pr) SHAs."""
    clone = cache / project_of(case)
    if not (clone / ".git").is_dir():
        clone.mkdir(parents=True, exist_ok=True)
        git(clone, "init", "-q")
        git(clone, "remote", "add", "origin", f"https://github.com/{case['repo']}.git")
        git(clone, "config", "core.autocrlf", "false")
    merge = case["merge_commit"]
    if not has_commit(clone, merge) or not has_commit(clone, f"{merge}^"):
        print(f"  fetching {case['repo']}@{merge[:10]} (depth 2) ...", flush=True)
        git(clone, "fetch", "--quiet", "--depth", "2", "origin", merge)
    base = git(clone, "rev-parse", f"{merge}^1").strip()
    pr = git(clone, "rev-parse", merge).strip()
    # Named refs, so a result JSON reads like the other benchmarks
    git(clone, "update-ref", f"refs/heads/ft/{case['id']}/base", base)
    git(clone, "update-ref", f"refs/heads/ft/{case['id']}/pr", pr)
    return base, pr


def ensure_index(clone: Path, base: str, idx_dir: Path, config: LGTMConfig) -> dict:
    """Index the base tree once per base SHA; the index lives outside the clone."""
    stamp = idx_dir / "base_sha"
    if stamp.is_file() and stamp.read_text().strip() == base:
        return {"index_seconds": 0.0, "index_reused": True}
    git(clone, "checkout", "-f", "-q", base)
    cfg = LGTMConfig(**{**config.to_dict(), "chroma_persist_dir": str(idx_dir)})
    started = time.monotonic()
    chunks = index_repo_docs(clone, cfg)
    idx_dir.mkdir(parents=True, exist_ok=True)
    stamp.write_text(base)
    return {"index_seconds": round(time.monotonic() - started, 1),
            "index_reused": False, "index_chunks": chunks}


def scrub(obj, needles: list[str]):
    if isinstance(obj, str):
        for n in needles:
            obj = obj.replace(n, "<cache>")
        return obj
    if isinstance(obj, list):
        return [scrub(x, needles) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v, needles) for k, v in obj.items()}
    return obj


COVERAGE_KEYS = (
    "planner", "investigator_status", "hunks_total", "hunks_reviewed",
    "sections_scheduled", "sections_completed", "sections_failed", "complete",
)


def coverage_brief(coverage: dict | None) -> dict | None:
    """The coverage counts that show whether an agent reviewed the PR, without the per-section rows."""
    if coverage is None:
        return None
    return {k: coverage.get(k) for k in COVERAGE_KEYS}


def judge_counts(findings: list[dict]) -> dict | None:
    """Supported / unsupported / not judged counts, or None when the pipeline has no judge."""
    if not any("supported" in f for f in findings):
        return None
    flags = [f.get("supported") for f in findings]
    return {
        "supported": sum(1 for s in flags if s is True),
        "unsupported": sum(1 for s in flags if s is False),
        "not_judged": sum(1 for s in flags if s is None),
    }


def run_case(case: dict, mode: str, cache: Path, config: LGTMConfig) -> dict:
    clone = cache / project_of(case)
    base, pr = ensure_case(case, cache)
    cfg = LGTMConfig(**config.to_dict())
    cfg.mode = mode
    diffs = get_pr_diff(clone, base, pr, cfg.git_timeout)
    py = [d for d in diffs if d.path.endswith(".py") and d.status != "deleted"]
    record = {
        "id": case["id"], "repo": case["repo"], "pr": case["pr"],
        "title": case.get("title", ""), "mode": mode, "model": cfg.ollama_model,
        "base": base, "pr_sha": pr,
        "files_changed": len(diffs), "python_files_changed": len(py),
        "added_lines": sum(len(h.added_lines) for d in py for h in d.hunks),
        "diff_chars": sum(len(d.hunk_text()) for d in py),
    }
    index_info: dict = {}
    if mode in ("lgtm", "lgtm-no-sast"):
        idx_dir = cache / ".index" / project_of(case)
        index_info = ensure_index(clone, base, idx_dir, cfg)
        cfg.chroma_persist_dir = str(idx_dir)
    started = time.monotonic()
    try:
        result = ReviewPipeline(clone, cfg).run(base, pr, output_dir=None)
    except Exception as exc:  # noqa: BLE001 - a crash is a result here
        record.update({
            "crashed": True, "error": f"{type(exc).__name__}: {exc}",
            "latency_seconds": round(time.monotonic() - started, 1),
            **index_info, "findings": [],
        })
        return record
    findings = [f.model_dump(exclude={"raw_response"}) for f in result.findings]
    record.update({
        "crashed": False, "error": None,
        "latency_seconds": round(time.monotonic() - started, 1),
        **index_info,
        "semgrep_findings_total": result.meta.semgrep_findings_total,
        "semgrep_findings_in_diff": result.meta.semgrep_findings_in_diff,
        "endpoints_reviewed": result.meta.endpoints_reviewed,
        "graph_state": result.meta.graph_state,
        "coverage": coverage_brief(result.meta.coverage),
        "judged": judge_counts(findings),
        "n_findings": len(findings),
        "verdicts": dict(Counter(f["verdict"] for f in findings)),
        "vulnerable_findings": [
            {"finding_id": f["finding_id"], "agent": f["agent"],
             "category": f["category"], "file": f["file"], "line": f["line"],
             "cwe_id": f["cwe_id"], "confidence": f["confidence"],
             "evidence_valid": f["evidence_valid"],
             "explanation": f["explanation"][:400]}
            for f in findings if f["verdict"] == "vulnerable"
        ],
        "tool_calls_total": sum(f.get("tool_calls_used", 0) for f in findings),
        "findings": findings,
    })
    return record


def summarize(records: list[dict]) -> dict:
    ran = [r for r in records if not r.get("crashed")]
    lat = [r["latency_seconds"] for r in ran]
    flagged = [r for r in ran if r.get("verdicts", {}).get("vulnerable")]
    covered = [r["coverage"] for r in ran if r.get("coverage")]
    judged = [r["judged"] for r in ran if r.get("judged")]
    return {
        "cases": len(records),
        "crashed": sum(1 for r in records if r.get("crashed")),
        "prs_with_vulnerable_verdict": len(flagged),
        "vulnerable_findings_total": sum(len(r.get("vulnerable_findings", [])) for r in ran),
        "findings_total": sum(r.get("n_findings", 0) for r in ran),
        "grounded_vulnerable_findings": sum(
            1 for r in ran for f in r.get("vulnerable_findings", []) if f["evidence_valid"]),
        "semgrep_in_diff_total": sum(r.get("semgrep_findings_in_diff", 0) for r in ran),
        "endpoints_reviewed_total": sum(r.get("endpoints_reviewed", 0) for r in ran),
        "prs_reviewed_by_agent": sum(1 for c in covered if (c.get("sections_completed") or 0) > 0),
        "prs_coverage_complete": sum(1 for c in covered if c.get("complete")),
        "sections_failed_total": sum(c.get("sections_failed") or 0 for c in covered),
        "graph_states": dict(Counter(r.get("graph_state") or "none" for r in ran)),
        "judge": ({k: sum(j[k] for j in judged) for k in ("supported", "unsupported", "not_judged")}
                  if judged else None),
        "latency_median_seconds": round(statistics.median(lat), 1) if lat else None,
        "latency_max_seconds": max(lat) if lat else None,
        "index_seconds_total": round(sum(r.get("index_seconds", 0) for r in ran), 1),
        "per_case": [
            {"id": r["id"], "crashed": r.get("crashed"), "error": r.get("error"),
             "latency_seconds": r.get("latency_seconds"),
             "n_findings": r.get("n_findings"), "verdicts": r.get("verdicts"),
             "vulnerable": len(r.get("vulnerable_findings", [])),
             "graph_state": r.get("graph_state"),
             "sections_completed": (r.get("coverage") or {}).get("sections_completed")}
            for r in records
        ],
    }


def write_summary(out_dir: Path, mode: str, records: list[dict], model: str) -> None:
    payload = {
        "mode": mode, "model": model if mode != "sast-only" else "none",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "git_commit": subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True).stdout.strip() or "unknown",
        "summary": summarize(records),
    }
    (out_dir / "summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--modes", nargs="+", choices=MODES, default=["sast-only", "lgtm"])
    parser.add_argument("--cases", nargs="+", default=None)
    parser.add_argument("--cache", type=Path, default=HERE / ".cache")
    parser.add_argument("--output", type=Path, default=BENCH / "results" / "field_trial")
    parser.add_argument("--model", default=None)
    parser.add_argument("--ollama-url", default=None)
    parser.add_argument("--fetch", action="store_true", help="only fetch the clones")
    parser.add_argument("--resume", action="store_true", help="skip cases with a result JSON")
    parser.add_argument("--summarize-only", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    cases = load_cases()
    if args.cases:
        wanted = set(args.cases)
        cases = [c for c in cases if c["id"] in wanted]
        missing = wanted - {c["id"] for c in cases}
        if missing:
            parser.error(f"unknown case ids: {sorted(missing)}")
    config = LGTMConfig()
    if args.model:
        config.ollama_model = args.model
    if args.ollama_url:
        config.ollama_base_url = args.ollama_url
    needles = [str(args.cache.resolve()), str(args.cache), str(Path.home())]

    if args.fetch:
        for case in cases:
            base, pr = ensure_case(case, args.cache)
            print(f"{case['id']}: base {base[:10]} pr {pr[:10]}")
        return 0

    for mode in args.modes:
        out_dir = args.output / mode
        out_dir.mkdir(parents=True, exist_ok=True)
        records: list[dict] = []
        for i, case in enumerate(cases, 1):
            path = out_dir / f"{case['id']}.json"
            if (args.resume or args.summarize_only) and path.is_file():
                records.append(json.loads(path.read_text(encoding="utf-8")))
                continue
            if args.summarize_only:
                continue
            print(f"[{mode} {i}/{len(cases)}] {case['id']} ...", end=" ", flush=True)
            try:
                record = run_case(case, mode, args.cache, config)
            except Exception as exc:  # noqa: BLE001 - fetch/diff failure, still a result
                record = {"id": case["id"], "repo": case["repo"], "pr": case["pr"],
                          "mode": mode, "crashed": True,
                          "error": f"{type(exc).__name__}: {exc}", "findings": []}
            record = scrub(record, needles)
            path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
            records.append(record)
            if record.get("crashed"):
                print(f"CRASH {record['error'][:120]}")
            else:
                print(f"{record.get('n_findings', 0)} finding(s) {record.get('verdicts', {})} "
                      f"{record['latency_seconds']}s")
        write_summary(out_dir, mode, records, config.ollama_model)
        print(json.dumps({k: v for k, v in summarize(records).items() if k != "per_case"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
