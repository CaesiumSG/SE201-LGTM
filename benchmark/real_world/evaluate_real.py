#!/usr/bin/env python3
"""Evaluate LGTM on the real-world CVE benchmark.

Reuses ``benchmark/evaluate.py`` for scoring and summaries (imported, not
copied), so the numbers are computed exactly as for the synthetic Shoply
benchmark. For every (case, variant, mode) it checks out the case's base
branch in the cached clone, indexes it when an agent will actually run, runs
``ReviewPipeline`` and writes one result JSON.

The run is meant to be done in short foreground chunks: ``--resume`` skips
cases whose result JSON already exists, and ``--budget`` stops starting new
cases after N seconds so a call ends well inside a shell time limit.

Variants:
- ``own``: only the repository's own docs are indexed (default branch pair).
- ``policy``: the same trees plus ``policies/<project>.md`` as
  ``security-policy.md`` (``fetch.py --policies``); authz cases, and only for
  the modes that retrieve documents (lgtm, lgtm-no-sast).

Index skipping: a mode that runs no agent for a case cannot use the index, so
it is not built. The test uses the pipeline's own functions: lgtm needs an
index when there is >= 1 detected endpoint or Semgrep finding in the diff;
lgtm-no-sast when there is >= 1 detected endpoint or heuristic SQL sink.
``index_skipped`` and ``index_skip_reason`` are recorded in every result.

Usage (Windows needs UTF-8 mode; see docs/real-world-eval.md):
    PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes sast-only
    PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes lgtm \
        --cases aegra_authz_safe --resume --budget 300
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO_ROOT = BENCH.parent
sys.path.insert(0, str(REPO_ROOT / "src"))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate = _load("lgtm_bench_evaluate", BENCH / "evaluate.py")
fetch = _load("lgtm_rw_fetch", HERE / "fetch.py")

from lgtm.agents.authz_reviewer import extract_changed_endpoints  # noqa: E402
from lgtm.config import LGTMConfig, setup_logging  # noqa: E402
from lgtm.diff.git_diff import get_pr_diff  # noqa: E402
from lgtm.pipeline import ReviewPipeline  # noqa: E402
from lgtm.rag.indexer import index_repo_docs  # noqa: E402

MODES = ("sast-only", "llm-only", "lgtm", "lgtm-no-sast")
DOC_MODES = ("lgtm", "lgtm-no-sast")  # modes whose agents retrieve from the index
DEFAULT_OUTPUT = BENCH / "results" / "real_world"
INFRA_PREFIXES = ("Agent execution failed", "LLM call failed")


# ----------------------------------------------------------------------
# Output hygiene
# ----------------------------------------------------------------------
def scrub(obj, replacements: list[tuple[str, str]]):
    """Replace absolute paths in every string of a JSON-like object.

    Longest needle first, so a clone path is replaced before the home
    directory that contains it.
    """
    ordered = sorted(replacements, key=lambda r: len(r[0]), reverse=True)

    def fix(value):
        if isinstance(value, str):
            for needle, repl in ordered:
                if needle:
                    value = value.replace(needle, repl)
            return value
        if isinstance(value, list):
            return [fix(v) for v in value]
        if isinstance(value, dict):
            return {fix(k): fix(v) for k, v in value.items()}
        return value

    return fix(obj)


def path_replacements(cache: Path, output: Path) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for path, token in ((cache, "<cache>"), (output, "<results>"),
                        (REPO_ROOT, "<repo>"), (Path.home(), "<home>")):
        for form in {str(path), path.as_posix(), str(path.resolve()),
                     path.resolve().as_posix()}:
            pairs.append((form, token))
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if len(user) >= 4:
        pairs.append((user, "<user>"))
    return pairs


# ----------------------------------------------------------------------
# Planning
# ----------------------------------------------------------------------
def variant_suffix(variant: str) -> str:
    return "-policy" if variant == "policy" else ""


def out_dir_for(output: Path, mode: str, variant: str) -> Path:
    return output / f"{mode}{variant_suffix(variant)}"


def work_units(cases, modes, variants):
    """(case, variant, mode) triples, case-major so one clone is used at a time."""
    for case in cases:
        for variant in variants:
            if variant == "policy" and fetch.policy_text(case) is None:
                continue
            for mode in modes:
                if variant == "policy" and mode not in DOC_MODES:
                    continue
                yield case, variant, mode


def pending_units(units, output: Path, resume: bool):
    """Drop units whose result JSON already exists when resuming."""
    for case, variant, mode in units:
        done = (out_dir_for(output, mode, variant) / f"{case['id']}.json").exists()
        if resume and done:
            continue
        yield case, variant, mode


def expected_ids(cases, mode: str, variant: str) -> set[str]:
    return {c["id"] for c, _v, _m in work_units(cases, [mode], [variant])}


# ----------------------------------------------------------------------
# Agent work and indexing
# ----------------------------------------------------------------------
def count_agent_items(mode: str, diffs, sast_in_diff: list) -> dict:
    """What would an agent have to review? Uses the pipeline's own detectors.

    ``sast_in_diff`` is ``ReviewPipeline._run_sast``'s in-diff findings (only
    consulted for ``lgtm``); ``lgtm-no-sast`` uses the pipeline's heuristic
    SQL-sink detector instead of Semgrep.
    """
    endpoints = extract_changed_endpoints(diffs)
    if mode == "lgtm":
        sinks, sink_kind = len(sast_in_diff), "Semgrep findings in the diff"
    else:
        sinks = len(ReviewPipeline._heuristic_sql_findings(diffs))
        sink_kind = "heuristic SQL sinks"
    return {
        "endpoint_ids": [e.endpoint_id for e in endpoints],
        "sink_count": sinks,
        "sink_kind": sink_kind,
        "agent_items": len(endpoints) + sinks,
    }


def git_out(clone: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(clone), *args],
                            capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout.decode("utf-8", "replace")


def ensure_index(clone: Path, base_branch: str, idx_dir: Path,
                 config: LGTMConfig, index_fn=index_repo_docs) -> dict:
    """Build (or reuse) the index for one base branch; returns marker data.

    The index lives outside the clone so it survives checkouts, and is shared
    by lgtm and lgtm-no-sast. A marker is written only after a build
    finishes, so an interrupted build is redone, never reused.
    """
    marker = idx_dir / "index.json"
    base_sha = git_out(clone, "rev-parse", base_branch).strip()
    if marker.is_file():
        data = json.loads(marker.read_text(encoding="utf-8"))
        if data.get("base_sha") == base_sha:
            return {**data, "reused": True}
    if idx_dir.exists():
        shutil.rmtree(idx_dir)  # scratch dir under results/, safe to rebuild
    git_out(clone, "checkout", "-f", "-q", base_branch)
    cfg = copy.copy(config)
    cfg.chroma_persist_dir = str(idx_dir)
    started = time.monotonic()
    chunks = index_fn(clone, cfg)
    data = {"base_sha": base_sha, "seconds": round(time.monotonic() - started, 2),
            "chunks": chunks}
    idx_dir.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(data), encoding="utf-8")
    return {**data, "reused": False}


# ----------------------------------------------------------------------
# One unit of work
# ----------------------------------------------------------------------
def diff_stats(diffs) -> dict:
    py = [len(d.hunk_text()) for d in diffs if d.path.endswith(".py")]
    return {
        "diff_files": len(diffs),
        "diff_added": sum(len(h.added_lines) for d in diffs for h in d.hunks),
        "diff_deleted": sum(len(h.deleted_lines) for d in diffs for h in d.hunks),
        "diff_py_chars": sum(py),
        "diff_max_file_chars": max(py or [0]),
    }


def error_result(case: dict, mode: str, variant: str, exc: Exception) -> dict:
    """Same semantics as evaluate.main(): a crash scores as 'not flagged'."""
    vulnerable = case["expected_verdict"] == "vulnerable"
    outcome = "FN" if vulnerable else "TN"
    return {
        "id": case["id"], "category": case["category"], "split": "real_world",
        "expected": case["expected_verdict"], "predicted": "error",
        "outcome": outcome, "correct": not vulnerable,
        "predicted_grounded": "error", "outcome_grounded": outcome,
        "error": f"{type(exc).__name__}: {exc}",
        "n_findings": 0, "verdicts": [], "grounded": 0, "grounding_rate": None,
        "latency_seconds": 0.0, "est_tokens": 0, "findings": [],
        "mode": mode, "variant": variant,
        "project": fetch.project_of(case), "infra_failures": 0,
    }


def run_unit(case: dict, variant: str, mode: str, cache: Path, output: Path,
             config: LGTMConfig, index_only: bool = False) -> dict | None:
    cid = case["id"]
    clone = cache / fetch.project_of(case)
    suffix = variant_suffix(variant)
    base_b = fetch.branch(cid, "base" + suffix)
    pr_b = fetch.branch(cid, "pr" + suffix)
    cfg = copy.copy(config)
    cfg.mode = mode
    case_started = time.monotonic()

    diffs = [d for d in get_pr_diff(clone, base_b, pr_b, cfg.git_timeout)
             if d.status != "deleted"]
    pipeline = ReviewPipeline(clone, cfg)

    extra: dict = {
        "project": fetch.project_of(case), "mode": mode, "variant": variant,
        **diff_stats(diffs),
        "endpoints_detected": [e.endpoint_id for e in extract_changed_endpoints(diffs)],
        "index_seconds": None, "index_chunks": None, "index_reused": None,
        "index_skipped": True, "index_skip_reason": "mode does not use the index",
    }

    if mode in DOC_MODES:
        sast = pipeline._run_sast(diffs, base_b, pr_b)[0] if mode == "lgtm" else []
        work = count_agent_items(mode, diffs, sast)
        if work["agent_items"] == 0:
            extra["index_skip_reason"] = (
                f"no agent can run: 0 detected endpoints and 0 {work['sink_kind']}"
            )
        else:
            idx_dir = output / ".index" / f"{cid}{suffix}"
            info = ensure_index(clone, base_b, idx_dir, cfg)
            cfg.chroma_persist_dir = str(idx_dir)  # same object the pipeline holds
            extra.update(index_skipped=False, index_skip_reason="",
                         index_seconds=info["seconds"],
                         index_chunks=info["chunks"], index_reused=info["reused"])
    if index_only:
        print(f"    index: skipped={extra['index_skipped']} "
              f"{extra['index_skip_reason'] or ''} "
              f"seconds={extra['index_seconds']} chunks={extra['index_chunks']} "
              f"reused={extra['index_reused']}")
        return None

    started = time.monotonic()
    result = pipeline.run(base_b, pr_b, output_dir=None)
    latency = time.monotonic() - started

    findings = [f.model_dump(exclude={"raw_response"}) for f in result.findings]
    if extra["index_skipped"] and mode in DOC_MODES and findings:
        raise RuntimeError("index was skipped but an agent produced findings")
    grounded = [f for f in findings if f.get("evidence_valid")]
    infra = [f["finding_id"] for f in findings
             if str(f.get("explanation", "")).startswith(INFRA_PREFIXES)
             or f.get("finding_id") == "plain:unparsable"]
    extra["semgrep_findings_in_diff"] = result.meta.semgrep_findings_in_diff
    return evaluate.score_case({
        "id": cid, "category": case["category"], "split": "real_world",
        "expected": case["expected_verdict"], "n_findings": len(findings),
        "verdicts": [f["verdict"] for f in findings], "grounded": len(grounded),
        "grounding_rate": round(len(grounded) / len(findings), 3) if findings else None,
        "latency_seconds": round(latency, 2),
        "case_seconds": round(time.monotonic() - case_started, 2),
        "est_tokens": evaluate.estimate_tokens(findings, {}),
        "infra_failures": len(infra), "infra_failure_ids": infra,
        "findings": findings, **extra,
    })


# ----------------------------------------------------------------------
# Summaries
# ----------------------------------------------------------------------
def write_dir_summary(out_dir: Path, mode: str, variant: str, expected: set[str],
                      model: str, extra: dict | None = None) -> dict | None:
    """Rebuild summary.json from every case JSON in ``out_dir``."""
    results = []
    for path in sorted(out_dir.glob("*.json")):
        if path.name == "summary.json":
            continue
        results.append(json.loads(path.read_text(encoding="utf-8")))
    if not results:
        return None
    present = {r["id"] for r in results}
    payload_extra = {
        "split": "real_world", "variant": variant,
        "experiments": {"require_tool_use": False, "static_facts": False,
                        "authz_role_guidance": False},
        "cases_expected": len(expected), "cases_present": len(present),
        "complete": present >= expected,
        "missing": sorted(expected - present),
        **(extra or {}),
    }
    with contextlib.redirect_stdout(io.StringIO()):  # write_summary prints it all
        evaluate.write_summary(out_dir, results, mode,
                               "none" if mode == "sast-only" else model, payload_extra)
    return json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))


# ----------------------------------------------------------------------
# Preflight: fail loudly instead of recording a run of silent non-results
# ----------------------------------------------------------------------
def preflight(modes, config: LGTMConfig) -> dict:
    if os.name == "nt" and not sys.flags.utf8_mode:
        raise SystemExit(
            "Run with PYTHONUTF8=1: on Windows the pipeline decodes git output "
            "with the locale code page (cp1252) and crashes on non-ASCII diffs "
            "(src/lgtm/diff/git_diff.py). See docs/real-world-eval.md."
        )
    info: dict = {"python": sys.version.split()[0],
                  "utf8_mode": bool(sys.flags.utf8_mode)}
    if any(m in ("sast-only", "lgtm") for m in modes):
        from lgtm.sast.semgrep_runner import _semgrep_executable

        check = subprocess.run([*_semgrep_executable(), "--version"],
                               capture_output=True, text=True)
        if check.returncode != 0:
            raise SystemExit(f"semgrep is not runnable: {check.stderr.strip()[:300]}")
        info["semgrep"] = check.stdout.strip().splitlines()[0]
    if any(m != "sast-only" for m in modes):
        base = config.ollama_base_url.rstrip("/")
        try:
            tags = json.loads(urllib.request.urlopen(f"{base}/api/tags", timeout=10).read())
            version = json.loads(urllib.request.urlopen(f"{base}/api/version", timeout=10).read())
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"Ollama is not reachable at {base}: {exc}") from exc
        names = {m["name"] for m in tags.get("models", [])}
        if config.ollama_model not in names:
            raise SystemExit(f"model {config.ollama_model} is not pulled (have: {sorted(names)})")
        info["ollama_version"] = version.get("version")
    return info


# ----------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate LGTM on the real-world benchmark")
    parser.add_argument("--cache", type=Path, default=HERE / ".cache",
                        help="directory holding the fetch.py clones")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--modes", nargs="*", choices=MODES, default=list(MODES))
    parser.add_argument("--variants", choices=("own", "policy", "both"), default="both")
    parser.add_argument("--cases", nargs="*", default=None)
    parser.add_argument("--resume", action="store_true",
                        help="skip units whose result JSON already exists")
    parser.add_argument("--budget", type=float, default=None,
                        help="start no new unit after this many seconds")
    parser.add_argument("--index-only", action="store_true",
                        help="build the indexes the selected units need, run no review")
    parser.add_argument("--summarize-only", action="store_true",
                        help="rebuild summary.json files from existing results")
    parser.add_argument("--model", default=None)
    parser.add_argument("--ollama-url", default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    config = LGTMConfig()  # defaults: every experiment flag off
    if args.model:
        config.ollama_model = args.model
    if args.ollama_url:
        config.ollama_base_url = args.ollama_url

    all_cases = fetch.load_cases()
    cases = all_cases
    if args.cases:
        unknown = set(args.cases) - {c["id"] for c in all_cases}
        if unknown:
            parser.error(f"unknown case ids: {sorted(unknown)}")
        cases = [c for c in all_cases if c["id"] in args.cases]
    variants = ["own", "policy"] if args.variants == "both" else [args.variants]
    scrubs = path_replacements(args.cache, args.output)
    args.output.mkdir(parents=True, exist_ok=True)

    # Also for --summarize-only: every summary.json records the environment it
    # was built in, and a rebuild must not drop those fields.
    env_info = preflight(args.modes, config)
    if not args.summarize_only:
        missing = [fetch.project_of(c) for c in cases
                   if not (args.cache / fetch.project_of(c) / ".git").is_dir()]
        if missing:
            raise SystemExit(
                f"no clone for {sorted(set(missing))} under {args.cache}; "
                "run benchmark/real_world/fetch.py --policies first"
            )

    units = list(pending_units(work_units(cases, args.modes, variants),
                               args.output, args.resume and not args.index_only))
    started = time.monotonic()
    touched: set[tuple[str, str]] = set()
    done = 0
    for i, (case, variant, mode) in enumerate(units, 1):
        if args.summarize_only:
            break
        if args.budget is not None and time.monotonic() - started > args.budget:
            print(f"budget of {args.budget:.0f}s reached after {done} unit(s); "
                  f"{len(units) - i + 1} left, re-run with --resume")
            break
        print(f"[{i}/{len(units)}] {case['id']} {mode}{variant_suffix(variant)} ...",
              flush=True)
        try:
            result = run_unit(case, variant, mode, args.cache, args.output,
                              config, index_only=args.index_only)
        except Exception as exc:  # noqa: BLE001 - one bad case must not kill the run
            result = error_result(case, mode, variant, exc)
            print(f"    ERROR: {scrub(result['error'], scrubs)}")
        done += 1
        if result is None or args.index_only:
            continue  # an index-only failure is printed, never a case result
        out_dir = out_dir_for(args.output, mode, variant)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{case['id']}.json").write_text(
            json.dumps(scrub(result, scrubs), indent=2, default=str), encoding="utf-8")
        touched.add((mode, variant))
        if result["predicted"] != "error":
            if result.get("index_seconds") is not None:
                index_note = f"index {result['index_seconds']}s"
                index_note += " (reused)" if result.get("index_reused") else ""
            else:
                index_note = "index skipped" if result.get("index_skipped") else "no index"
            print(f"    {result['outcome']} (expected {result['expected']}, predicted "
                  f"{result['predicted']}; review {result['latency_seconds']}s, "
                  f"{index_note}; {result['n_findings']} finding(s))")

    if args.index_only:
        return 0
    targets = touched if not args.summarize_only else {
        (m, v) for m in args.modes for v in variants
        if out_dir_for(args.output, m, v).is_dir()}
    for mode, variant in sorted(targets):
        summary = write_dir_summary(
            out_dir_for(args.output, mode, variant), mode, variant,
            expected_ids(all_cases, mode, variant), config.ollama_model, env_info)
        if summary:
            o = summary["summary"]["overall"]
            print(f"summary {mode}{variant_suffix(variant)}: cases={o['cases']} "
                  f"tp={o['tp']} fp={o['fp']} fn={o['fn']} tn={o['tn']} f1={o['f1']} "
                  f"complete={summary['complete']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
