#!/usr/bin/env python3
"""Build the LGTM report viewer: one self-contained HTML file from benchmark runs.

The viewer opens offline in any browser (no server, no Ollama, no GPU). It
shows each benchmark's metrics per mode, every case's outcome side by side
across modes, and for one case the PR diff with each finding pinned to the
line it cites, the Kev judge's verdict, the evidence and the agent's tool
calls.

Which runs go in is listed in ``viewer/runs.json``. Each benchmark names its
run directories (one per mode, each holding per-case JSON and a
``summary.json``) and where its diffs come from: the Shoply patch files via
``labels.json``, or a git clone cache for the real-world benchmarks.

Usage:
    python viewer/build_viewer.py                         # viewer/runs.json -> viewer/lgtm-viewer.html
    python viewer/build_viewer.py --config my-runs.json --out /tmp/viewer.html
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
TEMPLATE = HERE / "template.html"
DATA_MARKER = "/*__LGTM_DATA__*/null"

TRACE_RESULT_CHARS = 1200
EXPLANATION_CHARS = 4000
DIFF_MAX_LINES = 4000

# Summary metrics shown in the results table, in display order.
OVERALL_KEYS = ("precision", "recall", "f1", "false_positive_rate_on_safe",
                "tp", "fp", "fn", "tn", "scored", "errors")


def finding_status(f: dict) -> str:
    """One label per finding: the Kev judgment in lgtm mode, the verdict otherwise.

    New-format lgtm findings carry ``supported`` / ``judged`` / ``kev_verdict``
    and an empty ``verdict``; baseline and archived findings carry ``verdict``.
    """
    if f.get("verdict"):
        return f["verdict"]
    if "supported" in f or "judged" in f:
        if f.get("supported") is False:
            return "unsupported"
        if not f.get("judged"):
            return "not_judged"
        return f.get("kev_verdict") or "not_judged"
    return "unknown"


def norm_evidence(e: dict) -> dict:
    grounded = e.get("grounded_in_pr")
    if grounded is None and "valid" in e:
        grounded = e.get("valid")
    return {
        "type": e.get("type") or ("policy" if e.get("source") else "code"),
        "file": e.get("file"),
        "lines": e.get("lines"),
        "source": e.get("source"),
        "content": (e.get("content") or "")[:EXPLANATION_CHARS],
        "grounded": grounded,
    }


def norm_finding(f: dict) -> dict:
    return {
        "id": f.get("finding_id", ""),
        "agent": f.get("agent", ""),
        "category": f.get("category", ""),
        "cwe": f.get("cwe_id", ""),
        "file": f.get("file", ""),
        "line": f.get("line"),
        "status": finding_status(f),
        "severity": f.get("kev_severity") or f.get("severity") or "",
        "confidence": f.get("provenance_confidence", f.get("confidence")),
        "explanation": (f.get("explanation") or "")[:EXPLANATION_CHARS],
        "fix": (f.get("suggested_fix") or "")[:EXPLANATION_CHARS],
        "reason": f.get("unsupported_reason") or f.get("not_judged_reason") or "",
        "semgrep_rule": f.get("semgrep_rule_id", ""),
        "evidence": [norm_evidence(e) for e in f.get("evidence") or [] if isinstance(e, dict)],
    }


def compact_args(args) -> str:
    if not isinstance(args, dict):
        return str(args)[:200]
    return ", ".join(f"{k}={json.dumps(v)[:80]}" for k, v in args.items())


def norm_trace(record: dict) -> list[dict]:
    """The agent's tool calls in order, with results cut to a readable length."""
    steps = []
    for run in (record.get("trace") or {}).get("runs") or []:
        for turn in run.get("turns") or []:
            for call in turn.get("tool_calls") or []:
                result = str(call.get("result", ""))
                steps.append({
                    "section": run.get("section", ""),
                    "tool": call.get("tool", ""),
                    "args": compact_args(call.get("args")),
                    "result": result[:TRACE_RESULT_CHARS],
                    "truncated": len(result) > TRACE_RESULT_CHARS,
                })
    return steps


def coverage_brief(cov: dict | None) -> dict | None:
    if not cov:
        return None
    keys = ("planner", "investigator_status", "hunks_total", "hunks_reviewed",
            "sections_completed", "sections_failed", "complete")
    return {k: cov.get(k) for k in keys}


def norm_case(record: dict) -> dict:
    """The per-mode part of a case: outcome, findings, trace."""
    return {
        "outcome": record.get("outcome") or ("ERROR" if record.get("crashed") else None),
        "predicted": record.get("predicted"),
        "correct": record.get("correct"),
        "latency": record.get("latency_seconds"),
        "error": record.get("error"),
        "graph_state": record.get("graph_state"),
        "coverage": coverage_brief(record.get("coverage")),
        "scope": record.get("scope"),
        "code_sha": (record.get("pin") or {}).get("code_sha"),
        "findings": [norm_finding(f) for f in record.get("findings") or []],
        "trace": norm_trace(record),
    }


def norm_summary(payload: dict) -> dict:
    s = payload.get("summary", payload)
    overall = s.get("overall", s)
    kev = s.get("kev") or {}
    return {
        "model": payload.get("model"),
        "git_commit": payload.get("git_commit"),
        "generated_at": payload.get("generated_at"),
        "overall": {k: overall.get(k) for k in OVERALL_KEYS if k in overall},
        "median_latency_seconds": s.get("median_latency_seconds", s.get("latency_median_seconds")),
        "evidence_grounding_rate": s.get("evidence_grounding_rate"),
        "off_category_alarm_rate": s.get("off_category_alarm_rate"),
        "kev_verdicts": kev.get("verdicts"),
        "graph_states": s.get("graph_states"),
    }


_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")


def parse_diff(text: str) -> list[dict]:
    """Unified diff -> files -> hunks -> lines with old/new line numbers."""
    files: list[dict] = []
    cur = hunk = None
    old = new = 0
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            cur = {"path": raw.split(" b/", 1)[-1], "hunks": []}
            files.append(cur)
            hunk = None
        elif cur is None:
            continue
        elif raw.startswith("+++ "):
            path = raw[4:]
            if path != "/dev/null":
                cur["path"] = path[2:] if path.startswith("b/") else path
        elif raw.startswith("--- ") and hunk is None:
            continue
        elif (m := _HUNK.match(raw)):
            old, new = int(m.group(1)), int(m.group(2))
            hunk = {"header": raw, "lines": []}
            cur["hunks"].append(hunk)
        elif hunk is not None and raw[:1] in ("+", "-", " ", ""):
            kind = raw[:1] or " "
            line = {"k": kind, "t": raw[1:]}
            if kind != "+":
                line["o"] = old
                old += 1
            if kind != "-":
                line["n"] = new
                new += 1
            hunk["lines"].append(line)
    return files


def cap_diff(files: list[dict]) -> tuple[list[dict], bool]:
    total, kept = 0, []
    for f in files:
        hunks = []
        for h in f["hunks"]:
            if total >= DIFF_MAX_LINES:
                break
            hunks.append(h)
            total += len(h["lines"])
        if hunks:
            kept.append({**f, "hunks": hunks})
    return kept, total >= DIFF_MAX_LINES


def git_diff(repo: Path, base: str, pr: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), "diff", "--no-color", f"{base}..{pr}", "--", "*.py"],
        capture_output=True, encoding="utf-8", errors="replace", timeout=60,
    )
    return result.stdout if result.returncode == 0 else ""


def case_diff(bench: dict, case_id: str, records: list[dict], labels: dict) -> tuple[list[dict], bool]:
    patch = labels.get(case_id, {}).get("patch_file")
    if patch:
        path = REPO_ROOT / bench.get("patch_root", "benchmark") / patch
        if path.is_file():
            return cap_diff(parse_diff(path.read_text(encoding="utf-8", errors="replace")))
    cache = bench.get("clone_cache")
    if cache:
        for r in records:
            base = r.get("base_sha") or r.get("base") or (r.get("pin") or {}).get("base_sha")
            pr = r.get("pr_sha") or (r.get("pin") or {}).get("pr_sha")
            project = r.get("project") or (r.get("repo") or "").split("/")[-1]
            repo = REPO_ROOT / cache / project
            if base and pr and project and repo.is_dir():
                text = git_diff(repo, base, pr)
                if text:
                    return cap_diff(parse_diff(text))
    return [], False


def load_labels(bench: dict) -> dict:
    path = bench.get("labels")
    if not path:
        return {}
    data = json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))
    return {c["id"]: c for c in data.get("cases", data if isinstance(data, list) else [])}


def load_run(run_dir: Path) -> tuple[dict | None, dict[str, dict]]:
    summary = None
    cases: dict[str, dict] = {}
    for p in sorted(run_dir.glob("*.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        if p.name == "summary.json":
            summary = data
        elif isinstance(data, dict) and "id" in data and ("findings" in data or "crashed" in data):
            cases[data["id"]] = data
    return summary, cases


def build_benchmark(bench: dict) -> dict:
    labels = load_labels(bench)
    modes, summaries, per_mode = [], {}, {}
    for mode, rel in bench["runs"].items():
        run_dir = REPO_ROOT / rel
        if not run_dir.is_dir():
            print(f"  skipping {bench['key']}/{mode}: {rel} not found", file=sys.stderr)
            continue
        summary, cases = load_run(run_dir)
        modes.append(mode)
        per_mode[mode] = cases
        if summary:
            summaries[mode] = norm_summary(summary)
    ids = sorted({cid for cases in per_mode.values() for cid in cases},
                 key=lambda cid: (list(labels).index(cid) if cid in labels else len(labels), cid))
    cases_out = []
    for cid in ids:
        records = [per_mode[m][cid] for m in modes if cid in per_mode[m]]
        first = records[0]
        label = labels.get(cid, {})
        diff, truncated = case_diff(bench, cid, records, labels)
        cases_out.append({
            "id": cid,
            "title": first.get("title") or label.get("description") or first.get("description", ""),
            "category": first.get("category") or label.get("category", ""),
            "split": first.get("split") or label.get("split", ""),
            "expected": first.get("expected") or label.get("expected_verdict"),
            "url": first.get("url") or label.get("url"),
            "modes": {m: norm_case(per_mode[m][cid]) for m in modes if cid in per_mode[m]},
            "diff": diff,
            "diff_truncated": truncated,
        })
    return {
        "key": bench["key"],
        "title": bench["title"],
        "description": bench.get("description", ""),
        "modes": modes,
        "summaries": summaries,
        "cases": cases_out,
    }


def embed(data: dict) -> str:
    """JSON safe to place inside <script>: no '<' can close the tag early."""
    return json.dumps(data, separators=(",", ":")).replace("<", "\\u003c").replace(
        "\u2028", "\\u2028").replace("\u2029", "\\u2029")


def build(config: dict) -> str:
    sha = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    data = {
        "generated_at": datetime.datetime.now().isoformat(timespec="minutes"),
        "viewer_commit": sha or "unknown",
        "benchmarks": [build_benchmark(b) for b in config["benchmarks"]],
    }
    template = TEMPLATE.read_text(encoding="utf-8")
    if DATA_MARKER not in template:
        raise SystemExit(f"{TEMPLATE} has no data marker {DATA_MARKER!r}")
    return template.replace(DATA_MARKER, embed(data))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, default=HERE / "runs.json")
    parser.add_argument("--out", type=Path, default=HERE / "lgtm-viewer.html")
    args = parser.parse_args(argv)
    config = json.loads(args.config.read_text(encoding="utf-8"))
    html = build(config)
    args.out.write_text(html, encoding="utf-8")
    print(f"wrote {args.out} ({len(html) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
