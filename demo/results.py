"""Stored benchmark results, normalised for the dashboard: verdict, findings,
agent trace and the diff, read in place from the git-ignored result folders.

live_hunt results are never read: most of those leads are undisclosed.
"""

from __future__ import annotations

import json
import os
import re
import statistics
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
# The benchmark results the dashboard shows, committed with the repository (see benchmark-results/README.md).
# LGTM_DEMO_RESULTS points at another copy; LGTM_DEMO_CACHE at a clone cache (fetch.py), which is optional:
# without it, each case's diff comes from benchmark-results/diffs/.
RESULTS = Path(os.environ.get("LGTM_DEMO_RESULTS") or HERE / "benchmark-results")
SQLI = REALPRS = RESULTS
DIFFS = RESULTS / "diffs"
CACHE = Path(os.environ.get("LGTM_DEMO_CACHE") or REPO_ROOT / "benchmark" / "real_prs" / ".cache")
RUNS_DIR = HERE / ".runs"
CASE_FILES = {
    "development": REPO_ROOT / "benchmark" / "real_prs" / "cases.json",
    "heldout": REPO_ROOT / "benchmark" / "real_prs" / "heldout.json",
}

# Result sets shown in the UI. live_hunt results are deliberately absent: most
# of those leads are undisclosed and must never reach a screen.
DATASETS = [
    {"id": "heldout_v21", "label": "Held-out set · v2.1", "set": "heldout",
     "note": "17 advisories chosen after the SQLi reviewer was written; run once, not tuned on.",
     "modes": {"lgtm": SQLI / "heldout_v21" / "lgtm", "llm-only": SQLI / "heldout_v21" / "llm-only"}},
    {"id": "heldout_v20", "label": "Held-out set · v2.0", "set": "heldout",
     "note": "Same 17 advisories, before the section SQLi reviewer.",
     "modes": {"lgtm": SQLI / "heldout_v20" / "lgtm"}},
    {"id": "real_prs_sqli", "label": "Development set · v2.1 (SQLi)", "set": "development",
     "note": "The 4 SQL-injection advisories the SQLi reviewer was built on.",
     "modes": {"lgtm": SQLI / "real_prs_sqli" / "lgtm"}},
    {"id": "real_prs", "label": "Development set · v2.0", "set": "development",
     "note": "13 advisories: 4 SQLi, 9 authorization.",
     "modes": {"lgtm": REALPRS / "real_prs" / "lgtm", "llm-only": REALPRS / "real_prs" / "llm-only",
               "sast-only": REALPRS / "real_prs" / "sast-only"}},
    {"id": "live", "label": "Earlier demo runs", "set": "live",
     "note": "Advisory cases reviewed live from the first demo UI.", "modes": {"lgtm": RUNS_DIR}},
]
MODE_LABELS = {"lgtm": "LGTM (full pipeline)", "llm-only": "Plain LLM", "sast-only": "Semgrep only"}
TRACE_RESULT_CHARS = 1600
DIFF_LINE_BUDGET = 2500
OLLAMA = ("127.0.0.1", 11435)
KEV = ("127.0.0.1", 8008)


# ---------------------------------------------------------------------------
# Stored results
# ---------------------------------------------------------------------------
def load_advisories() -> dict[str, dict]:
    out = {}
    for set_name, path in CASE_FILES.items():
        for case in json.loads(path.read_text(encoding="utf-8"))["cases"]:
            out[case["id"]] = {**case, "set": set_name}
    return out


ADVISORIES = load_advisories()


def result_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.json") if p.name != "summary.json")


def dataset(ds_id: str) -> dict:
    for ds in DATASETS:
        if ds["id"] == ds_id:
            return ds
    raise KeyError(ds_id)


def case_row(record: dict, ds_id: str, mode: str) -> dict:
    return {
        "id": record.get("id"), "advisory": record.get("advisory"), "repo": record.get("repo"),
        "title": record.get("title", ""), "category": record.get("category"), "cwe": record.get("cwe"),
        "expected": record.get("expected"), "predicted": record.get("predicted"),
        "outcome": record.get("outcome"), "on_target": record.get("on_target"),
        "n_findings": record.get("n_findings", 0),
        "n_flagged": len(record.get("vulnerable_findings") or []),
        "latency_seconds": record.get("latency_seconds"), "dataset": ds_id, "mode": mode,
        "added_lines": record.get("added_lines"), "backend": record.get("backend"),
        "started_at": record.get("started_at"),
    }


def list_datasets() -> list[dict]:
    out = []
    for ds in DATASETS:
        modes = []
        for mode, directory in ds["modes"].items():
            rows = []
            for path in result_files(directory):
                try:
                    rows.append({**case_row(json.loads(path.read_text(encoding="utf-8")), ds["id"], mode),
                                 "key": path.stem})
                except (OSError, json.JSONDecodeError):
                    continue
            if ds["id"] == "live":
                rows.sort(key=lambda r: r.get("started_at") or "", reverse=True)
            modes.append({"mode": mode, "label": MODE_LABELS[mode], "cases": rows})
        out.append({"id": ds["id"], "label": ds["label"], "set": ds["set"], "note": ds["note"], "modes": modes})
    return out


def load_record(ds_id: str, mode: str, case_id: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", case_id):
        raise KeyError(case_id)
    path = dataset(ds_id)["modes"][mode] / f"{case_id}.json"
    if not path.is_file():
        raise KeyError(case_id)
    return json.loads(path.read_text(encoding="utf-8"))


def agent_of(section: str) -> str:
    if section == "investigator":
        return "investigator"
    if section.startswith("sast_triage:"):
        return "sast_triage"
    if section.startswith("sqli:"):
        return "sqli_reviewer"
    return "authz_reviewer"


TOOL_KINDS = {"read_file": "code", "grep_repo": "code", "search_policy": "rag",
              "investigate_base_code": "graph", "investigate_pr_code": "graph"}


def normalise_trace(record: dict) -> dict:
    runs = []
    for run in (record.get("trace") or {}).get("runs", []):
        calls = []
        for turn in run.get("turns", []):
            for call in turn.get("tool_calls") or []:
                result = str(call.get("result") or "")
                calls.append({
                    "tool": call.get("tool"), "kind": TOOL_KINDS.get(call.get("tool"), "other"),
                    "args": call.get("args") or {},
                    "result": result[:TRACE_RESULT_CHARS], "result_chars": len(result),
                })
        section = run.get("section", "")
        runs.append({"section": section, "agent": agent_of(section),
                     "label": section.split(":", 1)[1] if ":" in section else section,
                     "turns": len(run.get("turns", [])), "calls": calls})
    return {"runs": runs, "kev": (record.get("trace") or {}).get("kev", [])}


def finding_flagged(f: dict, mode: str) -> bool:
    if mode == "lgtm":
        return bool(f.get("supported")) and f.get("kev_verdict") != "not_real"
    return f.get("verdict") == "vulnerable"


def severity_of(f: dict) -> str:
    sev = (f.get("kev_severity") or f.get("severity") or f.get("semgrep_severity") or "").lower()
    return {"error": "high", "warning": "medium", "info": "low"}.get(sev, sev) or "unrated"


def normalise_findings(record: dict, mode: str) -> list[dict]:
    out = []
    for f in record.get("findings") or []:
        out.append({
            "id": f.get("finding_id"), "agent": f.get("agent"), "category": f.get("category"),
            "file": f.get("file"), "line": f.get("line"), "cwe": f.get("cwe_id"),
            "severity": severity_of(f), "explanation": f.get("explanation", ""),
            "suggested_fix": f.get("suggested_fix", ""),
            "evidence": [
                {"type": e.get("type"), "file": e.get("file"), "lines": e.get("lines"),
                 "content": e.get("content") or "", "source": e.get("source"),
                 "grounded_in_pr": e.get("grounded_in_pr")}
                for e in f.get("evidence") or []
            ],
            "supported": f.get("supported"), "kev_verdict": f.get("kev_verdict"),
            "judged": f.get("judged"), "not_judged_reason": f.get("not_judged_reason"),
            "unsupported_reason": f.get("unsupported_reason"),
            "confidence": f.get("provenance_confidence"), "tool_calls": f.get("tool_calls_used", 0),
            "semgrep_rule": f.get("semgrep_rule_id"), "llm_verdict": f.get("verdict"),
            "flagged": finding_flagged(f, mode),
        })
    out.sort(key=lambda f: (not f["flagged"], f["file"] or "", f["line"] or 0))
    return out


# ---------------------------------------------------------------------------
# Diffs, read from the cached clones
# ---------------------------------------------------------------------------
_DIFF_CACHE: dict[tuple, dict] = {}
HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)")


def clone_for(repo: str) -> Path:
    return CACHE / repo.split("/")[-1]


def build_diff(repo: str, base: str, head: str, keep: set[str], clone: Path | None = None,
               context: int = 4) -> dict:
    clone = clone or clone_for(repo)
    key = (str(clone), base, head, tuple(sorted(keep)), context)
    if key in _DIFF_CACHE:
        return _DIFF_CACHE[key]
    if not base or not head:
        return {"files": [], "available": False, "reason": "clone not cached"}
    stored = DIFFS / repo.split("/")[-1] / f"{base}..{head}.patch"
    if (clone / ".git").exists():
        proc = subprocess.run(
            ["git", "-C", str(clone), "diff", "--no-color", "--no-ext-diff", f"-U{context}", "--find-renames",
             base, head, "--", "*.py"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=60,
        )
        if proc.returncode != 0 and not stored.is_file():
            return {"files": [], "available": False, "reason": "commits not in the cache"}
        text = proc.stdout if proc.returncode == 0 else stored.read_text(encoding="utf-8")
    elif stored.is_file():   # the committed copy of this case's diff (-U4, Python files)
        text = stored.read_text(encoding="utf-8")
    else:
        return {"files": [], "available": False, "reason": "clone not cached"}
    files = parse_diff(text)
    used = 0
    # Files with findings first, so the budget never hides what the review flagged.
    for fd in sorted(files, key=lambda fd: fd["path"] not in keep):
        size = sum(len(h["lines"]) for h in fd["hunks"])
        if fd["path"] in keep or used + size <= DIFF_LINE_BUDGET:
            used += size
        else:
            fd["collapsed"] = True
            fd["hunks"] = []
    out = {"files": files, "available": True}
    _DIFF_CACHE[key] = out
    return out


def parse_diff(text: str) -> list[dict]:
    files: list[dict] = []
    fd = hunk = None
    old = new = 0
    for line in text.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.*) b/(.*)", line)
            fd = {"path": m.group(2) if m else line, "old_path": m.group(1) if m else "",
                  "status": "modified", "additions": 0, "deletions": 0, "hunks": [], "collapsed": False}
            files.append(fd)
            hunk = None
        elif fd is None:
            continue
        elif line.startswith("new file mode"):
            fd["status"] = "added"
        elif line.startswith("deleted file mode"):
            fd["status"] = "deleted"
        elif line.startswith("rename from"):
            fd["status"] = "renamed"
        elif line.startswith("@@"):
            m = HUNK_RE.match(line)
            if not m:
                continue
            old, new = int(m.group(1)), int(m.group(3))
            hunk = {"header": line, "context": m.group(5).strip(), "lines": []}
            fd["hunks"].append(hunk)
        elif hunk is not None and line[:1] in ("+", "-", " ") and not line.startswith(("+++", "---")):
            t = line[0]
            if t == "+":
                hunk["lines"].append({"t": "+", "old": None, "new": new, "text": line[1:]})
                new += 1
                fd["additions"] += 1
            elif t == "-":
                hunk["lines"].append({"t": "-", "old": old, "new": None, "text": line[1:]})
                old += 1
                fd["deletions"] += 1
            else:
                hunk["lines"].append({"t": " ", "old": old, "new": new, "text": line[1:]})
                old += 1
                new += 1
    return files


def verdict_of(record: dict, findings: list[dict]) -> str:
    if record.get("crashed") or record.get("outcome") == "ERROR":
        return "error"
    return "vulnerable" if any(f["flagged"] for f in findings) else "safe"


def normalise(record: dict, ds_id: str, mode: str, clone: Path | None = None) -> dict:
    findings = normalise_findings(record, mode)
    adv = ADVISORIES.get(record.get("advisory") or "", {})
    keep = {f["file"] for f in findings if f["file"]}
    diff = build_diff(record.get("repo", ""), record.get("base", ""), record.get("pr_sha", ""), keep, clone)
    verdict = verdict_of(record, findings)
    meta_keys = ["id", "advisory", "repo", "title", "url", "ghsa", "cwe", "category", "expected",
                 "predicted", "outcome", "on_target", "vulnerable_files", "model", "mode",
                 "latency_seconds", "base", "pr_sha", "files_changed", "python_files_changed",
                 "added_lines", "semgrep_findings_total", "semgrep_findings_in_diff", "changed_endpoints",
                 "investigator_tool_calls", "reviewer_tool_calls", "reviewer_units",
                 "sast_triage_tool_calls", "sast_triage_units", "index_chunks", "error", "backend",
                 "started_at"]
    meta = {k: record.get(k) for k in meta_keys}
    meta["advisory_title"] = adv.get("title")
    meta["advisory_where"] = adv.get("where")
    meta["advisory_url"] = adv.get("advisory_url")
    meta["advisory_severity"] = adv.get("severity")
    meta["cve"] = adv.get("cve")
    meta["framework"] = adv.get("framework")
    meta["set"] = adv.get("set")
    return {"dataset": ds_id, "mode": mode, "mode_label": MODE_LABELS.get(mode, mode),
            "verdict": verdict, "meta": meta, "findings": findings,
            "trace": normalise_trace(record), "diff": diff}


# ---------------------------------------------------------------------------
# Benchmark overview
# ---------------------------------------------------------------------------
def benchmark() -> list[dict]:
    out = []
    for ds in DATASETS:
        if ds["id"] == "live":
            continue
        modes = []
        for mode, directory in ds["modes"].items():
            recs = []
            for path in result_files(directory):
                try:
                    recs.append(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue
            n = {k: sum(1 for r in recs if r.get("outcome") == k) for k in ("TP", "FP", "FN", "TN", "ERROR")}
            lat = sorted(r["latency_seconds"] for r in recs if r.get("latency_seconds") is not None)
            modes.append({
                "mode": mode, "label": MODE_LABELS[mode], **n,
                "advisories": len({r.get("advisory") for r in recs}),
                "on_target": sum(1 for r in recs if r.get("outcome") == "TP" and r.get("on_target")),
                "median_latency": round(statistics.median(lat), 1) if lat else None,
            })
        out.append({"id": ds["id"], "label": ds["label"], "note": ds["note"], "modes": modes})
    return out

