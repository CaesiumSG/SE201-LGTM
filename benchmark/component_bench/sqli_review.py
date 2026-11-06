"""SQLi reviewer benchmark: gold section in, finding locations scored against the gold sink function."""

from __future__ import annotations

import json
import subprocess
from functools import cache
from pathlib import Path

from benchmark.component_bench.authz import CLONE_CACHE, _inside, build_section, case_reader  # noqa: F401 - run.py wires read_source via mod.case_reader
from benchmark.component_bench.outcomes import InfraError, NotScored
from benchmark.component_bench.schema import load_cases
from lgtm.agents.sqli_reviewer import SQLiReviewerAgent, needs_sql_review
from lgtm.agents.tools import AgentToolbox
from lgtm.pipeline import ReviewPipeline
from lgtm.review.dedup import dedup_findings
from lgtm.sast.semgrep_runner import SemgrepFinding

SAST_LABELS = Path(__file__).resolve().parent / "labels" / "sast-sqli.json"


def build_toolbox(item: dict, ctx) -> AgentToolbox:
    case = next(c for c in load_cases() if c["id"] == item["case_id"])
    project = case["repo_url"].rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    clone = CLONE_CACHE / project
    for sha in (case["base_ref"], case["pr_ref"]):
        found = clone.is_dir() and subprocess.run(
            ["git", "-C", str(clone), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
        ).returncode == 0
        if not found:
            raise InfraError(f"case clone or commit missing: {clone} {sha}")
    return AgentToolbox(
        clone, case["base_ref"], config=ctx.config, shas={"base": case["base_ref"], "pr": case["pr_ref"]}
    )


@cache
def _kept_sast_hits() -> dict[str, list[SemgrepFinding]]:
    """Semgrep hits the sast-sqli labels keep, per case: the stand-in for SAST triage output."""
    hits: dict[str, list[SemgrepFinding]] = {}
    for label in json.loads(SAST_LABELS.read_text(encoding="utf-8"))["items"]:
        if label["gold"]["keep"]:
            fields = {k: v for k, v in label["gold_input"].items() if k != "excerpt"}
            fields.setdefault("cwe", ["CWE-89"])
            hits.setdefault(label["case_id"], []).append(SemgrepFinding(**fields))
    return hits


def run_item(item: dict, ctx) -> list[dict] | NotScored:
    section = build_section(item["gold_input"])
    toolbox = build_toolbox(item, ctx)
    if not needs_sql_review(section, toolbox):
        return NotScored("gold section has no SQL signal; the pipeline would not send it to the SQLi reviewer")
    hits = [h for h in _kept_sast_hits().get(item["case_id"], []) if h.path in section.files]
    notes = "\n".join(f"- {h.rule_id} at {h.path}:{h.start_line}: {h.message}" for h in hits)
    agent = SQLiReviewerAgent(toolbox, ctx.config, llm=ctx.llm)
    reviewed = agent.review_section(section, notes)
    ctx.metrics.add_agent("reviewer", agent.run_records, toolbox.build_tools())
    if agent.errors:
        if all(e.get("kind") == "unparsable" for e in agent.errors):
            return NotScored("; ".join(e["message"] for e in agent.errors))
        raise InfraError("; ".join(e["message"] for e in agent.errors))
    triaged = [ReviewPipeline._sast_finding_to_agent_finding(h) for h in hits]
    sast_evidence = [e for t in triaged for e in t.evidence]
    # Reviewer findings first: a merged group keeps the first finding's location.
    merged = dedup_findings([*reviewed, *triaged])
    return [
        {"file": f.file, "line": f.line, "sast_also": any(e in sast_evidence for e in f.evidence)}
        for f in merged
        if f.agent != "semgrep"
    ]


def score(item: dict, output: list[dict], read_source=None) -> dict:
    gold = item["gold"]
    sinks = {(f["file"], f["line"]): f for f in output}.values()
    if gold["vulnerable"]:
        ranges = [(r, "pr") for r in gold["locations"]] + [(r, "base") for r in gold.get("old_locations", [])]
        hits = [f for f in sinks if _inside(f, ranges, read_source)]
        fp = len(sinks) - len(hits)
        also = any(f["sast_also"] for f in hits)
        return {
            "tp": int(bool(hits)), "fn": int(not hits), "fp": fp, "tn": 0,
            "sast_also": int(bool(hits) and also), "reviewer_only": int(bool(hits) and not also),
        }
    known = [(r, "pr") for r in gold["known_issues"]]
    fp = sum(not _inside(f, known, read_source) for f in sinks)
    return {"tp": 0, "fn": 0, "fp": fp, "tn": int(fp == 0), "sast_also": 0, "reviewer_only": 0}


def aggregate(units, results_dir):
    keys = ("tp", "fn", "fp", "sast_also", "reviewer_only")
    total = {k: sum(u["scores"][k] for u in units if u["status"] == "scored") for k in keys}
    tp, fn, fp = total["tp"], total["fn"], total["fp"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "hits": tp, "false_positives": fp, "precision": precision, "recall": recall, "f1": f1,
        "sast_also": total["sast_also"], "reviewer_only": total["reviewer_only"],
    }
