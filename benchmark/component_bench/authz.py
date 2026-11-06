"""Authz reviewer benchmark: gold section and gold policy passages in, finding locations scored."""

from __future__ import annotations

import subprocess
from pathlib import Path

from benchmark.component_bench.outcomes import InfraError, NotScored, finding_record, production_toolbox, track
from benchmark.component_bench.schema import load_cases
from benchmark.real_world.fetch import project_of
from lgtm.agents.authz_reviewer import AuthzReviewerAgent, _enclosing_functions
from lgtm.agents.tools import AgentToolbox
from lgtm.diff.git_diff import LineChange
from lgtm.review.sections import HunkRef, Section

CLONE_CACHE = Path(__file__).resolve().parents[1] / "real_world" / ".cache"


_KIND = {"+": "add", "-": "del", " ": "context"}


def _hunk(n: int, spec: dict) -> HunkRef:
    """Builds a hunk from unified-diff lines (prefix `+`, `-` or space); line numbers follow from the start lines."""
    old, new = spec["old_start"], spec["new_start"]
    changes = []
    for line in spec["lines"]:
        kind = _KIND[line[0]]
        changes.append(
            LineChange(kind, line[1:], old if kind != "add" else None, new if kind != "del" else None)
        )
        old += kind != "add"
        new += kind != "del"
    kinds = {c.kind for c in changes} - {"context"}
    change = "add" if kinds == {"add"} else "delete" if kinds == {"del"} else "mixed"
    return HunkRef(
        f"h{n}", spec["file"], spec["old_start"], old - spec["old_start"],
        spec["new_start"], new - spec["new_start"], change, changes,
    )


def build_section(gold_input: dict) -> Section:
    spec = gold_input["section"]
    hunks = [_hunk(n, h) for n, h in enumerate(spec["hunks"], 1)]
    return Section(
        section_id=spec["section_id"],
        origin="investigator",
        title=spec["title"],
        rationale=spec.get("rationale", ""),
        files=spec["files"],
        hunks=hunks,
    )


def build_toolbox(item: dict, ctx) -> AgentToolbox:
    case = next(c for c in load_cases() if c["id"] == item["case_id"])
    toolbox = production_toolbox(CLONE_CACHE / project_of(case), case, ctx.config, ctx.results_dir)
    track(ctx, toolbox)
    return toolbox


def run_item(item: dict, ctx) -> list[dict]:
    section = build_section(item["gold_input"])
    toolbox = build_toolbox(item, ctx)
    agent = AuthzReviewerAgent(toolbox, ctx.config, llm=ctx.llm)
    findings = agent.review_section(section)
    ctx.metrics.add_agent("reviewer", agent.run_records, toolbox.build_tools())
    if agent.errors:
        messages = "; ".join(e["message"] for e in agent.errors)
        if all(e["kind"] == "unparsable" for e in agent.errors):
            return NotScored(messages)
        raise InfraError(messages)
    ctx.record = finding_record(findings)
    return [{"file": f.file, "line": f.line} for f in findings]


def case_reader(item: dict):
    """`read_source(file, side)` over the case clone at the pr or base ref."""
    case = next(c for c in load_cases() if c["id"] == item["case_id"])
    clone = CLONE_CACHE / case["repo_url"].rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    refs = {"pr": case["pr_ref"], "base": case["base_ref"]}

    def read_source(file: str, side: str) -> str:
        shown = subprocess.run(
            ["git", "-C", str(clone), "show", f"{refs[side]}:{file}"], capture_output=True, check=True
        )
        return shown.stdout.decode("utf-8", errors="replace")

    return read_source


def _inside(finding: dict, ranges: list[tuple[dict, str]], read_source) -> bool:
    """PR-side range: exact range or same enclosing function. Base-side range: the finding's PR-side function name equals the range's function name, or the line is in base coordinates inside the range or its function and in no PR-side function."""
    line = finding["line"]
    for r, side in ranges:
        if r["file"] != finding["file"]:
            continue
        exact = r["start"] <= line <= r["end"]
        if exact and side == "pr":
            return True
        if read_source is None:
            if exact:
                return True
            continue
        try:
            pr_source = read_source(r["file"], "pr")
            range_source = pr_source if side == "pr" else read_source(r["file"], side)
        except Exception:  # noqa: BLE001 - unreadable file keeps exact-range scoring
            if exact:
                return True
            continue
        mine = _enclosing_functions(pr_source, [line])
        theirs = _enclosing_functions(range_source, [r["start"], r["end"]])
        if mine and mine[0][2] in {t[2] for t in theirs}:
            return True
        if side == "base" and not mine and (exact or any(t[0] <= line <= t[1] for t in theirs)):
            return True
    return False


def score(item: dict, output: list[dict], read_source=None) -> dict:
    gold = item["gold"]
    if gold["vulnerable"]:
        ranges = [(r, "pr") for r in gold["locations"]] + [(r, "base") for r in gold.get("old_locations", [])]
        hit = any(_inside(f, ranges, read_source) for f in output)
        fp = sum(not _inside(f, ranges, read_source) for f in output)
        return {"tp": int(hit), "fn": int(not hit), "fp": fp, "tn": 0, "verdict_correct": float(hit)}
    known = [(r, "pr") for r in gold["known_issues"]]
    fp = sum(not _inside(f, known, read_source) for f in output)
    return {"tp": 0, "fn": 0, "fp": fp, "tn": int(fp == 0), "verdict_correct": float(fp == 0)}


def aggregate(units, results_dir):
    total = {k: sum(u["scores"][k] for u in units if u["status"] == "scored") for k in ("tp", "fn", "fp", "tn")}
    tp, fn, fp = total["tp"], total["fn"], total["fp"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {**total, "precision": precision, "recall": recall, "f1": f1}
