"""Authz reviewer benchmark: gold section and gold policy passages in, finding locations scored."""

from __future__ import annotations

import subprocess
from pathlib import Path

from benchmark.component_bench.outcomes import InfraError
from benchmark.component_bench.schema import load_cases
from lgtm.agents.authz_reviewer import AuthzReviewerAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.diff.git_diff import LineChange
from lgtm.review.sections import HunkRef, Section

CLONE_CACHE = Path(__file__).resolve().parents[1] / "real_world" / ".cache"


class GoldPolicy:
    """Retriever stand-in that returns the labelled passages for every query."""

    def __init__(self, passages: list[str]):
        self.text = "\n\n".join(passages)

    def format_results(self, query: str) -> str:
        return self.text


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
    project = case["repo_url"].rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    clone = CLONE_CACHE / project
    for sha in (case["base_ref"], case["pr_ref"]):
        found = clone.is_dir() and subprocess.run(
            ["git", "-C", str(clone), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
        ).returncode == 0
        if not found:
            raise InfraError(f"case clone or commit missing: {clone} {sha}")
    return AgentToolbox(
        clone,
        case["base_ref"],
        retriever=GoldPolicy(item["gold_input"]["policy_passages"]),
        config=ctx.config,
        shas={"base": case["base_ref"], "pr": case["pr_ref"]},
    )


def run_item(item: dict, ctx) -> list[dict]:
    section = build_section(item["gold_input"])
    toolbox = build_toolbox(item, ctx)
    agent = AuthzReviewerAgent(toolbox, ctx.config, llm=ctx.llm)
    findings = agent.review_section(section)
    ctx.metrics.add_agent("reviewer", agent.run_records, toolbox.build_tools())
    if agent.errors:
        raise InfraError("; ".join(e["message"] for e in agent.errors))
    return [{"file": f.file, "line": f.line} for f in findings]


def _inside(finding: dict, ranges: list[dict]) -> bool:
    return any(r["file"] == finding["file"] and r["start"] <= finding["line"] <= r["end"] for r in ranges)


def score(item: dict, output: list[dict]) -> dict:
    gold = item["gold"]
    if gold["vulnerable"]:
        ranges = gold["locations"] + gold.get("old_locations", [])
        hit = any(_inside(f, ranges) for f in output)
        fp = sum(not _inside(f, ranges) for f in output)
        return {"tp": int(hit), "fn": int(not hit), "fp": fp, "tn": 0}
    fp = sum(not _inside(f, gold["known_issues"]) for f in output)
    return {"tp": 0, "fn": 0, "fp": fp, "tn": int(fp == 0)}
