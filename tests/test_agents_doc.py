"""docs/agents.md lists each agent's registry entries and tools and fails on drift from the code."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.agents import authz_reviewer, investigator, sast_triage
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.review.sections import HunkRef, LineChange, Section
from lgtm.sast.semgrep_runner import SemgrepFinding

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "agents.md"
REGISTRY = ROOT / "src" / "lgtm" / "agents" / "prompts.toml"
AGENTS = ("sast_triage", "authz_reviewer", "plain_reviewer", "investigator")
GRAPH_TOOLS = {"investigate_base_code", "investigate_pr_code"}
KNOWN_TOOLS = GRAPH_TOOLS | {"read_file", "grep_repo", "search_policy"}
SHAS = {"base": "a" * 40, "pr": "b" * 40}
SESSION_UP = SimpleNamespace(available=True, state="")
SESSION_MISSING = SimpleNamespace(available=False, state="")

CONDITIONS = {
    "all_met": dict(shas=SHAS, session=SESSION_UP),
    "no_snapshot_shas": dict(shas=None, session=SESSION_UP),
    "no_graph_session": dict(shas=SHAS, session=None),
    "graph_missing_at_startup": dict(shas=SHAS, session=SESSION_MISSING),
}


def _run_sast_triage(toolbox):
    finding = SemgrepFinding(
        rule_id="r", path="app.py", start_line=1, end_line=1, message="m", severity="ERROR"
    )
    sast_triage.SASTTriageAgent(toolbox, LGTMConfig(), llm=object()).triage(finding, None)


def _run_authz_reviewer(toolbox):
    hunk = HunkRef(
        hunk_id="app.py#1", file="app.py", old_start=1, old_count=0, new_start=1,
        new_count=1, change="add", changes=[LineChange("add", "x = 1", None, 1)],
    )
    section = Section(
        section_id="s1", origin="investigator", title="t", files=["app.py"], hunks=[hunk], rationale="r"
    )
    authz_reviewer.AuthzReviewerAgent(toolbox, LGTMConfig(), llm=object()).review_section(section)


def _run_investigator(toolbox):
    investigator.run_investigator([], LGTMConfig(), toolbox, object())


# Each entry point is run to completion except the model call, which is replaced by a recorder.
ENTRY_POINTS = {
    "sast_triage": (sast_triage, _run_sast_triage),
    "authz_reviewer": (authz_reviewer, _run_authz_reviewer),
    "investigator": (investigator, _run_investigator),
}


def code_tools(agent: str, cond: dict) -> set[str]:
    """Names the agent's code hands to the model loop under the offering condition."""
    if agent not in ENTRY_POINTS:
        return set()
    module, run = ENTRY_POINTS[agent]
    handed: list[list] = []

    def record(llm, tools, system, user, config):
        handed.append(tools)
        return "{}"

    box = AgentToolbox(".", "HEAD", shas=cond["shas"], session=cond["session"])
    original = module.run_tool_loop
    module.run_tool_loop = record
    try:
        run(box)
    finally:
        module.run_tool_loop = original
    assert len(handed) == 1, f"{agent} did not reach its tool loop exactly once"
    return {t.name for t in handed[0]}


def sections(page: str) -> dict[str, str]:
    parts = re.split(r"^#{2,4} +(.+)$", page, flags=re.M)
    return {
        agent: body
        for heading, body in zip(parts[1::2], parts[2::2])
        for agent in AGENTS
        if agent in heading
    }


def tool_names(text: str) -> set[str]:
    names = re.findall(r"`([a-z_]+)(?:\([^`]*\))?`", text)
    return {n for n in names if n in KNOWN_TOOLS}


def documented_tools(body: str, graph_conditions_met: bool) -> set[str]:
    mentioned = tool_names(body)
    return mentioned if graph_conditions_met else mentioned - GRAPH_TOOLS


def problems(page: str, tools_for) -> list[str]:
    """Differences between the page and the registered tools; empty when in sync."""
    found = sections(page)
    issues = [f"no section for {a}" for a in AGENTS if a not in found]
    for agent, body in found.items():
        for name, cond in CONDITIONS.items():
            expected = tools_for(agent, cond)
            actual = documented_tools(body, name == "all_met")
            if actual != expected:
                issues.append(f"{agent}/{name}: page {sorted(actual)} != code {sorted(expected)}")
        graph_blocks = [p for p in re.split(r"\n\s*\n", body) if tool_names(p) & GRAPH_TOOLS]
        if graph_blocks and not all("graph" in p.lower() and "sha" in p.lower() for p in graph_blocks):
            issues.append(f"{agent}: graph tools lack their offering condition")
    return issues


@pytest.fixture(scope="module")
def page() -> str:
    assert PAGE.is_file(), "docs/agents.md is missing"
    return PAGE.read_text(encoding="utf-8")


def test_page_has_a_section_per_agent_citing_its_registry_entries(page):
    found = sections(page)
    assert set(found) == set(AGENTS)
    for agent, body in found.items():
        assert re.search(rf"`{agent}\.[A-Za-z0-9_.]+`", body), f"{agent} cites no registry entry"


def test_plain_reviewer_is_documented_as_given_no_tools(page):
    body = sections(page)["plain_reviewer"]
    assert tool_names(body) == set()
    assert re.search(r"\bno tools?\b|\bnone\b", body, re.I)


def test_graph_offering_condition_is_stated_for_each_conditional_tool(page):
    for agent in ("authz_reviewer", "investigator"):
        blocks = [
            p for p in re.split(r"\n\s*\n", sections(page)[agent]) if tool_names(p) & GRAPH_TOOLS
        ]
        assert tool_names("\n".join(blocks)) == GRAPH_TOOLS
        assert all("graph" in p.lower() and "sha" in p.lower() for p in blocks)


def test_documented_tools_equal_registered_tools_under_each_condition(page):
    assert problems(page, code_tools) == []


def test_every_cited_registry_entry_exists(page):
    registry = tomllib.loads(REGISTRY.read_text(encoding="utf-8"))
    cited = re.findall(rf"`((?:{'|'.join(registry)})\.[A-Za-z0-9_.]+)`", page)
    assert cited
    for entry in cited:
        node = registry
        for part in entry.split("."):
            assert isinstance(node, dict) and part in node, f"{entry} is not in the registry"
            node = node[part]


class TestDriftFailsTheCheck:
    @pytest.fixture
    def page(self):
        return PAGE.read_text(encoding="utf-8")

    def test_tool_removed_from_page(self, page):
        assert problems(re.sub(r"`search_policy(\([^`]*\))?`", "search policy", page), code_tools)

    def test_tool_renamed_in_page(self, page):
        assert problems(re.sub(r"`grep_repo(\([^`]*\))?`", "`grep_repository`", page), code_tools)

    def test_tool_added_in_code(self, page):
        assert problems(page, lambda a, c: code_tools(a, c) | {"new_tool"})

    def test_condition_dropped_from_page(self, page):
        assert problems(re.sub(r"(?i)\bgraph\b", "index", page), code_tools)
