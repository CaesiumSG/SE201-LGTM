"""Shared guidance data and prompts for both agents across graph and no-graph runs (N1)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

from lgtm.agents.authz_reviewer import AuthzReviewerAgent, ChangedEndpoint
from lgtm.agents.base import run_tool_loop
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.graph.session import GraphSession
from lgtm.graph.snapshot import resolve_refs
from lgtm.sast.semgrep_runner import SemgrepFinding
from tests.graph_fakes import FakeRunner

SAFE = json.dumps({"verdict": "safe", "confidence": 0.9, "explanation": "ok"})
GRAPH_NAMES = [
    "investigate_base_code",
    "investigate_pr_code",
    "read_file",
    "grep_repo",
    "search_policy",
]
READ_NAMES = ["read_file", "grep_repo", "search_policy"]
BUDGET = 4

SCENARIOS = {
    "graph": dict(names=GRAPH_NAMES, graph=True, labels=["base", "pr"]),
    "missing_binary": dict(names=READ_NAMES, graph=False, labels=["base", "pr"]),
    "legacy": dict(names=READ_NAMES, graph=False, labels=["base"]),
}


class _Msg(SimpleNamespace):
    pass


class ScriptedLLM:
    def __init__(self, script):
        self.script = list(script)
        self.seen = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.seen.append(list(messages))
        return _Msg(content=self.script.pop(0), tool_calls=[])


def _build_toolbox(scenario, repo, config):
    if scenario == "legacy":
        return AgentToolbox(repo, "main", None, config), None, None
    shas = resolve_refs(repo, "main", "pr")
    runner = FakeRunner(available=scenario == "graph")
    session = GraphSession(repo, shas, config, runner=runner)
    try:
        toolbox = AgentToolbox(repo, "main", None, config, shas=shas, session=session)
    except TypeError:
        # Wiring keywords are asserted in tests/test_graph_tools.py; keep the matrix running.
        toolbox = AgentToolbox(repo, "main", None, config)
    return toolbox, session, runner


@pytest.fixture(params=list(SCENARIOS))
def scenario(request, git_repo):
    config = LGTMConfig(max_tool_calls=BUDGET, require_tool_use=False)
    toolbox, session, runner = _build_toolbox(request.param, git_repo, config)
    yield SimpleNamespace(
        name=request.param, toolbox=toolbox, config=config, runner=runner, session=session,
        expect=SCENARIOS[request.param],
    )
    if session is not None:
        session.close()


def _run_agent(kind, sc, script, config=None):
    config = config or sc.config
    llm = ScriptedLLM(script)
    if kind == "sast_triage":
        finding = SemgrepFinding(
            rule_id="r", path="app.py", start_line=2, end_line=2, message="m",
            severity="ERROR", matched_code="cursor.execute(x)",
        )
        SASTTriageAgent(sc.toolbox, config, llm=llm).triage(finding, None)
    else:
        endpoint = ChangedEndpoint(file="app.py", route_path="/u", http_methods=["GET"], decorator_line=1)
        AuthzReviewerAgent(sc.toolbox, config, llm=llm).review(endpoint, None)
    return llm


def _prompt(llm):
    return "\n".join(str(m.content) for m in llm.seen[0])


def _sentences(text):
    return [s for s in re.split(r"(?<=[.!?])\s+|\n", text) if s.strip()]


AGENTS = ["sast_triage", "authz_reviewer"]


@pytest.fixture
def prompt_parts():
    return pytest.importorskip(
        "lgtm.agents.prompt_parts",
        reason="module is created by this slice and does not exist yet",
    )


def _guidance(module, toolbox):
    assert hasattr(module, "tool_guidance"), "prompt_parts must expose tool_guidance(toolbox)"
    data = module.tool_guidance(toolbox)
    get = (lambda k: data[k]) if isinstance(data, dict) else (lambda k: getattr(data, k))
    return get


class TestSharedGuidanceData:
    def test_fields_describe_exactly_what_is_registered(self, prompt_parts, scenario):
        get = _guidance(prompt_parts, scenario.toolbox)
        assert list(get("tool_names")) == scenario.expect["names"]
        assert list(get("tool_names")) == [t.name for t in scenario.toolbox.build_tools()]
        assert get("graph_tools") is scenario.expect["graph"]
        assert list(get("snapshot_labels")) == scenario.expect["labels"]
        assert get("max_tool_calls") == BUDGET
        assert type(get("max_tool_calls")) is int and get("max_tool_calls") > 0

    def test_reading_guidance_uses_no_budget_and_starts_no_graph_work(self, prompt_parts, scenario):
        _guidance(prompt_parts, scenario.toolbox)("tool_names")
        assert scenario.toolbox.calls_used == 0
        if scenario.runner is not None:
            assert scenario.runner.calls == []
            assert scenario.session.init_seconds == 0.0 and scenario.session.state in (
                "ok", "unavailable:missing"
            )

    def test_prompt_parts_import_leaves_the_graph_package_unloaded(self, prompt_parts):
        code = (
            "import sys, lgtm.agents.prompt_parts\n"
            "print(sorted(m for m in sys.modules if m.startswith('lgtm.graph')))\n"
        )
        done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "[]"


@pytest.mark.parametrize("kind", AGENTS)
class TestAgentPromptMatrix:
    def test_prompt_names_every_registered_tool(self, kind, scenario):
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        for name in scenario.expect["names"]:
            assert name in text, f"{kind}/{scenario.name}: prompt does not mention {name}"

    def test_prompt_never_advertises_an_unregistered_tool(self, kind, scenario):
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        assert "search_code" not in text
        if not scenario.expect["graph"]:
            assert "investigate_" not in text

    def test_prompt_reports_the_configured_budget(self, kind, scenario):
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        assert re.search(rf"\b{BUDGET}\b", text)

    def test_graph_prompt_prefers_graph_tools_and_falls_back_to_same_label_reads(self, kind, scenario):
        if not scenario.expect["graph"]:
            pytest.skip("graph guidance only applies when graph tools are registered")
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        flat = " ".join(text.split())
        assert re.search(r"(prefer|first|start with)\W.{0,200}investigate_|investigate_.{0,200}(prefer|first)", flat, re.I)
        lowered = flat.lower()
        assert re.search(r"same[- ](snapshot|label)", lowered)
        for state in ("unavailable", "truncated", "unindexed"):
            assert state in lowered, f"fallback trigger '{state}' missing"
        assert re.search(r"\bsnapshot\b.{0,120}\bpr\b|\bpr\b.{0,120}\bsnapshot\b", lowered)

    def test_graph_prompt_never_claims_no_match_or_missing_edge_proves_safety(self, kind, scenario):
        if not scenario.expect["graph"]:
            pytest.skip("graph guidance only applies when graph tools are registered")
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        caveats = [
            s for s in _sentences(text)
            if re.search(r"no[ _-]match|missing edge", s, re.I)
            and re.search(r"safe|safety|prove|proof|establish|saving", s, re.I)
            and re.search(r"\bnot\b|\bnever\b|n't|\bcannot\b", s, re.I)
        ]
        assert caveats, "prompt must say a no-match or missing edge is not proof of safety"
        assert not [
            s for s in _sentences(text)
            if re.search(r"no[ _-]match|missing edge", s, re.I)
            and re.search(r"\b(means|implies|proves) (it is )?safe", s, re.I)
        ]

    def test_pushback_names_exactly_the_registered_tools(self, kind, scenario):
        config = LGTMConfig(max_tool_calls=BUDGET, require_tool_use=True)
        llm = _run_agent(kind, scenario, [SAFE, SAFE], config)
        pushback = llm.seen[1][-1].content
        for name in scenario.expect["names"]:
            assert name in pushback, f"{kind}/{scenario.name}: push-back omits {name}"
        assert "search_code" not in pushback
        if not scenario.expect["graph"]:
            assert "investigate_" not in pushback


class TestPushBackFollowsTheToolList:
    def test_names_come_from_the_tools_handed_to_the_loop(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        only_read = [t for t in toolbox.build_tools() if t.name == "read_file"]
        llm = ScriptedLLM([SAFE, SAFE])
        run_tool_loop(llm, only_read, "sys", "user", LGTMConfig(require_tool_use=True))
        pushback = llm.seen[1][-1].content
        assert "read_file" in pushback
        assert "grep_repo" not in pushback and "search_policy" not in pushback

