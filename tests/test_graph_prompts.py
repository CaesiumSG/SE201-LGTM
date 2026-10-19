"""Shared guidance data and prompts for both agents across graph and no-graph runs (N1)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

from lgtm.agents import prompt_parts
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
    toolbox = AgentToolbox(repo, "main", None, config, shas=shas, session=session)
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
def graph_scenario(git_repo):
    config = LGTMConfig(max_tool_calls=BUDGET, require_tool_use=False)
    toolbox, session, runner = _build_toolbox("graph", git_repo, config)
    yield SimpleNamespace(
        name="graph", toolbox=toolbox, config=config, runner=runner, session=session,
        expect=SCENARIOS["graph"],
    )
    session.close()


def _guidance(toolbox):
    data = prompt_parts.tool_guidance(toolbox)
    return lambda k: getattr(data, k)


def _guidance_section(toolbox):
    return prompt_parts.render_tool_section(prompt_parts.tool_guidance(toolbox))


def _flat(text):
    return " ".join(text.split())


def _guidance_sentences(section):
    return [s for s in _sentences(section) if not s.lstrip().startswith("-")]


class TestSharedGuidanceData:
    def test_fields_describe_exactly_what_is_registered(self, scenario):
        get = _guidance(scenario.toolbox)
        assert list(get("tool_names")) == scenario.expect["names"]
        assert list(get("tool_names")) == [t.name for t in scenario.toolbox.build_tools()]
        assert get("graph_tools") is scenario.expect["graph"]
        assert list(get("snapshot_labels")) == scenario.expect["labels"]
        assert get("max_tool_calls") == BUDGET
        assert type(get("max_tool_calls")) is int and get("max_tool_calls") > 0

    def test_reading_guidance_uses_no_budget_and_starts_no_graph_work(self, scenario):
        _guidance(scenario.toolbox)("tool_names")
        assert scenario.toolbox.calls_used == 0
        if scenario.runner is not None:
            assert scenario.runner.calls == []
            assert scenario.session.init_seconds == 0.0 and scenario.session.state in (
                "ok", "unavailable:missing"
            )

    def test_prompt_parts_import_leaves_the_graph_package_unloaded(self):
        code = (
            "import sys, lgtm.agents.prompt_parts\n"
            "print(sorted(m for m in sys.modules if m.startswith('lgtm.graph')))\n"
        )
        done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "[]"


class TestGraphGuidanceSection:
    def test_section_prefers_graph_tools_for_symbols_and_call_relations(self, graph_scenario):
        sentences = _guidance_sentences(_guidance_section(graph_scenario.toolbox))
        preferring = [
            s for s in sentences
            if re.search(r"\b(prefer|start with|first)\b", s, re.I)
            and "investigate_base_code" in s and "investigate_pr_code" in s
        ]
        assert preferring

    def test_section_falls_back_to_same_label_reads_on_each_trigger_in_one_sentence(self, graph_scenario):
        sentences = _guidance_sentences(_guidance_section(graph_scenario.toolbox))
        fallback = [
            s for s in sentences
            if re.search(r"same[- ](snapshot|label)", s, re.I)
            and "read_file" in s and "grep_repo" in s
            and all(trigger in s.lower() for trigger in ("unavailable", "truncated", "unindexed"))
        ]
        assert fallback

    def test_section_says_no_match_or_missing_edge_is_not_proof_of_safety(self, graph_scenario):
        sentences = _guidance_sentences(_guidance_section(graph_scenario.toolbox))
        caveats = [
            s for s in sentences
            if re.search(r"no[ _-]match|missing edge", s, re.I)
            and re.search(r"safe|safety|prove|proof|establish", s, re.I)
            and re.search(r"\bnot\b|\bnever\b|n't|\bcannot\b", s, re.I)
        ]
        assert caveats

    def test_section_mentions_the_pr_snapshot_argument(self, graph_scenario):
        assert re.search(r"""["']pr["']""", _guidance_section(graph_scenario.toolbox))

    @pytest.mark.parametrize("name", ["legacy", "missing_binary"])
    def test_non_graph_sections_carry_no_graph_guidance(self, git_repo, name):
        config = LGTMConfig(max_tool_calls=BUDGET)
        toolbox, session, _ = _build_toolbox(name, git_repo, config)
        try:
            section = _guidance_section(toolbox)
        finally:
            if session is not None:
                session.close()
        assert "investigate_" not in section
        assert bool(re.search(r"""["']pr["']""", section)) is (name == "missing_binary")


@pytest.mark.parametrize("kind", AGENTS)
class TestAgentPromptMatrix:
    def test_prompt_names_every_registered_tool(self, kind, scenario):
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        for name in scenario.expect["names"]:
            assert name in text, f"{kind}/{scenario.name}: prompt does not mention {name}"

    def test_prompt_never_advertises_an_unregistered_tool(self, kind, scenario):
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        if not scenario.expect["graph"]:
            assert "investigate_" not in text

    def test_prompt_reports_the_configured_budget(self, kind, scenario):
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        assert re.search(rf"\b{BUDGET}\b", text)

    def test_graph_prompt_includes_the_tool_guidance_section(self, kind, graph_scenario):
        text = _flat(_prompt(_run_agent(kind, graph_scenario, [SAFE])))
        assert _flat(_guidance_section(graph_scenario.toolbox)) in text

    def test_graph_prompt_never_claims_no_match_or_missing_edge_proves_safety(self, kind, graph_scenario):
        text = _prompt(_run_agent(kind, graph_scenario, [SAFE]))
        assert not [
            s for s in _sentences(text)
            if re.search(r"no[ _-]match|missing edge", s, re.I)
            and re.search(r"\b(means|implies|proves) (it is )?safe", s, re.I)
        ]

    def test_prompt_offers_the_pr_snapshot_only_when_it_is_registered(self, kind, scenario):
        config = LGTMConfig(max_tool_calls=BUDGET, require_tool_use=True)
        llm = _run_agent(kind, scenario, [SAFE, SAFE], config)
        offers_pr = lambda text: bool(re.search(r"""["']pr["']""", text))
        assert offers_pr(_prompt(llm)) is ("pr" in scenario.expect["labels"])
        if "pr" not in scenario.expect["labels"]:
            assert not offers_pr(llm.seen[1][-1].content)

    def test_prompt_says_tool_output_is_data_not_instructions(self, kind, scenario):
        text = _prompt(_run_agent(kind, scenario, [SAFE]))
        statements = [
            s for s in _sentences(text)
            if re.search(r"tool (output|result)s?", s, re.I)
            and re.search(r"\bdata\b", s, re.I)
            and re.search(r"instruction", s, re.I)
            and re.search(r"\bnot\b|\bnever\b|n't|\bignore\b", s, re.I)
        ]
        assert statements, f"{kind}/{scenario.name}: prompt does not mark tool output as data"

    def test_pushback_names_exactly_the_registered_tools(self, kind, scenario):
        config = LGTMConfig(max_tool_calls=BUDGET, require_tool_use=True)
        llm = _run_agent(kind, scenario, [SAFE, SAFE], config)
        pushback = llm.seen[1][-1].content
        for name in scenario.expect["names"]:
            assert name in pushback, f"{kind}/{scenario.name}: push-back omits {name}"
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

