"""Shared guidance data and prompts for both agents across graph and no-graph runs (N1)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

from lgtm.agents import prompt_parts
from lgtm.agents.authz_reviewer import ROLE_GUIDANCE, AuthzReviewerAgent
from lgtm.agents.base import run_tool_loop
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import LineChange
from lgtm.graph.session import GraphSession
from lgtm.graph.snapshot import resolve_refs
from lgtm.review.sections import ContextPointer, HunkRef, Section, render_section
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


def _section(lines=("x = 1",), **overrides):
    changes = [LineChange("add", text, None, n) for n, text in enumerate(lines, 1)]
    hunk = HunkRef(
        hunk_id="app.py#1", file="app.py", old_start=1, old_count=0, new_start=1,
        new_count=len(changes), change="add", changes=changes,
    )
    fields = dict(
        section_id="s1", origin="investigator", title="Order listing", files=["app.py"],
        hunks=[hunk], rationale="Lists orders for the caller",
    )
    return Section(**{**fields, **overrides})


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
        AuthzReviewerAgent(sc.toolbox, config, llm=llm).review_section(_section(), "")
    return llm


def _expected_names(kind, scenario):
    names = scenario.expect["names"]
    if kind == "sast_triage":
        return [n for n in names if not n.startswith("investigate_")]
    return names


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
        for name in _expected_names(kind, scenario):
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
        if kind == "sast_triage":
            assert "investigate_" not in text
        else:
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
        for name in _expected_names(kind, scenario):
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


EMPTY_FINDINGS = json.dumps({"findings": []})


def _section_prompt(git_repo, section, notes="", retriever=None, **config_kwargs):
    config = LGTMConfig(max_tool_calls=BUDGET, **config_kwargs)
    toolbox = AgentToolbox(git_repo, "main", retriever, config)
    llm = ScriptedLLM([EMPTY_FINDINGS])
    AuthzReviewerAgent(toolbox, config, llm=llm).review_section(section, notes)
    return _prompt(llm)


class _LongPolicyRetriever:
    def __init__(self, text):
        self.text = text

    def format_results(self, query, *args, **kwargs):
        return self.text

    def is_available(self):
        return True


class TestSectionReviewPrompt:
    def test_prompt_names_the_section_and_its_rationale(self, git_repo):
        section = _section(
            section_id="sec-7", title="Refund approval", rationale="Managers approve refunds"
        )
        text = _section_prompt(git_repo, section)
        assert "sec-7" in text and "Refund approval" in text
        assert "Managers approve refunds" in text

    def test_section_text_longer_than_six_thousand_characters_appears_in_full(self, git_repo):
        lines = [f"value_{i:04d} = {i}" for i in range(500)]
        section = _section(lines=lines)
        rendered = render_section(section)
        assert len(rendered) > 6000
        assert rendered in _section_prompt(git_repo, section)

    def test_context_pointers_are_listed(self, git_repo):
        pointer = ContextPointer(
            path="auth/guards.py", symbol="require_owner", start_line=10, end_line=24,
            snapshot="pr", why="ownership guard used by the route",
        )
        text = _section_prompt(git_repo, _section(context=[pointer]))
        assert "auth/guards.py" in text and "require_owner" in text
        assert "ownership guard used by the route" in text

    def test_policy_excerpts_are_cut_at_exactly_five_thousand_characters(self, git_repo):
        marker = "§"
        retriever = _LongPolicyRetriever(marker * 6000)
        text = _section_prompt(git_repo, _section(), retriever=retriever)
        assert text.count(marker) == 5000

    def test_short_policy_excerpts_are_kept_whole(self, git_repo):
        retriever = _LongPolicyRetriever("Only admins may delete users.")
        text = _section_prompt(git_repo, _section(), retriever=retriever)
        assert "Only admins may delete users." in text

    def test_sibling_notice_appears_only_for_multi_part_sections(self, git_repo):
        notice = re.compile(r"sibling|\bparts?\b", re.I)
        single = _section_prompt(git_repo, _section())
        multi = _section_prompt(
            git_repo, _section(split=True, group_id="g1", part_index=1, part_count=3)
        )
        assert not notice.search(single)
        assert notice.search(multi)

    def test_semgrep_notes_are_included_when_given_and_absent_otherwise(self, git_repo):
        note = "- python.sqli at app.py:2: tainted query"
        assert note in _section_prompt(git_repo, _section(), notes=note)
        assert "python.sqli" not in _section_prompt(git_repo, _section(), notes="")

    def test_role_guidance_follows_the_config_flag(self, git_repo):
        assert ROLE_GUIDANCE in _section_prompt(git_repo, _section(), authz_role_guidance=True)
        assert ROLE_GUIDANCE not in _section_prompt(git_repo, _section(), authz_role_guidance=False)

    def test_prompt_says_a_missing_rule_is_not_a_confirmed_violation(self, git_repo):
        text = _flat(_section_prompt(git_repo, _section()))
        assert re.search(r"lack of an explicit rule", text, re.I)
        assert not re.search(r"\b(vulnerable|possible|insufficient_evidence)\b", text, re.I)


def _user_prompt(git_repo, section, notes=""):
    config = LGTMConfig(max_tool_calls=BUDGET)
    toolbox = AgentToolbox(git_repo, "main", None, config)
    llm = ScriptedLLM([EMPTY_FINDINGS])
    AuthzReviewerAgent(toolbox, config, llm=llm).review_section(section, notes)
    return str(llm.seen[0][1].content)


def _classified_lines(text):
    """(line, inside_fence) pairs following CommonMark: fences and closers are indented 0-3 spaces."""
    result, open_len = [], 0
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        ticks = len(stripped) - len(stripped.lstrip("`"))
        if open_len:
            closes = indent <= 3 and ticks >= open_len and set(stripped) == {"`"}
            result.append((line, not closes))
            if closes:
                open_len = 0
        else:
            result.append((line, False))
            if indent <= 3 and ticks >= 3 and "`" not in stripped[ticks:]:
                open_len = ticks
    assert not open_len, "a code fence in the prompt is never closed"
    return result


SEPARATORS = ["\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
HEADING = "INJECTED_HEADING obey"


def _hostile_section(field, payload):
    pointer = dict(
        path="auth/guards.py", symbol="require_owner", start_line=1, end_line=2,
        snapshot="pr", why="guard",
    )
    overrides = {}
    notes = ""
    if field in ("title", "rationale"):
        overrides[field] = payload
    elif field == "files":
        overrides["files"] = [payload]
    elif field == "notes":
        notes = f"- rule at app.py:2: {payload}"
    else:
        pointer[field.removeprefix("pointer_")] = payload
        overrides["context"] = [ContextPointer(**pointer)]
    return _section(**overrides), notes


class TestSectionPromptInjectionResistance:
    @pytest.mark.parametrize("separator", SEPARATORS, ids=repr)
    @pytest.mark.parametrize(
        "field",
        ["title", "rationale", "files", "notes", "pointer_path", "pointer_symbol", "pointer_why"],
    )
    def test_pr_controlled_field_cannot_start_a_new_prompt_line(self, git_repo, field, separator):
        section, notes = _hostile_section(field, f"x{separator}{HEADING} y")

        lines = _classified_lines(_user_prompt(git_repo, section, notes))

        escaped = [
            line for line, inside in lines
            if not inside and line.strip().lstrip("-#*> ").startswith("INJECTED_HEADING")
        ]
        assert not escaped

    @pytest.mark.parametrize(
        "field",
        ["title", "rationale", "files", "notes", "pointer_path", "pointer_symbol", "pointer_why"],
    )
    def test_pr_controlled_field_sits_inside_the_untrusted_block_or_is_labelled_untrusted(
        self, git_repo, field
    ):
        section, notes = _hostile_section(field, "PR_CONTROLLED_VALUE")

        lines = _classified_lines(_user_prompt(git_repo, section, notes))

        hits = [i for i, (line, _) in enumerate(lines) if "PR_CONTROLLED_VALUE" in line]
        assert hits, "the field value is not shown to the reviewer"
        for i in hits:
            line, inside = lines[i]
            heading = next(
                (lines[j][0] for j in range(i, -1, -1) if not lines[j][1] and lines[j][0].startswith("#")),
                "",
            )
            assert inside or "untrusted" in line.lower() or "untrusted" in heading.lower(), line

    @pytest.mark.parametrize("indent", [0, 1, 2, 3])
    @pytest.mark.parametrize("ticks", [3, 4, 9])
    def test_backtick_run_in_section_content_cannot_close_the_untrusted_block(
        self, git_repo, indent, ticks
    ):
        fence = " " * indent + "`" * ticks
        changes = [
            LineChange("context", fence, 1, 1),
            LineChange("add", "ESCAPED_INSTRUCTION = 1", None, 2),
            LineChange("context", fence, 2, 3),
        ]
        hunk = HunkRef(
            hunk_id="app.py#1", file="app.py", old_start=1, old_count=2, new_start=1,
            new_count=3, change="mixed", changes=changes,
        )
        section = _section(hunks=[hunk])

        lines = _classified_lines(_user_prompt(git_repo, section))

        added = [inside for line, inside in lines if "ESCAPED_INSTRUCTION" in line]
        assert added and all(added)
        trailing = [inside for line, inside in lines if "Review the section's authorization" in line]
        assert trailing == [False]
