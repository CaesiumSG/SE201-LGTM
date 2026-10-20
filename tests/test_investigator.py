"""Investigator: scripted-LLM behavior of run_investigator(diffs, config, toolbox, llm)."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from lgtm.agents.investigator import run_investigator
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, Hunk, LineChange
from lgtm.graph.session import GraphSession
from tests.graph_fakes import FakeRunner

TOOL_NAMES = {"investigate_base_code", "investigate_pr_code", "read_file", "grep_repo", "search_policy"}


class ScriptedLLM:
    """Replays the script; the last item repeats. Exceptions in the script are raised."""

    def __init__(self, script):
        self.script = list(script)
        self.seen: list[list] = []
        self.bound_tools: list = []

    def bind_tools(self, tools):
        self.bound_tools = list(tools)
        return self

    def invoke(self, messages):
        self.seen.append(list(messages))
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, Exception):
            raise item
        return item


def answer(text):
    return SimpleNamespace(content=text, tool_calls=[])


def tool_call_reply(n, *, name="read_file"):
    calls = [{"name": name, "args": {"path": f"f{i}.py"}, "id": f"call_{i}"} for i in range(n)]
    return SimpleNamespace(content="", tool_calls=calls)


def sections_json(*hunk_ids):
    return json.dumps(
        {
            "sections": [
                {
                    "id": "s1",
                    "title": "Auth change",
                    "rationale": "touches access control",
                    "hunks": list(hunk_ids),
                    "context": [],
                }
            ]
        }
    )


def hunk(old_start, new_start, kinds, prefix="L"):
    changes = [
        LineChange(kind=kind, content=f"{prefix}{i}_{kind}") for i, kind in enumerate(kinds)
    ]
    return Hunk(
        old_start=old_start,
        old_count=len(kinds),
        new_start=new_start,
        new_count=len(kinds),
        changes=changes,
    )


def small_diffs():
    return [
        FileDiff(path="app.py", status="modified", hunks=[hunk(10, 12, ["context", "add", "del"])]),
        FileDiff(path="README.md", status="modified", hunks=[hunk(1, 1, ["add"], prefix="DOC")]),
    ]


def manifest_diffs():
    many = ["add"] * 8
    return [
        FileDiff(
            path="svc/views.py",
            status="modified",
            hunks=[hunk(4711, 4802, many, prefix="HA"), hunk(5900, 6001, many, prefix="HB")],
        ),
        FileDiff(path="gone.py", status="deleted", hunks=[hunk(7, 0, ["del"] * 6, prefix="HC")]),
        FileDiff(path="notes.md", status="modified", hunks=[hunk(1, 1, ["add"], prefix="DOC")]),
    ]


def prompt_text(llm):
    return "\n".join(str(getattr(m, "content", "")) for m in llm.seen[0])


@pytest.fixture
def config():
    return LGTMConfig(
        llm_retries=0,
        max_answer_reasks=0,
        require_tool_use=False,
        max_tool_calls=9,
        max_agent_iterations=10,
        investigator_max_tool_calls=2,
        investigator_max_iterations=3,
    )


@pytest.fixture
def toolbox(tmp_path, config):
    return AgentToolbox(tmp_path, "main", None, config)


def run(diffs, config, toolbox, llm):
    return run_investigator(diffs, config, toolbox, llm)


def test_full_diff_success_returns_parsed_sections_and_counts_tool_calls(config, toolbox):
    llm = ScriptedLLM([tool_call_reply(1), answer(sections_json("app.py#0"))])

    result = run(small_diffs(), config, toolbox, llm)

    assert result.status == "ok"
    assert result.input_mode == "full"
    assert not result.error
    assert [s.section_id for s in result.proposed] == ["s1"]
    assert result.proposed[0].hunk_refs == ["app.py#0"]
    assert result.tool_calls == 1


def test_full_mode_prompt_carries_the_diff_lines_and_hunk_ids(config, toolbox):
    llm = ScriptedLLM([answer(sections_json("app.py#0"))])

    run(small_diffs(), config, toolbox, llm)

    text = prompt_text(llm)
    assert "app.py#0" in text
    for marker in ("L1_add", "L2_del"):
        assert marker in text


def test_investigator_is_given_the_full_toolbox(tmp_path, config):
    shas = {"base": "a" * 40, "pr": "b" * 40}
    session = GraphSession(tmp_path, shas, config, runner=FakeRunner())
    graph_toolbox = AgentToolbox(tmp_path, "main", None, config, shas=shas, session=session)
    llm = ScriptedLLM([answer(sections_json("app.py#0"))])

    try:
        run(small_diffs(), config, graph_toolbox, llm)
    finally:
        session.close()

    assert {t.name for t in llm.bound_tools} == TOOL_NAMES


def test_oversized_diff_switches_to_manifest_only_with_status_and_hunk_coordinates(config, toolbox):
    config.investigator_diff_chars = 100
    llm = ScriptedLLM([answer(sections_json("svc/views.py#0"))])

    result = run(manifest_diffs(), config, toolbox, llm)

    assert result.status == "ok"
    assert result.input_mode == "manifest_only"
    text = prompt_text(llm)
    for expected in ("svc/views.py", "gone.py", "deleted", "svc/views.py#0", "svc/views.py#1", "gone.py#0"):
        assert expected in text
    for coordinate in ("4711", "4802", "5900", "6001"):
        assert coordinate in text
    assert "notes.md" not in text


def test_manifest_only_prompt_has_at_most_three_changed_lines_per_hunk(config, toolbox):
    config.investigator_diff_chars = 100
    llm = ScriptedLLM([answer(sections_json("svc/views.py#0"))])

    run(manifest_diffs(), config, toolbox, llm)

    text = prompt_text(llm)
    for prefix in ("HA", "HB", "HC"):
        shown = set(re.findall(rf"{prefix}\d+_(?:add|del)", text))
        assert 1 <= len(shown) <= 3, f"{prefix} hunk shows {len(shown)} changed lines"


def test_diff_within_the_character_budget_stays_in_full_mode(config, toolbox):
    config.investigator_diff_chars = 100000
    llm = ScriptedLLM([answer(sections_json("svc/views.py#0"))])

    result = run(manifest_diffs(), config, toolbox, llm)

    assert result.input_mode == "full"
    assert all(f"HA{i}_add" in prompt_text(llm) for i in range(8))


@pytest.mark.parametrize(
    "reply",
    ["this is not json", "", '{"other": 1}', '{"sections": "nope"}'],
)
def test_unparsable_or_malformed_output_fails_without_proposed_sections(reply, config, toolbox):
    llm = ScriptedLLM([answer(reply)])

    result = run(small_diffs(), config, toolbox, llm)

    assert result.status == "failed"
    assert result.proposed is None
    assert result.error


def test_llm_exception_fails_with_the_error_text(config, toolbox):
    llm = ScriptedLLM([RuntimeError("model endpoint exploded")])

    result = run(small_diffs(), config, toolbox, llm)

    assert result.status == "failed"
    assert result.proposed is None
    assert "model endpoint exploded" in result.error


def test_tool_budget_exhausted_without_a_valid_answer_fails(config, toolbox):
    llm = ScriptedLLM([tool_call_reply(4), answer("I need more tool calls")])

    result = run(small_diffs(), config, toolbox, llm)

    assert result.status == "failed"
    assert result.proposed is None
    assert result.error
    assert result.tool_calls == config.investigator_max_tool_calls


def test_iteration_cap_without_a_valid_answer_fails(config, toolbox):
    llm = ScriptedLLM([tool_call_reply(1)])

    result = run(small_diffs(), config, toolbox, llm)

    assert result.status == "failed"
    assert result.proposed is None
    assert result.error


def test_investigator_uses_its_own_tool_cap_then_section_default_returns_on_reset(config, toolbox):
    llm = ScriptedLLM([tool_call_reply(5), answer(sections_json("app.py#0"))])

    result = run(small_diffs(), config, toolbox, llm)

    assert result.status == "ok"
    assert result.tool_calls == 2
    assert toolbox.calls_used == 2
    assert toolbox.budget == config.investigator_max_tool_calls

    toolbox.reset_budget()

    assert toolbox.budget == config.max_tool_calls == 9
    assert toolbox.calls_used == 0


def test_investigator_uses_its_own_iteration_cap_not_the_section_one(config, toolbox):
    llm = ScriptedLLM([tool_call_reply(1)])

    run(small_diffs(), config, toolbox, llm)

    assert config.investigator_max_iterations < len(llm.seen) < config.max_agent_iterations


@pytest.mark.parametrize("diff_chars", [30000, 100])
def test_prompt_marks_diff_content_as_untrusted_data(diff_chars, config, toolbox):
    config.investigator_diff_chars = diff_chars
    llm = ScriptedLLM([answer(sections_json("svc/views.py#0"))])

    run(manifest_diffs(), config, toolbox, llm)

    assert "untrusted" in prompt_text(llm).lower()


@pytest.mark.parametrize("diff_chars", [30000, 100])
def test_callers_config_and_toolbox_config_are_not_mutated(diff_chars, config, toolbox):
    config.investigator_diff_chars = diff_chars
    before = copy.deepcopy(asdict(config))
    llm = ScriptedLLM([tool_call_reply(1), answer(sections_json("svc/views.py#0"))])

    run(manifest_diffs(), config, toolbox, llm)

    assert asdict(config) == before
    assert config.max_agent_iterations == 10
    assert asdict(toolbox.config) == before
