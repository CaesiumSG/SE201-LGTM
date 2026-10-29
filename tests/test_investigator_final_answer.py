"""Investigator final answer: a cut-off or wrongly shaped answer is re-asked with room to finish."""

from __future__ import annotations

import json

import pytest

from lgtm.agents import registry
from lgtm.agents.investigator import run_investigator
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from tests.test_investigator import answer, sections_json, small_diffs, tool_call_reply

FINAL_TOKENS = 5000
FILLER_CHARS = 3000

CUT = (
    '{"sections": [{"id": "s1", "title": "T", "rationale": "r", "hunks": ["app.py#0"], '
    '"context": []}, {"id": "s2", "title": "Second", "rationale": "r2", "hun'
)
VALID = sections_json("app.py#0")
NESTED_OBJECT = json.dumps({"id": "s1", "title": "T", "rationale": "r", "hunks": ["app.py#0"]})


class OptionsLLM:
    """Scripted LLM that records the options in effect for every call (invoke kwargs, bind kwargs, model_copy updates)."""

    def __init__(self, script, options=None):
        self.script = list(script)
        self.seen: list[list] = []
        self.options: list[dict] = []
        self._options = dict(options or {})

    def bind_tools(self, tools):
        return self

    def bind(self, **kwargs):
        view = OptionsLLM.__new__(OptionsLLM)
        view.__dict__ = dict(self.__dict__)
        view._options = {**self._options, **kwargs}
        return view

    def model_copy(self, update=None, **kwargs):
        view = OptionsLLM.__new__(OptionsLLM)
        view.__dict__ = dict(self.__dict__)
        view._options = {**self._options, **(update or {})}
        return view

    def invoke(self, messages, **kwargs):
        self.seen.append(list(messages))
        self.options.append({**self._options, **kwargs})
        return self.script.pop(0) if len(self.script) > 1 else self.script[0]


class FillerLLM(OptionsLLM):
    """Keeps calling a tool while tools are bound; the unbound final-answer turns get the answer."""

    def __init__(self, filler, final):
        super().__init__([final])
        self.filler = filler

    def bind_tools(self, tools):
        owner = self

        class _Bound:
            def invoke(self, messages, **kwargs):
                owner.seen.append(list(messages))
                owner.options.append(dict(owner._options))
                return owner.filler

        return _Bound()


def limits(options):
    found = [v for v in options.values() if isinstance(v, int) and not isinstance(v, bool)]
    for v in options.values():
        if isinstance(v, dict):
            found += [x for x in v.values() if isinstance(x, int) and not isinstance(x, bool)]
    return found or [0]


@pytest.fixture
def config():
    return LGTMConfig(
        llm_retries=0,
        max_answer_reasks=3,
        require_tool_use=False,
        investigator_max_tool_calls=2,
        investigator_max_iterations=2,
    )


@pytest.fixture
def toolbox(tmp_path, config):
    return AgentToolbox(tmp_path, "main", None, config)


def run(config, toolbox, llm):
    return run_investigator(small_diffs(), config, toolbox, llm)


def last_user_text(call):
    return str(call[-1].content)


def assistant_turns(result):
    return [t["assistant"] for t in result.run_record.turns]


def test_cut_off_answer_is_reasked_not_accepted_as_its_first_nested_object(config, toolbox):
    llm = OptionsLLM([answer(CUT), answer(VALID)])

    result = run(config, toolbox, llm)

    assert len(llm.seen) == 2
    assert result.status == "ok"
    assert [s.section_id for s in result.proposed] == ["s1"]


def test_later_valid_answer_ends_the_loop(config, toolbox):
    llm = OptionsLLM([answer(CUT), answer(CUT), answer(VALID), answer(CUT)])

    result = run(config, toolbox, llm)

    assert len(llm.seen) == 3
    assert result.status == "ok"


def test_cut_off_answer_is_reasked_up_to_the_existing_cap_then_fails_at_parse(config, toolbox):
    llm = OptionsLLM([answer(CUT)])

    result = run(config, toolbox, llm)

    assert len(llm.seen) == 1 + config.max_answer_reasks
    assert result.status == "failed"
    assert result.proposed is None


def test_reask_cap_is_the_configured_cap(config, toolbox):
    config.max_answer_reasks = 1
    llm = OptionsLLM([answer(CUT)])

    run(config, toolbox, llm)

    assert len(llm.seen) == 2


@pytest.mark.parametrize(
    "wrong_top_level",
    [
        NESTED_OBJECT,
        json.dumps({"findings": []}),
        json.dumps({"sections": "none"}),
        json.dumps([{"sections": []}]),
    ],
    ids=["a-section-object", "other-object", "sections-not-a-list", "array"],
)
def test_answer_without_the_required_top_level_object_is_reasked(config, toolbox, wrong_top_level):
    llm = OptionsLLM([answer(wrong_top_level), answer(VALID)])

    result = run(config, toolbox, llm)

    assert len(llm.seen) == 2
    assert result.status == "ok"
    assert [s.section_id for s in result.proposed] == ["s1"]


def test_every_reask_is_a_recorded_turn_in_order(config, toolbox):
    second_bad = json.dumps({"findings": []})
    llm = OptionsLLM([answer(CUT), answer(second_bad), answer(VALID)])

    result = run(config, toolbox, llm)

    assert assistant_turns(result) == [CUT, second_bad, VALID]
    assert result.run_record.raw_answer == VALID


def test_reask_carries_the_failed_answer_and_a_new_instruction(config, toolbox):
    llm = OptionsLLM([answer(CUT), answer(VALID)])

    run(config, toolbox, llm)

    reask_request = llm.seen[1]
    assert any(getattr(m, "content", None) == CUT for m in reask_request)
    instruction = last_user_text(reask_request)
    assert instruction != registry.entry("shared.reask")
    assert "sections" in instruction


def test_reask_turn_has_an_output_allowance_above_the_default_limit(config, toolbox):
    llm = OptionsLLM([answer(CUT), answer(VALID)])

    run(config, toolbox, llm)

    assert max(limits(llm.options[1])) > config.llm_max_output_tokens


def test_forced_final_turn_has_an_output_allowance_and_its_own_instruction(config, toolbox):
    llm = OptionsLLM([tool_call_reply(1), tool_call_reply(1), answer(CUT), answer(VALID)])

    result = run(config, toolbox, llm)

    forced_index = 2
    assert result.status == "ok"
    assert max(limits(llm.options[forced_index])) > config.llm_max_output_tokens
    assert max(limits(llm.options[forced_index + 1])) > config.llm_max_output_tokens
    forced_text = last_user_text(llm.seen[forced_index])
    assert forced_text != registry.entry("shared.forced_final")
    assert "sections" in forced_text
    assert assistant_turns(result)[-2:] == [CUT, VALID]


def test_tool_rounds_keep_the_default_output_limit(config, toolbox):
    llm = OptionsLLM([tool_call_reply(1), answer(VALID)])

    run(config, toolbox, llm)

    assert all(value <= config.llm_max_output_tokens for value in limits(llm.options[0]))


def num_predicts(llm):
    return [options.get("num_predict") for options in llm.options]


def test_reask_turn_runs_with_the_configured_final_output_allowance(config, toolbox):
    config.investigator_final_output_tokens = FINAL_TOKENS
    llm = OptionsLLM([answer(CUT), answer(VALID)])

    run(config, toolbox, llm)

    assert num_predicts(llm)[1] == FINAL_TOKENS


def test_forced_final_and_its_reask_run_with_the_configured_final_output_allowance(config, toolbox):
    config.investigator_final_output_tokens = FINAL_TOKENS
    llm = OptionsLLM([tool_call_reply(1), tool_call_reply(1), answer(CUT), answer(VALID)])

    run(config, toolbox, llm)

    assert num_predicts(llm)[2:4] == [FINAL_TOKENS, FINAL_TOKENS]
    assert num_predicts(llm)[0] != FINAL_TOKENS


def test_full_context_still_ends_in_the_investigators_answer_not_a_context_error(config, toolbox):
    config.llm_context_tokens = 12000
    config.investigator_max_tool_calls = 40
    config.investigator_max_iterations = 40
    filler = tool_call_reply(1)
    filler.content = "x" * FILLER_CHARS
    llm = FillerLLM(filler, answer(VALID))

    result = run(config, toolbox, llm)

    assert result.error is None
    assert result.status == "ok"
    assert [s.section_id for s in result.proposed] == ["s1"]
    assert llm.options[-1].get("num_predict") == config.investigator_final_output_tokens
    final_chars = sum(len(str(m.content)) for m in llm.seen[-1])
    assert final_chars <= (config.llm_context_tokens - config.investigator_final_output_tokens) * 3
