"""The tool loop keeps every chat request inside the model's context window."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

from lgtm.agents import registry
from lgtm.agents.base import (
    CHARS_PER_TOKEN,
    FinalAnswerSpec,
    build_llm,
    final_answer_spec,
    invoke_with_retry,
    request_valid_answer,
    run_tool_loop,
)
from lgtm.config import LGTMConfig

CONTEXT_TOKENS = 1400
OUTPUT_TOKENS = 200
RESULT_CHARS = 1500
SCRIPTED_CALLS = 30
TOOL_ROUNDS_THAT_FIT = 2
ANSWER = '{"verdict": "safe"}'


class _ContextLLM:
    """Calls the bound tool on every bound request; answers on unbound requests."""

    def __init__(self, scripted_calls):
        self.scripted_calls = scripted_calls
        self.requests: list[list] = []
        self.bound_requests = 0

    def bind_tools(self, tools):
        owner = self

        class _Bound:
            def invoke(self, messages):
                owner.requests.append(list(messages))
                if owner.bound_requests >= owner.scripted_calls:
                    return AIMessage(content=ANSWER)
                owner.bound_requests += 1
                call = {"name": "dump", "args": {}, "id": f"c{owner.bound_requests}"}
                return AIMessage(content="", tool_calls=[call])

        return _Bound()

    def invoke(self, messages):
        self.requests.append(list(messages))
        return AIMessage(content=ANSWER)


def _tool():
    runs = []
    toolbox = SimpleNamespace(calls_used=0, budget=SCRIPTED_CALLS * 10, steps_exhausted=None, budget_spent=None)

    @tool
    def dump() -> str:
        """Return a large blob."""
        runs.append(1)
        return "x" * RESULT_CHARS

    dump.metadata = {"toolbox": toolbox}
    return dump, runs, toolbox


def _chars(messages) -> int:
    return sum(len(str(m.content)) for m in messages)


HEADROOM_FIELD = "llm_window_headroom"
DEFAULT_HEADROOM = "default"


def _config(headroom=1.0, **overrides):
    """Pins the headroom fraction to 1 (the usable window) unless a test names another or the default."""
    config = LGTMConfig(**{
        "llm_context_tokens": CONTEXT_TOKENS,
        "llm_max_output_tokens": OUTPUT_TOKENS,
        "max_agent_iterations": SCRIPTED_CALLS + 5,
        **overrides,
    })
    if headroom != DEFAULT_HEADROOM:
        setattr(config, HEADROOM_FIELD, headroom)
    return config


USABLE_CHARS = (CONTEXT_TOKENS - OUTPUT_TOKENS) * CHARS_PER_TOKEN


def test_build_llm_passes_context_size_as_num_ctx():
    llm = build_llm(LGTMConfig(llm_context_tokens=12345))
    assert llm.num_ctx == 12345


def test_stops_tool_calls_before_a_request_exceeds_the_context():
    dump, runs, _ = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)
    out = run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert out == ANSWER
    assert len(runs) == TOOL_ROUNDS_THAT_FIT
    limit = (CONTEXT_TOKENS - OUTPUT_TOKENS) * CHARS_PER_TOKEN
    assert all(_chars(r) <= limit for r in llm.requests)


def test_context_full_stop_is_not_reported_as_steps_exhausted():
    dump, _, toolbox = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)
    run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert toolbox.steps_exhausted is False


def test_every_request_keeps_the_original_system_and_user_messages():
    dump, _, _ = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)
    run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert len(llm.requests) == TOOL_ROUNDS_THAT_FIT + 1
    for request in llm.requests:
        assert isinstance(request[0], SystemMessage) and request[0].content == "SYSTEM-PROMPT"
        assert isinstance(request[1], HumanMessage) and request[1].content == "USER-PROMPT"


def test_ends_with_a_final_request_after_the_guard_trips():
    dump, _, _ = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)
    run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert llm.bound_requests == TOOL_ROUNDS_THAT_FIT
    assert isinstance(llm.requests[-1][-1], HumanMessage)


def test_oversized_initial_request_never_reaches_the_model_over_the_window_and_raises_nothing():
    llm = _ContextLLM(0)
    oversized_user_prompt = "x" * (CONTEXT_TOKENS * CHARS_PER_TOKEN)

    run_tool_loop(llm, [], "SYSTEM-PROMPT", oversized_user_prompt, _config())

    assert all(_chars(request) <= USABLE_CHARS for request in llm.requests)
    assert all(request[0].content == "SYSTEM-PROMPT" for request in llm.requests)


def test_oversized_tool_result_is_never_sent_over_the_window_and_raises_nothing():
    dump, _, _ = _tool()
    dump.func = lambda: "x" * (CONTEXT_TOKENS * CHARS_PER_TOKEN)
    llm = _ContextLLM(SCRIPTED_CALLS)

    run_tool_loop(llm, [dump], "sys", "user", _config())

    assert len(llm.requests) == 1
    assert all(_chars(request) <= USABLE_CHARS for request in llm.requests)


def test_forced_final_request_fits_after_tool_round():
    dump, _, _ = _tool()
    dump.func = lambda: "x" * 700
    llm = _ContextLLM(SCRIPTED_CALLS)
    run_tool_loop(llm, [dump], "sys", "user", _config(llm_context_tokens=650))

    limit = (650 - OUTPUT_TOKENS) * CHARS_PER_TOKEN
    assert llm.requests
    assert llm.requests[-1][-1].content
    assert all(_chars(request) <= limit for request in llm.requests)


def test_json_repair_request_fits_context_window():
    class _RepairLLM:
        def __init__(self):
            self.requests = []

        def invoke(self, messages):
            self.requests.append(list(messages))
            return AIMessage(content=ANSWER)

    llm = _RepairLLM()
    messages = [SystemMessage(content="s"), HumanMessage(content="x" * 3400)]
    answer = request_valid_answer(
        llm,
        messages,
        "not json",
        _config(max_answer_reasks=1),
        is_valid=lambda text: text == ANSWER,
    )

    limit = (CONTEXT_TOKENS - OUTPUT_TOKENS) * CHARS_PER_TOKEN
    assert answer == ANSWER
    assert llm.requests
    assert all(_chars(request) <= limit for request in llm.requests)


@pytest.mark.parametrize("extra_chars", [0, 1], ids=["exact-fit", "one-over"])
def test_model_request_context_boundary(extra_chars):
    class _RequestLLM:
        def __init__(self):
            self.requests = []

        def invoke(self, messages):
            self.requests.append(list(messages))
            return AIMessage(content=ANSWER)

    llm = _RequestLLM()
    allowance = (CONTEXT_TOKENS - OUTPUT_TOKENS) * CHARS_PER_TOKEN
    messages = [HumanMessage(content="x" * (allowance + extra_chars))]

    if extra_chars:
        with pytest.raises(ValueError, match="Model request exceeds the configured context allowance"):
            invoke_with_retry(llm, messages, _config())
        assert llm.requests == []
    else:
        invoke_with_retry(llm, messages, _config())
        assert len(llm.requests) == 1
        assert _chars(llm.requests[0]) == allowance


def test_short_conversation_is_unaffected():
    dump, runs, _ = _tool()
    llm = _ContextLLM(2)
    out = run_tool_loop(llm, [dump], "sys", "user", LGTMConfig(max_agent_iterations=8))

    assert out == ANSWER
    assert len(runs) == 2
    assert len(llm.requests) == 3


def test_context_full_stop_leaves_room_for_a_larger_final_answer_allowance():
    final_tokens = 800
    dump, _, _ = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)

    with final_answer_spec(FinalAnswerSpec(options={"num_predict": final_tokens})):
        out = run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert out == ANSWER
    final_window = (CONTEXT_TOKENS - final_tokens) * CHARS_PER_TOKEN
    assert _chars(llm.requests[-1]) <= final_window


class _ScriptedFinalLLM(_ContextLLM):
    """Calls the tool on every bound request; unbound requests get the scripted replies in order."""

    def __init__(self, replies):
        super().__init__(SCRIPTED_CALLS)
        self.replies = list(replies)

    def invoke(self, messages):
        self.requests.append(list(messages))
        return AIMessage(content=self.replies.pop(0) if len(self.replies) > 1 else self.replies[0])


def _context_full_run(replies):
    dump, _, toolbox = _tool()
    toolbox.turns = []
    llm = _ScriptedFinalLLM(replies)
    return llm, toolbox, lambda: run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())


def test_default_caller_reask_after_context_full_stop_keeps_the_whole_history():
    llm, toolbox, run = _context_full_run(["not json", ANSWER])

    assert run() == ANSWER

    forced_request, reask_request = llm.requests[-2], llm.requests[-1]
    assert [m.content for m in reask_request[: len(forced_request)]] == [m.content for m in forced_request]
    assert len(reask_request) == len(forced_request) + 2
    assert [t["assistant"] for t in toolbox.turns][-2:] == ["not json", ANSWER]


def test_default_caller_reask_is_fitted_sent_and_raises_nothing_when_dropping_old_history_makes_room():
    llm, _, run = _context_full_run(["x" * RESULT_CHARS, ANSWER])

    assert run() == ANSWER
    assert all(_chars(request) <= USABLE_CHARS for request in llm.requests)
    assert str(llm.requests[-1][-2].content) == "x" * RESULT_CHARS
    assert str(llm.requests[-1][-1].content) == registry.entry("shared.reask")


def test_default_caller_reask_that_cannot_fit_is_not_sent_and_raises_nothing():
    baseline, _, run_baseline = _context_full_run([ANSWER])
    run_baseline()
    llm, _, run = _context_full_run(["x" * USABLE_CHARS, ANSWER])

    assert run() == "x" * USABLE_CHARS
    assert len(llm.requests) == len(baseline.requests)
    assert all(_chars(request) <= USABLE_CHARS for request in llm.requests)


def _fitted_reask_run(reply_chars):
    spec = FinalAnswerSpec(options={"num_predict": OUTPUT_TOKENS})
    with final_answer_spec(spec):
        llm, _, run = _context_full_run(["x" * reply_chars, ANSWER])
        out = run()
    return llm, out


def test_fitted_reask_drops_the_oldest_history_first_and_keeps_system_user_failed_answer_and_reask():
    allowance = (CONTEXT_TOKENS - OUTPUT_TOKENS) * CHARS_PER_TOKEN
    probe, _ = _fitted_reask_run(0)
    reask_text = registry.entry("shared.reask")
    reply_chars = allowance + 1 - _chars(probe.requests[-2]) - len(reask_text)

    llm, out = _fitted_reask_run(reply_chars)

    forced, fitted = llm.requests[-2], llm.requests[-1]
    texts = lambda ms: [str(m.content) for m in ms]
    assert out == ANSWER
    assert _chars(fitted) <= allowance
    assert texts(fitted[:2]) == ["SYSTEM-PROMPT", "USER-PROMPT"]
    assert texts(fitted[2:-2]) == texts(forced[4:])
    assert texts(fitted[-2:]) == ["x" * reply_chars, reask_text]


def test_fitted_reask_never_drops_the_failed_answer_to_make_room():
    allowance = (CONTEXT_TOKENS - OUTPUT_TOKENS) * CHARS_PER_TOKEN
    llm, out = _fitted_reask_run(allowance)

    assert out == "x" * allowance
    assert llm.replies == [ANSWER]


# --- AC-US8-1, AC-US8-2, AC-US8-4 for callers that run the loop with no per-call stop ---


class _SizedTool:
    """Returns the scripted result sizes in call order."""

    def __init__(self, sizes):
        self.sizes = list(sizes)
        self.runs = 0

    def build(self):
        owner = self
        toolbox = SimpleNamespace(
            calls_used=0, budget=SCRIPTED_CALLS * 10, steps_exhausted=None, budget_spent=None, turns=[]
        )

        @tool
        def dump() -> str:
            """Return a blob."""
            owner.runs += 1
            return "x" * owner.sizes[min(owner.runs, len(owner.sizes)) - 1]

        dump.metadata = {"toolbox": toolbox}
        return dump, toolbox


class _MultiCallLLM(_ContextLLM):
    """First bound request asks for several calls at once; later bound requests answer."""

    def __init__(self, calls_in_first_turn):
        super().__init__(0)
        self.first_turn = calls_in_first_turn

    def bind_tools(self, tools):
        owner = self

        class _Bound:
            def invoke(self, messages):
                owner.requests.append(list(messages))
                if owner.bound_requests:
                    return AIMessage(content=ANSWER)
                owner.bound_requests += 1
                calls = [{"name": "dump", "args": {}, "id": f"c{i}"} for i in range(owner.first_turn)]
                return AIMessage(content="", tool_calls=calls)

        return _Bound()


@pytest.mark.parametrize(
    "headroom",
    [DEFAULT_HEADROOM, 0.5, 1.0],
    ids=["default-0.8", "half", "whole-window"],
)
def test_every_request_fits_the_headroom_adjusted_window(headroom):
    dump, _, _ = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)

    out = run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config(headroom))

    fraction = 0.8 if headroom == DEFAULT_HEADROOM else headroom
    assert out == ANSWER
    assert llm.bound_requests >= 1
    assert all(_chars(request) <= fraction * USABLE_CHARS for request in llm.requests)


def test_a_larger_headroom_fraction_allows_more_tool_rounds():
    rounds = {}
    for fraction in (0.5, 1.0):
        dump, _, _ = _tool()
        llm = _ContextLLM(SCRIPTED_CALLS)
        run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config(fraction))
        rounds[fraction] = llm.bound_requests

    assert rounds[1.0] == TOOL_ROUNDS_THAT_FIT
    assert 1 <= rounds[0.5] < rounds[1.0]


def test_closing_request_after_a_stop_shortens_only_older_results_and_the_record_keeps_them_whole():
    sized = _SizedTool([800, 2800])
    dump, toolbox = sized.build()
    llm = _ContextLLM(SCRIPTED_CALLS)

    out = run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    closing = llm.requests[-1]
    results = [m for m in closing if isinstance(m, ToolMessage)]
    assert out == ANSWER
    assert _chars(closing) <= USABLE_CHARS
    assert [m.content for m in closing[:2]] == ["SYSTEM-PROMPT", "USER-PROMPT"]
    assert isinstance(closing[-1], HumanMessage)
    assert results[-1].content == "x" * 2800
    assert len(results[0].content) < 800
    assert [c["result"] for t in toolbox.turns for c in t["tool_calls"]] == ["x" * 800, "x" * 2800]


def test_every_call_of_a_multi_call_turn_runs_with_no_stop_message_and_nothing_over_the_window_is_sent():
    sized = _SizedTool([RESULT_CHARS])
    dump, toolbox = sized.build()
    llm = _MultiCallLLM(3)

    run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert sized.runs == 3
    assert all(_chars(request) <= USABLE_CHARS for request in llm.requests)
    assert not any(
        str(m.content) == registry.entry("tools.context_full") for request in llm.requests for m in request
    )
    assert [len(t["tool_calls"]) for t in toolbox.turns][:1] == [3]
