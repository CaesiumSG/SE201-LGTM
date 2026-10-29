"""The tool loop keeps every chat request inside the model's context window."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool

from lgtm.agents.base import CHARS_PER_TOKEN, build_llm, invoke_with_retry, request_valid_answer, run_tool_loop
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


def _config(**overrides):
    return LGTMConfig(**{
        "llm_context_tokens": CONTEXT_TOKENS,
        "llm_max_output_tokens": OUTPUT_TOKENS,
        "max_agent_iterations": SCRIPTED_CALLS + 5,
        **overrides,
    })


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


def test_oversized_initial_request_is_bounded_before_model_invocation():
    llm = _ContextLLM(0)
    oversized_user_prompt = "x" * (CONTEXT_TOKENS * CHARS_PER_TOKEN)

    with pytest.raises(ValueError, match="Agent request exceeds the configured context allowance"):
        run_tool_loop(llm, [], "SYSTEM-PROMPT", oversized_user_prompt, _config())

    assert llm.requests == []


def test_oversized_tool_result_never_reaches_a_model_request():
    dump, _, _ = _tool()
    dump.func = lambda: "x" * (CONTEXT_TOKENS * CHARS_PER_TOKEN)
    llm = _ContextLLM(SCRIPTED_CALLS)

    with pytest.raises(ValueError, match="Forced-final request exceeds the configured context allowance"):
        run_tool_loop(llm, [dump], "sys", "user", _config())

    assert len(llm.requests) == 1
    assert _chars(llm.requests[0]) <= (CONTEXT_TOKENS - OUTPUT_TOKENS) * CHARS_PER_TOKEN


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
