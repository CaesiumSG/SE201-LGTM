"""The tool loop keeps every chat request inside the model's context window."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool

from lgtm.agents.base import build_llm, run_tool_loop
from lgtm.config import LGTMConfig

CHARS_PER_TOKEN = 4
CONTEXT_TOKENS = 1400
OUTPUT_TOKENS = 200
RESULT_CHARS = 1500
SCRIPTED_CALLS = 30
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

    @tool
    def dump() -> str:
        """Return a large blob."""
        runs.append(1)
        return "x" * RESULT_CHARS

    return dump, runs


def _chars(messages) -> int:
    return sum(len(str(m.content)) for m in messages)


def _config(**overrides):
    return LGTMConfig(
        llm_context_tokens=CONTEXT_TOKENS,
        llm_max_output_tokens=OUTPUT_TOKENS,
        max_agent_iterations=SCRIPTED_CALLS + 5,
        **overrides,
    )


def test_context_setting_defaults_to_32768():
    assert LGTMConfig().llm_context_tokens == 32768


def test_build_llm_passes_context_size_as_num_ctx():
    llm = build_llm(LGTMConfig(llm_context_tokens=12345))
    assert llm.num_ctx == 12345


def test_stops_tool_calls_before_a_request_exceeds_the_context():
    dump, runs = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)
    out = run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert out == ANSWER
    assert 0 < len(runs) < SCRIPTED_CALLS
    limit = CONTEXT_TOKENS * CHARS_PER_TOKEN
    assert all(_chars(r) < limit for r in llm.requests)


def test_every_request_keeps_the_original_system_and_user_messages():
    dump, _ = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)
    run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert len(llm.requests) > 2
    for request in llm.requests:
        assert isinstance(request[0], SystemMessage) and request[0].content == "SYSTEM-PROMPT"
        assert isinstance(request[1], HumanMessage) and request[1].content == "USER-PROMPT"


def test_ends_with_a_final_request_after_the_guard_trips():
    dump, runs = _tool()
    llm = _ContextLLM(SCRIPTED_CALLS)
    run_tool_loop(llm, [dump], "SYSTEM-PROMPT", "USER-PROMPT", _config())

    assert llm.bound_requests < SCRIPTED_CALLS
    assert isinstance(llm.requests[-1][-1], HumanMessage)


def test_short_conversation_is_unaffected():
    dump, runs = _tool()
    llm = _ContextLLM(2)
    out = run_tool_loop(llm, [dump], "sys", "user", LGTMConfig(max_agent_iterations=8))

    assert out == ANSWER
    assert len(runs) == 2
    assert len(llm.requests) == 3
