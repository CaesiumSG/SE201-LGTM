"""The Bedrock reviewer adapter: message mapping, pricing and the spend cap (no network)."""

import json
import sys
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool

from lgtm.agents import bedrock_llm
from lgtm.agents.bedrock_llm import BedrockBudgetExceeded, BedrockClaude, _Shared, call_cost, to_anthropic
from lgtm.config import LGTMConfig

MODEL = "global.anthropic.claude-haiku-4-5-20251001-v1:0"


@tool
def read_file(path: str) -> str:
    """Read a file."""
    return path


def _usage(i=1000, o=100, w=0, r=0):
    return SimpleNamespace(input_tokens=i, output_tokens=o, cache_creation_input_tokens=w, cache_read_input_tokens=r)


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []
        self.messages = self

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self.replies.pop(0)


def _reply(*blocks, usage=None):
    return SimpleNamespace(content=list(blocks), usage=usage or _usage(), stop_reason="end_turn")


def _config(tmp_path, budget=100.0):
    return LGTMConfig(llm_backend="bedrock", bedrock_model=MODEL, bedrock_budget_usd=budget,
                      bedrock_ledger=str(tmp_path / "spend.jsonl"))


def test_tool_turns_map_to_tool_use_and_tool_result_blocks():
    system, body = to_anthropic([
        SystemMessage(content="sys"),
        HumanMessage(content="review"),
        AIMessage(content="looking", tool_calls=[{"name": "read_file", "args": {"path": "a.py"}, "id": "t1"}]),
        ToolMessage(content="code", tool_call_id="t1"),
        HumanMessage(content="final answer now"),
    ])
    assert system == "sys"
    assert [m["role"] for m in body] == ["user", "assistant", "user"]
    assert body[1]["content"][1] == {"type": "tool_use", "id": "t1", "name": "read_file", "input": {"path": "a.py"}}
    assert body[2]["content"][0] == {"type": "tool_result", "tool_use_id": "t1", "content": "code"}
    assert body[2]["content"][1]["text"] == "final answer now"


def test_a_tool_use_whose_result_was_dropped_still_gets_one():
    _, body = to_anthropic([
        HumanMessage(content="go"),
        AIMessage(content="", tool_calls=[{"name": "read_file", "args": {}, "id": "a"}, {"name": "read_file", "args": {}, "id": "b"}]),
        ToolMessage(content="ra", tool_call_id="a"),
        HumanMessage(content="answer"),
    ])
    results = [b["tool_use_id"] for b in body[-1]["content"] if b["type"] == "tool_result"]
    assert sorted(results) == ["a", "b"]


def test_cost_uses_cache_rates_and_the_safety_margin():
    # haiku 4.5: $1 in, $5 out per MTok; writes 1.25x, reads 0.1x; x1.10
    usd = call_cost(MODEL, _usage(i=1_000_000, o=100_000, w=1_000_000, r=1_000_000))
    assert usd == pytest.approx((1 + 0.5 + 1.25 + 0.1) * 1.10)


def test_unpriced_models_are_refused_before_any_call(tmp_path):
    with pytest.raises(ValueError):
        BedrockClaude(LGTMConfig(llm_backend="bedrock", bedrock_model="global.openai.gpt-6-sol",
                                 bedrock_ledger=str(tmp_path / "l")), shared=_Shared(client=None))


def test_invoke_returns_tool_calls_and_writes_the_ledger(tmp_path):
    fake = FakeClient([_reply(SimpleNamespace(type="text", text="hi"),
                              SimpleNamespace(type="tool_use", name="read_file", input={"path": "x"}, id="u1"))])
    llm = BedrockClaude(_config(tmp_path), shared=_Shared(client=fake)).bind_tools([read_file])
    out = llm.invoke([SystemMessage(content="s"), HumanMessage(content="u")])
    assert out.content == "hi"
    assert out.tool_calls == [{"name": "read_file", "args": {"path": "x"}, "id": "u1", "type": "tool_call"}]
    sent = fake.requests[0]
    assert sent["tools"][0]["name"] == "read_file" and sent["system"][0]["cache_control"]
    assert sent["messages"][-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}
    row = json.loads((tmp_path / "spend.jsonl").read_text())
    assert row["model"] == MODEL and row["usd"] > 0


def test_the_final_unbound_call_keeps_tool_definitions_with_tool_choice_none(tmp_path):
    fake = FakeClient([_reply(SimpleNamespace(type="text", text="{}"))])
    base = BedrockClaude(_config(tmp_path), shared=_Shared(client=fake))
    base.bind_tools([read_file])
    final = base.model_copy(update={"num_predict": 256})
    final.invoke([HumanMessage(content="u"),
                  AIMessage(content="", tool_calls=[{"name": "read_file", "args": {}, "id": "t"}]),
                  ToolMessage(content="r", tool_call_id="t")])
    sent = fake.requests[0]
    assert sent["max_tokens"] == 256 and sent["tool_choice"] == {"type": "none"}


def test_spend_at_the_budget_stops_further_calls(tmp_path):
    (tmp_path / "spend.jsonl").write_text(json.dumps({"usd": 5.0}) + "\n")
    llm = BedrockClaude(_config(tmp_path, budget=5.0), shared=_Shared(client=FakeClient([])))
    with pytest.raises(BedrockBudgetExceeded):
        llm.invoke([HumanMessage(content="u")])


def test_build_llm_picks_the_bedrock_backend(tmp_path, monkeypatch):
    from lgtm.agents.base import build_llm

    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "t")
    monkeypatch.setattr(bedrock_llm, "_Shared", lambda client: _Shared(client=None))
    # The anthropic package is the optional "bedrock" extra, not installed in CI: stand in for it.
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(AnthropicBedrock=lambda **kwargs: None))
    assert isinstance(build_llm(_config(tmp_path)), BedrockClaude)


def test_the_budget_stop_is_not_retried(tmp_path, monkeypatch):
    from lgtm.agents import base

    (tmp_path / "spend.jsonl").write_text(json.dumps({"usd": 5.0}) + "\n")
    config = _config(tmp_path, budget=5.0)
    config.llm_retries = 3
    sleeps = []
    monkeypatch.setattr(base, "_sleep", sleeps.append)
    llm = BedrockClaude(config, shared=_Shared(client=FakeClient([])))
    with pytest.raises(BedrockBudgetExceeded):
        base.invoke_with_retry(llm, [HumanMessage(content="u")], config)
    assert sleeps == []
