import json
import sys
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from lgtm.agents.base import build_llm
from lgtm.agents.bedrock_llm import BedrockBudgetExceeded
from lgtm.agents.bedrock_openai_llm import BedrockOpenAI, price_of, strip_reasoning, to_openai
from lgtm.config import LGTMConfig


class FakeResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.bodies = []

    def post(self, path, json):
        self.bodies.append(json)
        status, payload = self.payloads.pop(0)
        return FakeResponse(status, payload)


def _config(tmp_path, **kw):
    cfg = LGTMConfig()
    cfg.llm_backend = "bedrock"
    cfg.bedrock_model = "openai.gpt-oss-20b-1:0"
    cfg.bedrock_ledger = str(tmp_path / "ledger.jsonl")
    for k, v in kw.items():
        setattr(cfg, k, v)
    return cfg


def _reply(content="", tool_calls=None, usage=(1000, 200)):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return (200, {"choices": [{"message": msg, "finish_reason": "stop"}],
                  "usage": {"prompt_tokens": usage[0], "completion_tokens": usage[1]}})


def test_strip_reasoning_removes_closed_and_unclosed_blocks():
    assert strip_reasoning("<reasoning>think</reasoning>{\"a\": 1}") == '{"a": 1}'
    assert strip_reasoning("<reasoning>never closed") == ""
    assert strip_reasoning("plain") == "plain"


def test_price_of_prefers_the_longest_key_and_refuses_unknown():
    assert price_of("openai.gpt-oss-120b-1:0") == (0.15, 0.60)
    assert price_of("openai.gpt-oss-20b-1:0") == (0.07, 0.30)
    with pytest.raises(ValueError):
        price_of("openai.unknown")


def test_to_openai_answers_every_tool_call_once():
    msgs = [
        SystemMessage("sys"), HumanMessage("hi"),
        AIMessage(content="", tool_calls=[{"id": "c1", "name": "read_file", "args": {"path": "a.py"}},
                                          {"id": "c2", "name": "grep_repo", "args": {"pattern": "x"}}]),
        ToolMessage(content="body", tool_call_id="c1"),
        ToolMessage(content="stray", tool_call_id="zz"),
        HumanMessage("answer now"),
    ]
    out = to_openai(msgs)
    assert [m["role"] for m in out] == ["system", "user", "assistant", "tool", "tool", "user"]
    assert out[2]["tool_calls"][0]["function"] == {"name": "read_file", "arguments": json.dumps({"path": "a.py"})}
    assert {m["tool_call_id"] for m in out if m["role"] == "tool"} == {"c1", "c2"}
    assert next(m for m in out if m.get("tool_call_id") == "c2")["content"] == "(omitted)"


def test_invoke_parses_tool_calls_strips_reasoning_and_writes_ledger(tmp_path):
    client = FakeClient([_reply("<reasoning>x</reasoning>done", [
        {"id": "t1", "type": "function", "function": {"name": "read_file", "arguments": '{"path": "a.py"}'}},
        {"id": "t2", "type": "function", "function": {"name": "grep_repo", "arguments": "not json"}},
    ])])
    llm = BedrockOpenAI(_config(tmp_path, llm_temperature=0.5), client=client)
    msg = llm.invoke([HumanMessage("go")])
    assert msg.content == "done"
    assert [c["args"] for c in msg.tool_calls] == [{"path": "a.py"}, {}]
    assert client.bodies[0]["temperature"] == 0.5
    row = json.loads((tmp_path / "ledger.jsonl").read_text())
    assert row["input"] == 1000 and row["output"] == 200
    assert row["usd"] == pytest.approx((1000 * 0.07 + 200 * 0.30) / 1e6 * 1.10, rel=1e-3)


def test_final_answer_without_tools_sends_tool_choice_none(tmp_path):
    from langchain_core.tools import tool

    @tool
    def read_file(path: str) -> str:
        """Read a file."""
        return ""

    client = FakeClient([_reply("{}")])
    bound = BedrockOpenAI(_config(tmp_path), client=client).bind_tools([read_file])
    plain = bound.model_copy(update={"num_predict": 50})
    plain.tools = None
    plain.invoke([HumanMessage("go"), AIMessage(content="", tool_calls=[{"id": "c", "name": "read_file", "args": {}}]),
                  ToolMessage(content="x", tool_call_id="c"), HumanMessage("final")])
    body = client.bodies[0]
    assert body["tool_choice"] == "none" and body["max_tokens"] == 50
    assert body["tools"][0]["function"]["name"] == "read_file"


def test_retries_throttling_then_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    client = FakeClient([(429, {}), (503, {}), _reply("ok")])
    assert BedrockOpenAI(_config(tmp_path), client=client).invoke([HumanMessage("go")]).content == "ok"


def test_budget_stops_before_calling(tmp_path):
    (tmp_path / "ledger.jsonl").write_text(json.dumps({"usd": 5.0}) + "\n")
    client = FakeClient([])
    llm = BedrockOpenAI(_config(tmp_path, bedrock_budget_usd=5.0), client=client)
    with pytest.raises(BedrockBudgetExceeded):
        llm.invoke([HumanMessage("go")])
    assert client.bodies == []


def test_build_llm_routes_openai_models(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "test-token")
    # The anthropic package is the optional "bedrock" extra, not installed in CI: stand in for it.
    monkeypatch.setitem(sys.modules, "anthropic", SimpleNamespace(AnthropicBedrock=lambda **kwargs: None))
    assert isinstance(build_llm(_config(tmp_path)), BedrockOpenAI)
    assert not isinstance(build_llm(_config(tmp_path, bedrock_model="global.anthropic.claude-haiku-4-5-20251001-v1:0")),
                          BedrockOpenAI)
