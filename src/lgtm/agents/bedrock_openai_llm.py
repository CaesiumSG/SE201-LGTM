"""OpenAI open-weights models (gpt-oss) on Amazon Bedrock as the reviewer model.

Bedrock serves the gpt-oss models through an OpenAI-compatible Chat
Completions endpoint (``https://bedrock-runtime.<region>.amazonaws.com/openai/v1``)
that takes a Bedrock API key as a bearer token. This adapter gives the agents
the same duck-typed interface as ``BedrockClaude`` and ``ChatOllama``:
``bind_tools(tools)``, ``invoke(messages)`` returning an ``AIMessage`` with
``tool_calls``, and ``model_copy(update={"num_predict": n})``.

The models put their chain of thought inline as ``<reasoning>…</reasoning>``
in the message content; it is removed before the agents parse the answer.
Every call is priced, appended to the same spend ledger as the Claude backend
and checked against ``config.bedrock_budget_usd`` first.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path

from lgtm.agents.bedrock_llm import _LEDGER_LOCK, PRICE_SAFETY, BedrockBudgetExceeded, _text, ledger_total
from lgtm.config import LGTMConfig

# USD per million tokens (input, output), Bedrock on-demand list prices.
PRICES: dict[str, tuple[float, float]] = {
    "gpt-oss-20b": (0.07, 0.30),
    "gpt-oss-120b": (0.15, 0.60),
}
REASONING_RE = re.compile(r"<reasoning>.*?</reasoning>", re.DOTALL)


def price_of(model: str) -> tuple[float, float]:
    for key, price in sorted(PRICES.items(), key=lambda kv: -len(kv[0])):
        if key in model:
            return price
    raise ValueError(f"No price for Bedrock model {model!r}; add it to PRICES before spending on it")


def strip_reasoning(text: str) -> str:
    text = REASONING_RE.sub("", text or "")
    # An unclosed block (output cut at the token limit) is all reasoning.
    head, sep, _ = text.partition("<reasoning>")
    return (head if sep else text).strip()


def _tool_schema(tool) -> dict:
    from langchain_core.utils.function_calling import convert_to_openai_tool

    return convert_to_openai_tool(tool)


def to_openai(messages) -> list[dict]:
    """LangChain messages -> OpenAI chat messages, every tool call answered once."""
    from langchain_core.messages import AIMessage, SystemMessage, ToolMessage

    out: list[dict] = []
    open_calls: list[str] = []

    def close_open_calls() -> None:
        for call_id in open_calls:
            out.append({"role": "tool", "tool_call_id": call_id, "content": "(omitted)"})
        open_calls.clear()

    for message in messages:
        if isinstance(message, SystemMessage):
            out.append({"role": "system", "content": _text(message.content)})
        elif isinstance(message, ToolMessage):
            if message.tool_call_id not in open_calls:
                continue
            open_calls.remove(message.tool_call_id)
            out.append({"role": "tool", "tool_call_id": message.tool_call_id,
                        "content": _text(message.content) or "(empty)"})
        elif isinstance(message, AIMessage):
            close_open_calls()
            entry: dict = {"role": "assistant", "content": _text(message.content).strip() or None}
            calls = [
                {"id": c["id"], "type": "function",
                 "function": {"name": c["name"], "arguments": json.dumps(c.get("args") or {})}}
                for c in message.tool_calls or []
            ]
            if calls:
                entry["tool_calls"] = calls
                open_calls.extend(c["id"] for c in calls)
            elif entry["content"] is None:
                entry["content"] = "(no output)"
            out.append(entry)
        else:
            close_open_calls()
            out.append({"role": "user", "content": _text(message.content) or "(empty)"})
    close_open_calls()
    return out


class BedrockOpenAI:
    """Duck-typed stand-in for ChatOllama backed by gpt-oss on Bedrock."""

    def __init__(self, config: LGTMConfig, *, tools: list[dict] | None = None,
                 all_tools: list[dict] | None = None, max_tokens: int | None = None, client=None):
        import httpx

        self.config = config
        self.model = config.bedrock_model
        price_of(self.model)  # refuse unpriced models before any call
        self.max_tokens = max_tokens or config.llm_max_output_tokens
        self.ledger = Path(os.path.expanduser(config.bedrock_ledger))
        self.tools = tools
        self.all_tools = all_tools if all_tools is not None else []
        if client is None:
            token = os.environ.get("AWS_BEARER_TOKEN_BEDROCK") or os.environ.get("AWS_BEDROCK_API_KEY")
            if not token:
                raise RuntimeError("Set AWS_BEARER_TOKEN_BEDROCK (a Bedrock API key) to use the Bedrock backend")
            client = httpx.Client(
                base_url=f"https://bedrock-runtime.{config.bedrock_region}.amazonaws.com/openai/v1",
                headers={"Authorization": f"Bearer {token}"},
                timeout=config.llm_timeout,
            )
        self._client = client

    def bind_tools(self, tools) -> BedrockOpenAI:
        schemas = [_tool_schema(t) for t in tools]
        self.all_tools[:] = schemas
        return BedrockOpenAI(self.config, tools=schemas, all_tools=self.all_tools,
                             max_tokens=self.max_tokens, client=self._client)

    def model_copy(self, update: dict | None = None) -> BedrockOpenAI:
        limit = (update or {}).get("num_predict") or self.max_tokens
        return BedrockOpenAI(self.config, tools=self.tools, all_tools=self.all_tools,
                             max_tokens=limit, client=self._client)

    def _post(self, body: dict) -> dict:
        delay = 2.0
        for attempt in range(4):
            response = self._client.post("/chat/completions", json=body)
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(delay)
                delay *= 2
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError("unreachable")

    def invoke(self, messages):
        from langchain_core.messages import AIMessage

        spent = ledger_total(self.ledger)
        if spent >= self.config.bedrock_budget_usd:
            raise BedrockBudgetExceeded(
                f"Bedrock spend ${spent:.2f} reached the ${self.config.bedrock_budget_usd:.2f} budget"
            )
        body: dict = {
            "model": self.model,
            "messages": to_openai(messages),
            "max_tokens": self.max_tokens,
            "temperature": self.config.llm_temperature,
        }
        if self.tools:
            body["tools"] = self.tools
        elif any(m.get("tool_calls") for m in body["messages"]) and self.all_tools:
            # The final answer is asked without tools; the history still holds tool turns.
            body["tools"] = self.all_tools
            body["tool_choice"] = "none"
        started = time.monotonic()
        data = self._post(body)
        usage = data.get("usage") or {}
        p_in, p_out = price_of(self.model)
        tokens_in, tokens_out = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        usd = (tokens_in * p_in + tokens_out * p_out) / 1_000_000 * PRICE_SAFETY
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": self.model, "usd": round(usd, 6),
            "input": tokens_in, "output": tokens_out, "cache_write": 0, "cache_read": 0,
            "seconds": round(time.monotonic() - started, 2), "run": self.config.bedrock_run_label,
        }
        with _LEDGER_LOCK:
            self.ledger.parent.mkdir(parents=True, exist_ok=True)
            with self.ledger.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        calls = []
        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append({"name": fn.get("name", ""), "args": args if isinstance(args, dict) else {},
                          "id": call.get("id") or uuid.uuid4().hex, "type": "tool_call"})
        return AIMessage(
            content=strip_reasoning(message.get("content") or ""), tool_calls=calls,
            usage_metadata={"input_tokens": tokens_in, "output_tokens": tokens_out,
                            "total_tokens": tokens_in + tokens_out},
            response_metadata={"model": self.model, "finish_reason": choice.get("finish_reason"), "usd": usd},
        )
