"""Claude on Amazon Bedrock as the reviewer model, behind the interface the agents use.

The agents talk to a LangChain-style chat model: ``bind_tools(tools)``,
``invoke(messages)`` returning an ``AIMessage`` with ``tool_calls``, and
``model_copy(update={"num_predict": n})`` for a smaller output limit. This
adapter maps that onto the Anthropic SDK's Bedrock client, so the review
pipeline runs unchanged with Claude in place of the local Ollama model.

Every call is priced and appended to a spend ledger (JSONL). Before each call
the ledger total is checked against ``config.bedrock_budget_usd``; once it is
reached, calls raise ``BedrockBudgetExceeded`` instead of spending more.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from lgtm.config import LGTMConfig

# USD per million tokens (input, output), Anthropic list prices for the
# Bedrock global endpoints these IDs name. Cache writes cost 1.25x input,
# cache reads 0.1x input.
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-4-6": (5.00, 25.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}
# Headroom over list price, in case Bedrock bills these IDs above it.
PRICE_SAFETY = 1.10
_LEDGER_LOCK = threading.Lock()


class BedrockBudgetExceeded(RuntimeError):
    pass


def price_of(model: str) -> tuple[float, float]:
    for key, price in PRICES.items():
        if key in model:
            return price
    raise ValueError(f"No price for Bedrock model {model!r}; add it to PRICES before spending on it")


def call_cost(model: str, usage) -> float:
    p_in, p_out = price_of(model)
    written = getattr(usage, "cache_creation_input_tokens", 0) or 0
    read = getattr(usage, "cache_read_input_tokens", 0) or 0
    dollars = (
        usage.input_tokens * p_in
        + written * p_in * 1.25
        + read * p_in * 0.10
        + usage.output_tokens * p_out
    ) / 1_000_000
    return dollars * PRICE_SAFETY


def ledger_total(path: Path) -> float:
    if not path.is_file():
        return 0.0
    total = 0.0
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            total += float(json.loads(line)["usd"])
        except (ValueError, KeyError, TypeError):
            continue
    return total


def _tool_schema(tool) -> dict:
    from langchain_core.utils.function_calling import convert_to_openai_tool

    fn = convert_to_openai_tool(tool)["function"]
    return {
        "name": fn["name"],
        "description": fn.get("description", ""),
        "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
    }


def _text(content) -> str:
    if isinstance(content, list):
        return "\n".join(
            part if isinstance(part, str) else str(part.get("text", ""))
            for part in content
            if isinstance(part, str) or part.get("type", "text") == "text"
        )
    return content if isinstance(content, str) else str(content)


def to_anthropic(messages) -> tuple[str, list[dict]]:
    """LangChain messages -> (system, Anthropic messages), with every tool_use answered once."""
    from langchain_core.messages import AIMessage, SystemMessage, ToolMessage

    system: list[str] = []
    out: list[dict] = []
    open_calls: list[str] = []

    def user_blocks() -> list:
        if not out or out[-1]["role"] != "user":
            out.append({"role": "user", "content": []})
        return out[-1]["content"]

    def close_open_calls() -> None:
        # A trimmed history can drop a result; the API needs one per tool_use.
        for call_id in open_calls:
            user_blocks().insert(0, {"type": "tool_result", "tool_use_id": call_id, "content": "(omitted)"})
        open_calls.clear()

    for message in messages:
        if isinstance(message, SystemMessage):
            system.append(_text(message.content))
        elif isinstance(message, ToolMessage):
            if message.tool_call_id not in open_calls:
                continue
            open_calls.remove(message.tool_call_id)
            user_blocks().append(
                {"type": "tool_result", "tool_use_id": message.tool_call_id, "content": _text(message.content) or "(empty)"}
            )
        elif isinstance(message, AIMessage):
            close_open_calls()
            blocks: list[dict] = []
            text = _text(message.content).strip()
            if text:
                blocks.append({"type": "text", "text": text})
            for call in message.tool_calls or []:
                blocks.append({"type": "tool_use", "id": call["id"], "name": call["name"], "input": call.get("args") or {}})
                open_calls.append(call["id"])
            if not blocks:
                blocks.append({"type": "text", "text": "(no output)"})
            out.append({"role": "assistant", "content": blocks})
        else:
            if open_calls and out and out[-1]["role"] == "assistant":
                close_open_calls()
            user_blocks().append({"type": "text", "text": _text(message.content) or "(empty)"})
    close_open_calls()
    if out and out[0]["role"] != "user":
        out.insert(0, {"role": "user", "content": [{"type": "text", "text": "(start)"}]})
    return "\n\n".join(system), out


def _mark_cache(messages: list[dict]) -> None:
    """Cache the conversation prefix: the tool loop resends it on every turn."""
    for message in reversed(messages):
        if message["content"]:
            message["content"][-1] = {**message["content"][-1], "cache_control": {"type": "ephemeral"}}
            return


@dataclass
class _Shared:
    client: object
    tools: list[dict] = field(default_factory=list)


class BedrockClaude:
    """Duck-typed stand-in for ChatOllama: bind_tools, invoke, model_copy."""

    def __init__(self, config: LGTMConfig, *, shared: _Shared | None = None,
                 tools: list[dict] | None = None, max_tokens: int | None = None):
        self.config = config
        self.model = config.bedrock_model
        price_of(self.model)  # refuse unpriced models before any call
        self.max_tokens = max_tokens or config.llm_max_output_tokens
        self.ledger = Path(os.path.expanduser(config.bedrock_ledger))
        self.tools = tools
        if shared is None:
            import anthropic

            token = os.environ.get("AWS_BEARER_TOKEN_BEDROCK") or os.environ.get("AWS_BEDROCK_API_KEY")
            if not token:
                raise RuntimeError("Set AWS_BEARER_TOKEN_BEDROCK (a Bedrock API key) to use the Bedrock backend")
            shared = _Shared(anthropic.AnthropicBedrock(
                api_key=token, aws_region=config.bedrock_region, timeout=config.llm_timeout, max_retries=3,
            ))
        self._shared = shared

    def bind_tools(self, tools) -> BedrockClaude:
        schemas = [_tool_schema(t) for t in tools]
        self._shared.tools = schemas
        return BedrockClaude(self.config, shared=self._shared, tools=schemas, max_tokens=self.max_tokens)

    def model_copy(self, update: dict | None = None) -> BedrockClaude:
        limit = (update or {}).get("num_predict") or self.max_tokens
        return BedrockClaude(self.config, shared=self._shared, tools=self.tools, max_tokens=limit)

    def invoke(self, messages):
        from langchain_core.messages import AIMessage

        spent = ledger_total(self.ledger)
        if spent >= self.config.bedrock_budget_usd:
            raise BedrockBudgetExceeded(
                f"Bedrock spend ${spent:.2f} reached the ${self.config.bedrock_budget_usd:.2f} budget"
            )
        system, body = to_anthropic(messages)
        _mark_cache(body)
        kwargs: dict = {}
        has_tool_turns = any(b.get("type") == "tool_use" for m in body for b in m["content"])
        if self.tools:
            kwargs["tools"] = self.tools
        elif has_tool_turns and self._shared.tools:
            # The final answer is asked without tools; the history still holds tool turns.
            kwargs["tools"] = self._shared.tools
            kwargs["tool_choice"] = {"type": "none"}
        if system:
            kwargs["system"] = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        started = time.monotonic()
        response = self._shared.client.messages.create(
            # No temperature: the SDK no longer takes sampling parameters.
            model=self.model, max_tokens=self.max_tokens, messages=body, **kwargs,
        )
        usd = call_cost(self.model, response.usage)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": self.model, "usd": round(usd, 6),
            "input": response.usage.input_tokens, "output": response.usage.output_tokens,
            "cache_write": getattr(response.usage, "cache_creation_input_tokens", 0) or 0,
            "cache_read": getattr(response.usage, "cache_read_input_tokens", 0) or 0,
            "seconds": round(time.monotonic() - started, 2), "run": self.config.bedrock_run_label,
        }
        with _LEDGER_LOCK:
            self.ledger.parent.mkdir(parents=True, exist_ok=True)
            with self.ledger.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        text = "\n".join(b.text for b in response.content if b.type == "text")
        calls = [
            {"name": b.name, "args": b.input if isinstance(b.input, dict) else {}, "id": b.id or uuid.uuid4().hex, "type": "tool_call"}
            for b in response.content if b.type == "tool_use"
        ]
        # Anthropic's input_tokens leaves out cached prompt tokens; the model still read them.
        prompt_tokens = response.usage.input_tokens + entry["cache_write"] + entry["cache_read"]
        return AIMessage(
            content=text, tool_calls=calls,
            usage_metadata={"input_tokens": prompt_tokens, "output_tokens": response.usage.output_tokens,
                            "total_tokens": prompt_tokens + response.usage.output_tokens,
                            "input_token_details": {"cache_creation": entry["cache_write"],
                                                    "cache_read": entry["cache_read"]}},
            response_metadata={"model": self.model, "stop_reason": response.stop_reason, "usd": usd},
        )
