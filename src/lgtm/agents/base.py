"""Shared agent infrastructure: finding schema, LLM loop, JSON parsing."""

from __future__ import annotations

import json
import logging
import re
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from lgtm.config import LGTMConfig

logger = logging.getLogger(__name__)

Verdict = Literal["vulnerable", "safe", "possible", "insufficient_evidence"]

VALID_VERDICTS = {"vulnerable", "safe", "possible", "insufficient_evidence"}


class EvidenceItem(BaseModel):
    type: Literal["code", "policy"] = "code"
    file: str | None = None  # for code evidence
    lines: list[int] | None = None  # [start, end]
    source: str | None = None  # for policy evidence (doc path)
    content: str = ""


class AgentFinding(BaseModel):
    finding_id: str
    verdict: str = "insufficient_evidence"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    cwe_id: str = ""
    explanation: str = ""
    evidence: list[EvidenceItem] = Field(default_factory=list)
    suggested_fix: str = ""
    # Filled in by the pipeline / validator:
    category: str = ""  # "sqli" | "authz"
    agent: str = ""  # which agent produced this
    file: str = ""  # primary file under review
    line: int = 0  # primary line under review
    tool_calls_used: int = 0
    evidence_valid: bool | None = None
    evidence_issues: list[str] = Field(default_factory=list)
    raw_response: str = ""

    def normalized(self) -> "AgentFinding":
        """Clamp verdict/confidence into the allowed ranges."""
        if self.verdict not in VALID_VERDICTS:
            logger.warning(
                "Invalid verdict %r for %s; downgrading to insufficient_evidence",
                self.verdict,
                self.finding_id,
            )
            self.verdict = "insufficient_evidence"
        self.confidence = min(1.0, max(0.0, self.confidence))
        return self


def repair_json(candidate: str) -> str:
    """Escape unescaped double quotes inside JSON string values.

    Small local models often paste code (docstrings included) verbatim into
    JSON strings. A quote inside a string is treated as literal when the
    next non-whitespace character is not a structural delimiter.
    """
    out: list[str] = []
    in_str = False
    i = 0
    n = len(candidate)
    while i < n:
        ch = candidate[i]
        if not in_str:
            if ch == '"':
                in_str = True
            out.append(ch)
            i += 1
            continue
        # Inside a string
        if ch == "\\" and i + 1 < n:
            out.append(ch)
            out.append(candidate[i + 1])
            i += 2
            continue
        if ch == '"':
            j = i + 1
            while j < n and candidate[j] in " \t\r\n":
                j += 1
            if j >= n or candidate[j] in ",:}]":
                in_str = False
                out.append(ch)
            else:
                out.append('\\"')
            i += 1
            continue
        if ch == "\n":
            out.append("\\n")  # literal newlines are invalid in JSON strings
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _loads_lenient(candidate: str) -> dict | None:
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    try:
        repaired = repair_json(candidate)
        data = json.loads(repaired)
        logger.debug("JSON parsed only after repair")
        return data
    except json.JSONDecodeError:
        return None


def extract_json_object(text: str) -> dict | None:
    """Extract the first plausible JSON object from LLM output.

    Handles fenced code blocks, leading prose, trailing commentary, and
    common escaping mistakes (unescaped quotes/newlines in string values).
    """
    # Try fenced blocks first
    for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
        data = _loads_lenient(match.group(1))
        if data is not None:
            return data
    # Then scan for balanced top-level braces
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\" and in_str:
                escape = True
            elif ch == '"':
                in_str = not in_str
            elif not in_str:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        data = _loads_lenient(text[start : i + 1])
                        if data is not None:
                            return data
                        break
        start = text.find("{", start + 1)
    # Last resort: first "{" through last "}" with repair
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        return _loads_lenient(text[first : last + 1])
    return None


def parse_agent_output(
    text: str, finding_id: str, default_cwe: str = ""
) -> AgentFinding:
    """Parse an agent's final response into an AgentFinding.

    Falls back to ``insufficient_evidence`` when the output is unparsable,
    so a malformed LLM response never crashes the pipeline.
    """
    data = extract_json_object(text)
    if data is None:
        logger.warning("Agent output for %s contained no JSON", finding_id)
        return AgentFinding(
            finding_id=finding_id,
            verdict="insufficient_evidence",
            cwe_id=default_cwe,
            explanation="Agent did not produce parsable structured output.",
            raw_response=text[:2000],
        )

    # Coerce evidence entries defensively
    evidence: list[EvidenceItem] = []
    for item in data.get("evidence", []) or []:
        if not isinstance(item, dict):
            continue
        lines = item.get("lines")
        if isinstance(lines, int):
            lines = [lines, lines]
        elif isinstance(lines, list):
            lines = [int(x) for x in lines if isinstance(x, (int, float))][:2] or None
        else:
            lines = None
        etype = item.get("type", "code")
        if etype not in ("code", "policy"):
            etype = "policy" if item.get("source") else "code"
        try:
            evidence.append(
                EvidenceItem(
                    type=etype,
                    file=item.get("file"),
                    lines=lines,
                    source=item.get("source"),
                    content=str(item.get("content", ""))[:2000],
                )
            )
        except ValidationError:
            continue

    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = min(1.0, max(0.0, confidence))

    finding = AgentFinding(
        finding_id=str(data.get("finding_id") or finding_id),
        verdict=str(data.get("verdict", "insufficient_evidence")).strip().lower(),
        confidence=confidence,
        cwe_id=str(data.get("cwe_id", default_cwe) or default_cwe),
        explanation=str(data.get("explanation", "")),
        evidence=evidence,
        suggested_fix=str(data.get("suggested_fix", "") or ""),
        raw_response=text[:2000],
    )
    return finding.normalized()


def build_llm(config: LGTMConfig):
    """Construct the ChatOllama LLM from config."""
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=config.ollama_model,
        base_url=config.ollama_base_url,
        temperature=config.llm_temperature,
        keep_alive="24h",
        # Bound each call (timeout) and the output length (num_predict): a
        # runaway generation with no stop token blocked a benchmark run for
        # over an hour before either existed.
        num_predict=config.llm_max_output_tokens,
        client_kwargs={"timeout": config.llm_timeout},
    )


TOOL_CALL_TAG_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


def parse_text_tool_calls(content: str, tool_names: set[str]) -> list[dict]:
    """Recover tool calls that a model wrote as plain text.

    Some local models (qwen2.5-coder via Ollama) advertise tool support but
    answer with ``{"name": "read_file", "arguments": {...}}`` in the message
    body instead of a native tool call. Without this fallback the loop takes
    that text as the final answer and the agent never uses its tools.
    """
    if not content or not tool_names:
        return []
    blocks = TOOL_CALL_TAG_RE.findall(content)
    candidates = [extract_json_object(b) for b in blocks] if blocks else [
        extract_json_object(content)
    ]
    calls: list[dict] = []
    for i, data in enumerate(candidates):
        if not isinstance(data, dict) or "verdict" in data:
            continue  # a final answer, not a tool call
        name = data.get("name")
        args = data.get("arguments", data.get("parameters", {}))
        if isinstance(args, str):  # OpenAI style: arguments as a JSON string
            try:
                args = json.loads(args) if args.strip() else {}
            except json.JSONDecodeError:
                continue
        if name in tool_names and isinstance(args, dict):
            calls.append({"name": name, "args": args, "id": f"text_call_{i}"})
    return calls


def run_tool_loop(
    llm,
    tools: list,
    system_prompt: str,
    user_prompt: str,
    config: LGTMConfig,
) -> str:
    """Run a manual tool-calling loop and return the final text response.

    The loop stops when the model answers without tool calls or when the
    iteration cap is reached (the model is then forced to answer).
    """
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    tool_map = {t.name: t for t in tools}
    llm_with_tools = llm.bind_tools(tools)
    messages: list = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
    tools_used = 0
    pushed_back = False

    for iteration in range(config.max_agent_iterations):
        response = llm_with_tools.invoke(messages)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        content = response.content if isinstance(response.content, str) else str(response.content)
        text_calls = False
        if not tool_calls:
            tool_calls = parse_text_tool_calls(content, set(tool_map))
            text_calls = bool(tool_calls)
            if not tool_calls:
                if config.require_tool_use and tools and not tools_used and not pushed_back:
                    # The model answered from the prompt alone; ask it once
                    # to verify against the repository first.
                    pushed_back = True
                    messages.append(
                        HumanMessage(
                            content=(
                                "Before giving a verdict, verify your reasoning "
                                "against the repository: call at least one tool "
                                "(e.g. read the auth decorators or the function "
                                "you are judging). Then give your final JSON."
                            )
                        )
                    )
                    continue
                return content

        tools_used += len(tool_calls)
        for call in tool_calls:
            name = call.get("name")
            args = call.get("args", {}) or {}
            call_id = call.get("id", f"call_{iteration}")
            tool_fn = tool_map.get(name)
            if tool_fn is None:
                result = f"ERROR: unknown tool '{name}'"
            else:
                try:
                    result = tool_fn.invoke(args)
                except Exception as exc:  # noqa: BLE001 - surface to the model
                    logger.warning("Tool %s raised: %s", name, exc)
                    result = f"ERROR: tool failed: {exc}"
            if text_calls:
                # No native tool_call to attach a ToolMessage to: return the
                # result as a user turn instead.
                messages.append(
                    HumanMessage(
                        content=f"Result of {name}({json.dumps(args)}):\n{result}\n\n"
                        "Call another tool, or give your final JSON verdict."
                    )
                )
            else:
                messages.append(ToolMessage(content=str(result), tool_call_id=call_id))

    # Iteration cap reached: force a final answer without tools.
    logger.warning("Agent hit iteration cap (%d); forcing final answer", config.max_agent_iterations)
    messages.append(
        HumanMessage(
            content=(
                "You have used all available analysis steps. Produce your final "
                "JSON verdict NOW based on the evidence gathered so far. "
                "Respond with ONLY the JSON object."
            )
        )
    )
    response = llm.invoke(messages)
    return response.content if isinstance(response.content, str) else str(response.content)
