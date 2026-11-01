"""Shared agent infrastructure: finding schema, LLM loop, JSON parsing."""

from __future__ import annotations

import inspect
import json
import logging
import math
import re
import time
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from lgtm.agents import registry
from lgtm.config import LGTMConfig

logger = logging.getLogger(__name__)

PARSE_RETRIES = 3

UNRESOLVED_EVIDENCE_REASON = "unresolved-evidence"

SNAPSHOT_LABELS = ("base", "pr")

_LOCATOR_ALIAS = re.compile(
    r"^(?P<path>.+?)(?::L(?P<start>\d+)(?:-L?(?P<end>\d+))?)?\s+@(?P<label>base|pr)$",
    re.IGNORECASE,
)


class EvidenceItem(BaseModel):
    type: Literal["code", "policy"] = "code"
    file: str | None = None  # for code evidence
    lines: list[int] | None = None  # [start, end]
    source: str | None = None  # for policy evidence (doc path)
    content: str = ""
    snapshot: Literal["base", "pr"] | None = None
    snapshot_conflict: bool = False
    grounded_in_pr: bool | None = None
    raw_snapshot: Any = Field(default=None, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _normalize_locator_and_snapshot(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        updates: dict[str, Any] = {}

        alias_label = None
        file = data.get("file")
        alias = _LOCATOR_ALIAS.match(file.strip()) if isinstance(file, str) else None
        if alias is not None:
            alias_label = alias["label"].lower()
            updates["file"] = alias["path"]
            if data.get("lines") is None and alias["start"] is not None:
                start = int(alias["start"])
                end = int(alias["end"]) if alias["end"] is not None else start
                updates["lines"] = [start, end]

        # Unknown values are never kept as labels; the conflict flag and raw value record them.
        raw = data.get("snapshot")
        label = raw.strip().lower() if isinstance(raw, str) else raw
        if label in SNAPSHOT_LABELS and alias_label not in (None, label):
            updates.update(snapshot=None, snapshot_conflict=True)
        elif label in SNAPSHOT_LABELS or label in (None, ""):
            updates["snapshot"] = label if label in SNAPSHOT_LABELS else alias_label
        else:
            updates.update(snapshot=None, snapshot_conflict=True, raw_snapshot=raw)
        return {**data, **updates}


class AgentFinding(BaseModel):
    finding_id: str
    cwe_id: str = ""
    explanation: str = ""
    evidence: list[EvidenceItem] = Field(default_factory=list)
    suggested_fix: str = ""
    semgrep_rule_id: str = ""
    semgrep_severity: str = ""
    semgrep_message: str = ""
    # Result fields: left unset by agents, written by validation.
    verdict: str = ""  # baseline modes only
    severity: str = ""
    supported: bool | None = None
    provenance_confidence: float | None = None
    kev_verdict: str | None = None
    kev_severity: str | None = None
    judged: bool = False
    not_judged_reason: str = ""
    unsupported_reason: str = ""
    # Filled in by the pipeline / validator:
    category: str = ""  # "sqli" | "authz"
    agent: str = ""  # which agent produced this
    file: str = ""  # primary file under review
    line: int = 0  # primary line under review
    tool_calls_used: int = 0
    # Set by the pipeline from graph session health; never read from model JSON.
    pr_graph_ok: bool | None = None
    raw_response: str = ""


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


def _is_tool_output(content: str) -> bool:
    """Tool envelopes and failure text are not code evidence."""
    text = content.lstrip()
    return text.startswith(tuple(registry.entry("shared.tool_output_prefixes"))) or any(
        marker in text for marker in registry.entry("shared.tool_output_markers")
    )


def parse_agent_output(
    text: str, finding_id: str, default_cwe: str = ""
) -> AgentFinding:
    """Parse an agent's final response into an AgentFinding.

    The model's verdict and confidence are ignored. Unparsable output yields
    a placeholder candidate, so a malformed LLM response never crashes the
    pipeline.
    """
    text = _content_text(text)
    data = extract_json_object(text)
    if data is None:
        logger.warning("Agent output for %s contained no JSON", finding_id)
        return AgentFinding(
            finding_id=finding_id,
            cwe_id=default_cwe,
            explanation=registry.entry("shared.unparsable_explanation"),
            raw_response=text[:2000],
        )

    # Coerce evidence entries defensively
    evidence: list[EvidenceItem] = []
    for item in data.get("evidence", []) or []:
        if not isinstance(item, dict):
            continue
        content = str(item.get("content", ""))
        if _is_tool_output(content):
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
                    content=content[:2000],
                    snapshot=item.get("snapshot"),
                )
            )
        except ValidationError:
            continue

    return AgentFinding(
        finding_id=str(data.get("finding_id") or finding_id),
        cwe_id=str(data.get("cwe_id", default_cwe) or default_cwe),
        explanation=str(data.get("explanation", "")),
        evidence=evidence,
        suggested_fix=str(data.get("suggested_fix", "") or ""),
        raw_response=text[:2000],
    )


def answer_until_parsed(
    ask: Callable[[], str],
    parse: Callable[[str], Any | None],
    stop: Callable[[], bool] = lambda: False,
) -> Any | None:
    """Run ``ask`` until ``parse`` accepts its answer, retrying PARSE_RETRIES times.

    Exceptions from ``ask`` propagate unretried; None means every answer failed to parse.
    ``stop`` is checked after each failed parse and ends the retries.
    """
    for _ in range(PARSE_RETRIES + 1):
        result = parse(ask())
        if result is not None:
            return result
        if stop():
            break
    return None


def answer_until_resolved(
    ask: Callable[..., str],
    parse: Callable[[str], AgentFinding | list[AgentFinding] | None],
    toolbox: Any,
) -> list[AgentFinding] | None:
    """Like ``answer_until_parsed``, but an answer citing code that does not resolve at the
    toolbox snapshots counts as a parse failure.

    ``ask`` may take one optional argument: after such a failure it receives the re-ask text
    naming the unresolved citations. After the budget the last such answer is returned whole;
    candidates with unresolved items are marked unsupported (logged). None means no answer parsed.
    """
    from lgtm.validation.evidence import EvidenceValidator

    validator = EvidenceValidator(
        toolbox.repo, toolbox.base_ref, config=toolbox.config, shas=toolbox.shas
    )
    unresolved: list[AgentFinding] | None = None
    unresolved_ids: set[str] = set()
    note = ""
    takes_note = bool(inspect.signature(ask).parameters)

    def check(raw: str) -> list[AgentFinding] | None:
        nonlocal unresolved, unresolved_ids, note
        result = parse(raw)
        if result is None:
            return None
        findings = result if isinstance(result, list) else [result]
        issues = {
            id(f): [
                issue
                for i in f.evidence
                if i.type != "policy"
                for issue in validator.resolution_issues(i)
            ]
            for f in findings
        }
        if not any(issues.values()):
            return findings
        unresolved = findings
        unresolved_ids = {id(f) for f in findings if issues[id(f)]}
        note = registry.render(
            "shared.unresolved_reask",
            details="; ".join(i for found in issues.values() for i in found)[:1000],
        )
        return None

    def ask_with_note() -> str:
        return ask(note) if note and takes_note else ask()

    answer = answer_until_parsed(ask_with_note, check, lambda: toolbox.budget_spent)
    if answer is not None:
        return answer
    for f in unresolved or []:
        if id(f) in unresolved_ids:
            f.supported = False
            f.unsupported_reason = UNRESOLVED_EVIDENCE_REASON
            logger.warning("Kept candidate %s unsupported: cited code does not resolve", f.finding_id)
    return unresolved


def build_llm(config: LGTMConfig):
    """Construct the ChatOllama LLM from config."""
    from langchain_ollama import ChatOllama

    kwargs = {} if config.reasoning is None else {"reasoning": config.reasoning}
    return ChatOllama(
        model=config.ollama_model,
        base_url=config.ollama_base_url,
        temperature=config.llm_temperature,
        keep_alive="24h",
        # Bound each call (timeout) and the output length (num_predict): a
        # runaway generation with no stop token blocked a benchmark run for
        # over an hour before either existed.
        num_predict=config.llm_max_output_tokens,
        num_ctx=config.llm_context_tokens,
        client_kwargs={"timeout": config.llm_timeout},
        **kwargs,
    )


TOOL_CALL_TAG_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


def parse_text_tool_calls(
    content: str, tool_names: set[str], *, include_unknown: bool = False
) -> list[dict]:
    """Recover tool calls that a model wrote as plain text.

    Some local models (qwen2.5-coder via Ollama) advertise tool support but
    answer with ``{"name": "read_file", "arguments": {...}}`` in the message
    body instead of a native tool call. Without this fallback the loop takes
    that text as the final answer and the agent never uses its tools.

    With ``include_unknown``, requests naming an unregistered tool are returned
    too, and arguments that are not a JSON object are returned unchanged.
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
        if not isinstance(name, str):
            continue
        known = name in tool_names
        if not known and not (include_unknown and ("arguments" in data or "parameters" in data)):
            continue
        args = data.get("arguments", data.get("parameters", {}))
        if isinstance(args, str):  # OpenAI style: arguments as a JSON string
            try:
                args = json.loads(args) if args.strip() else {}
            except json.JSONDecodeError:
                pass
        if not include_unknown and not (known and isinstance(args, dict)):
            continue
        calls.append({"name": name, "args": args, "id": f"text_call_{i}"})
    return calls


_sleep = time.sleep


def message_text(response) -> str:
    return _content_text(response.content)


def _content_text(content) -> str:
    if isinstance(content, list):
        return "\n".join(
            part if isinstance(part, str) else str(part.get("text", ""))
            for part in content
            if isinstance(part, str) or (isinstance(part, dict) and part.get("type", "text") == "text")
        )
    return content if isinstance(content, str) else str(content)


def is_json_object(text: str) -> bool:
    return isinstance(extract_json_object(text), dict)


def invoke_with_retry(llm, messages, config: LGTMConfig, output_tokens: int | None = None) -> Any:
    """``output_tokens`` is the output limit ``llm`` was built with, for the context allowance."""
    if output_tokens is None:
        output_tokens = config.llm_max_output_tokens
    allowance = (config.llm_context_tokens - output_tokens) * CHARS_PER_TOKEN
    if _message_chars(messages) > allowance:
        raise ValueError("Model request exceeds the configured context allowance")
    attempts = max(0, config.llm_retries) + 1
    delays = tuple(config.llm_backoff_seconds)
    for attempt in range(1, attempts + 1):
        try:
            return llm.invoke(messages)
        except Exception as exc:
            if attempt == attempts:
                raise
            delay = delays[min(attempt - 1, len(delays) - 1)] if delays else 0.0
            logger.warning(
                "LLM call failed (attempt %d of %d): %s: %s; retrying in %.1fs",
                attempt,
                attempts,
                type(exc).__name__,
                str(exc)[:200],
                delay,
            )
            _sleep(delay)


def validate_tool_call(name: object, tool_map: dict, args: object) -> str | None:
    if not isinstance(name, str) or name not in tool_map:
        available = ", ".join(sorted(tool_map)) or registry.entry("shared.no_tools_available")
        details = registry.render("shared.unknown_tool", available=available)
    elif not isinstance(args, dict):
        details = registry.entry("shared.arguments_not_object")
    else:
        schema = getattr(tool_map[name], "args_schema", None)
        if not (isinstance(schema, type) and issubclass(schema, BaseModel)):
            return None
        try:
            schema.model_validate(args)
        except ValidationError as exc:
            details = "; ".join(
                f"{'.'.join(str(p) for p in e['loc']) or registry.entry('shared.arguments_location')}: {e['msg']}"
                for e in exc.errors()
            )
        else:
            return None
    details = details[:300].rstrip(". ")
    return registry.render("shared.invalid_tool_input", name=name, details=details)


@dataclass(frozen=True)
class FinalAnswerSpec:
    """How a tool loop asks for, checks and re-asks its final answer; the defaults are the shared behaviour."""

    is_valid: Callable[[str], bool] = is_json_object
    reask: str = "shared.reask"
    forced_final: str = "shared.forced_final"
    options: dict = field(default_factory=dict)


# Carries the spec to run_tool_loop without widening its signature.
_final_answer: ContextVar[FinalAnswerSpec | None] = ContextVar("final_answer", default=None)


@contextmanager
def final_answer_spec(spec: FinalAnswerSpec):
    token = _final_answer.set(spec)
    try:
        yield
    finally:
        _final_answer.reset(token)


def _with_options(llm, options: dict):
    # ChatOllama rejects per-call num_predict; it reads the field at call time, so a copy applies it.
    copy = getattr(llm, "model_copy", None)
    return copy(update=options) if options and copy else llm


_TEXT_RESULT = "text_call_result"


def context_allowance(config: LGTMConfig, output_tokens: int) -> int:
    """Characters a tool-loop request may hold: the headroom share of the usable window, rounded down."""
    return math.floor((config.llm_context_tokens - output_tokens) * CHARS_PER_TOKEN * config.llm_window_headroom)


def cut_to_fit(text: str, budget: int) -> str:
    """Keep the start and end of ``text`` within ``budget`` characters; a marker stating the cut size replaces the middle."""
    if len(text) <= budget:
        return text
    # The marker for len(text) cut characters is the longest one the cut can need.
    keep = max(0, budget - len(registry.render("shared.prompt_cut", chars=len(text))))
    head = keep // 2
    marker = registry.render("shared.prompt_cut", chars=len(text) - keep)
    return (text[:head] + marker + text[len(text) - (keep - head) :])[: max(0, budget)]


def user_prompt_budget(config: LGTMConfig, system_prompt: str, final: FinalAnswerSpec) -> int:
    """Characters left for the user prompt of a first request, with room for the closing instruction."""
    window = min(
        context_allowance(config, config.llm_max_output_tokens),
        context_allowance(config, final.options.get("num_predict", config.llm_max_output_tokens)),
    )
    return window - len(system_prompt) - len(registry.entry(final.forced_final))


def _fit_reask(messages: list, config: LGTMConfig, output_tokens: int) -> bool:
    """Drop the oldest messages after the system and user pair until the request fits; the failed answer and the re-ask stay."""
    from langchain_core.messages import ToolMessage

    allowance = context_allowance(config, output_tokens)
    total = _message_chars(messages)
    drop = 2
    # Results of a dropped tool-call turn go with it.
    while drop < len(messages) - 2 and (total > allowance or isinstance(messages[drop], ToolMessage)):
        total -= _message_chars([messages[drop]])
        drop += 1
    del messages[2:drop]
    return total <= allowance


def _trim_prose(message, excess: int) -> str | None:
    """The text of ``message`` with ``excess`` characters cut from the end of its prose; tool-call markup stays whole.

    None when the prose is shorter than ``excess``.
    """
    text = message.content
    if not isinstance(text, str):
        return None
    if message.tool_calls:
        prose = [(0, len(text))]
    else:
        tags = [m.span() for m in TOOL_CALL_TAG_RE.finditer(text)]
        if not tags:
            return None
        bounds = [0, *(edge for span in tags for edge in span), len(text)]
        prose = list(zip(bounds[0::2], bounds[1::2]))
    if sum(end - start for start, end in prose) < excess:
        return None
    for start, end in reversed(prose):
        take = min(end - start, excess)
        text = text[: end - take] + text[end:]
        excess -= take
    return text


def fit_closing_request(messages: list, config: LGTMConfig, output_tokens: int, closing: bool = False) -> bool:
    """Shorten older tool results, oldest first, until the request fits; the results right before the final message stay.

    Covers ToolMessage results and text-form results (marked HumanMessages). With ``closing``, the prose of the
    assistant turn that precedes those results is then cut to the room left; its tool calls, native or text-form,
    stay whole. Replaces list entries instead of editing them. False when the request still does not fit.
    """
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

    def is_result(message) -> bool:
        return isinstance(message, ToolMessage) or bool(getattr(message, "additional_kwargs", {}).get(_TEXT_RESULT))

    allowance = context_allowance(config, output_tokens)
    total = _message_chars(messages)
    recent = len(messages) - 1
    while recent > 0 and is_result(messages[recent - 1]):
        recent -= 1
    stub = registry.entry("tools.result_elided")
    for i in range(recent):
        message = messages[i]
        if total <= allowance:
            break
        if is_result(message) and len(str(message.content)) > len(stub):
            total -= len(str(message.content)) - len(stub)
            if isinstance(message, ToolMessage):
                messages[i] = ToolMessage(content=stub, tool_call_id=message.tool_call_id)
            else:
                messages[i] = HumanMessage(content=stub, additional_kwargs={_TEXT_RESULT: True})
    stop_turn = recent - 1
    excess = total - allowance
    if closing and excess > 0 and stop_turn > 1 and isinstance(messages[stop_turn], AIMessage):
        trimmed = _trim_prose(messages[stop_turn], excess)
        if trimmed is not None:
            messages[stop_turn] = messages[stop_turn].model_copy(update={"content": trimmed})
            total = allowance
    return total <= allowance


def request_valid_answer(
    llm,
    messages: list,
    content: str,
    config: LGTMConfig,
    is_valid: Callable[[str], bool],
    on_turn: Callable[[str], Any] | None = None,
    reask: str = "shared.reask",
    options: dict | None = None,
    fit: bool = False,
) -> str:
    """``fit`` fits each re-ask to the headroom-adjusted window, whether or not ``options`` carry an output limit."""
    from langchain_core.messages import HumanMessage

    reasks = 0
    cap = max(0, config.max_answer_reasks)
    output_tokens = (options or {}).get("num_predict")
    if fit and output_tokens is None:
        output_tokens = config.llm_max_output_tokens
    while not is_valid(content) and reasks < cap:
        reasks += 1
        logger.warning("Final answer was not valid JSON; re-asking (%d of %d)", reasks, cap)
        messages.append(HumanMessage(content=registry.entry(reask)))
        if output_tokens is not None and not _fit_reask(messages, config, output_tokens):
            logger.warning("Re-ask does not fit the context allowance; keeping the invalid answer")
            messages.pop()
            break
        response = invoke_with_retry(llm, messages, config, output_tokens)
        messages.append(response)
        content = message_text(response)
        if on_turn is not None:
            on_turn(content)
    return content


def _toolbox_of(tools) -> Any:
    for tool in tools:
        toolbox = (getattr(tool, "metadata", None) or {}).get("toolbox")
        if toolbox is not None:
            return toolbox
    return None


@dataclass
class RunRecord:
    """What one agent run did: tool calls, final answer text, the budget it hit, and the turns.

    A turn is ``{"assistant": text, "tool_calls": [{"tool", "args", "result"}]}``, in the order made.
    """

    section: str
    tool_calls: list[dict] = field(default_factory=list)
    raw_answer: str = ""
    limit_hit: Literal["tool_calls", "steps"] | None = None
    turns: list[dict] = field(default_factory=list)


def _close_run(
    toolbox: Any, answer: str, steps_exhausted: bool, budget_spent: bool = False, closing_unfitted: bool = False
) -> str:
    if toolbox is not None:
        toolbox.steps_exhausted = steps_exhausted
        toolbox.budget_spent = budget_spent
        toolbox.closing_unfitted = closing_unfitted
    return answer


def fill_record(record: RunRecord, toolbox: Any, answer: str) -> str:
    """Fill ``record`` from the toolbox after a ``run_tool_loop`` call; returns ``answer``.

    Raises ValueError, after filling, when the loop could not fit a request to the context window.
    """
    record.raw_answer = answer
    record.tool_calls = list(toolbox.call_log)
    record.turns = getattr(toolbox, "turns", record.turns)
    over_budget = getattr(toolbox, "budget_spent", False) or len(toolbox.call_log) > toolbox.budget
    if toolbox.steps_exhausted:
        record.limit_hit = "steps"
    else:
        record.limit_hit = "tool_calls" if over_budget else None
    if getattr(toolbox, "closing_unfitted", False):
        raise ValueError(registry.entry("tools.closing_not_fitted"))
    return answer


CHARS_PER_TOKEN = 3


def _message_chars(messages: list) -> int:
    return sum(len(str(m.content)) for m in messages)


def run_tool_loop(
    llm,
    tools: list,
    system_prompt: str,
    user_prompt: str,
    config: LGTMConfig,
) -> str:
    """Run a manual tool-calling loop and return the final text response.

    The loop stops when the model answers without tool calls, when the
    iteration cap is reached, or when the invalid tool input cap is reached
    (the model is then forced to answer). Final answers that are not JSON
    objects are re-asked up to ``max_answer_reasks`` times.
    """
    from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

    final = _final_answer.get() or FinalAnswerSpec()
    tool_map = {t.name: t for t in tools}
    toolbox = _toolbox_of(tool_map.values())
    # The toolbox cut and this reserve share one bound; 0 leaves the default loop behaviour.
    result_bound = getattr(getattr(toolbox, "evidence", None), "bound", 0)
    llm_with_tools = llm.bind_tools(tools)
    final_llm = _with_options(llm, final.options)
    user_prompt = cut_to_fit(user_prompt, max(0, user_prompt_budget(config, system_prompt, final)))
    messages: list = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
    tools_used = 0
    pushed_back = False
    invalid_inputs = 0
    budget_spent = False
    context_full = False
    cap = config.max_invalid_tool_inputs
    window_chars = context_allowance(config, config.llm_max_output_tokens)
    final_chars = len(registry.entry(final.forced_final))
    stop_chars = (
        max(len(registry.entry("tools.context_full")), len(toolbox.BUDGET_MESSAGE)) if result_bound else 0
    )
    final_window_chars = context_allowance(config, final.options.get("num_predict", config.llm_max_output_tokens))
    turns = getattr(toolbox, "turns", None)

    def log_turn(text: str) -> dict:
        turn = {"assistant": text, "tool_calls": []}
        if turns is not None:
            turns.append(turn)
        return turn

    for iteration in range(config.max_agent_iterations):
        if _message_chars(messages) > window_chars and not fit_closing_request(
            messages, config, config.llm_max_output_tokens
        ):
            logger.warning("Request does not fit the context allowance; not sent")
            return _close_run(toolbox, "", False, budget_spent, closing_unfitted=True)
        round_start = _message_chars(messages)
        response = invoke_with_retry(llm_with_tools, messages, config)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        content = message_text(response)
        turn = log_turn(content)
        text_calls = False
        if not tool_calls:
            tool_calls = parse_text_tool_calls(content, set(tool_map), include_unknown=True)
            text_calls = bool(tool_calls)
            if not tool_calls:
                if config.require_tool_use and tools and not tools_used and not pushed_back:
                    # The model answered from the prompt alone; ask it once
                    # to verify against the repository first.
                    pushed_back = True
                    tool_names = ", ".join(t.name for t in tools)
                    messages.append(
                        HumanMessage(
                            content=registry.render("shared.verify_with_tools", tool_names=tool_names)
                        )
                    )
                    continue
                answer = request_valid_answer(
                    final_llm, messages, content, config, final.is_valid, log_turn, final.reask, final.options, fit=True
                )
                return _close_run(toolbox, answer, False)

        for position, call in enumerate(tool_calls):
            name = call.get("name")
            args = call.get("args", {}) or {}
            call_id = call.get("id", f"call_{iteration}")
            error = validate_tool_call(name, tool_map, args)
            if result_bound and not context_full:
                # A result at the bound plus a stop message per later call must still leave room for the closing request.
                context_full = (
                    _message_chars(messages)
                    + result_bound
                    + (len(tool_calls) - position - 1) * stop_chars
                    + final_chars
                    > min(window_chars, final_window_chars)
                )
            # Valid calls are charged by the tool body on invoke; rejected calls are charged here.
            if context_full:
                if toolbox is None or toolbox.charge(name, args):
                    result = registry.entry("tools.context_full")
                else:
                    result = toolbox.BUDGET_MESSAGE
            elif error:
                invalid_inputs += 1
                if toolbox is None or toolbox.charge(name, args):
                    logger.warning("Invalid tool input (%d of %d): tool=%s", invalid_inputs, cap, name)
                    result = error
                else:
                    result = toolbox.BUDGET_MESSAGE
            else:
                tools_used += 1
                try:
                    result = tool_map[name].invoke(args)
                except Exception as exc:  # noqa: BLE001 - surface to the model
                    logger.warning("Tool %s raised: %s", name, exc)
                    result = registry.render("shared.tool_failed", error=exc)
            turn["tool_calls"].append({"tool": name, "args": args, "result": str(result)})
            if text_calls:
                # No native tool_call to attach a ToolMessage to: return the
                # result as a user turn instead.
                messages.append(
                    HumanMessage(
                        content=registry.render(
                            "shared.text_call_result",
                            name=name,
                            args=json.dumps(args, default=str),
                            result=result,
                        ),
                        additional_kwargs={_TEXT_RESULT: True},
                    )
                )
            else:
                messages.append(ToolMessage(content=str(result), tool_call_id=call_id))
        if cap > 0 and invalid_inputs >= cap:
            break
        if toolbox is not None and toolbox.calls_used >= toolbox.budget:
            # Every further tool call would be refused and still cost a model call.
            budget_spent = True
            break
        if context_full:
            break
        used = _message_chars(messages)
        # Another round as large as this one, plus the final-answer prompt, would not fit.
        if not result_bound and used + (used - round_start) + final_chars > min(
            window_chars, final_window_chars
        ):
            context_full = True
            break

    invalid_capped = cap > 0 and invalid_inputs >= cap
    if context_full:
        logger.warning("Agent history nears the context window; asking for the final answer")
    elif invalid_capped:
        logger.warning("Agent hit invalid tool input cap (%d); forcing final answer", cap)
    elif budget_spent:
        logger.info("Agent spent its tool budget (%d); asking for the final answer", toolbox.budget)
    else:
        logger.warning("Agent hit iteration cap (%d); forcing final answer", config.max_agent_iterations)
    messages.append(HumanMessage(content=registry.entry(final.forced_final)))
    if not fit_closing_request(
        messages, config, final.options.get("num_predict", config.llm_max_output_tokens), closing=True
    ):
        logger.warning("Closing request does not fit the context allowance; not sent")
        return _close_run(
            toolbox,
            "",
            steps_exhausted=not (invalid_capped or budget_spent or context_full),
            budget_spent=budget_spent,
            closing_unfitted=True,
        )
    response = invoke_with_retry(final_llm, messages, config, final.options.get("num_predict"))
    messages.append(response)
    forced = message_text(response)
    log_turn(forced)
    answer = request_valid_answer(
        final_llm, messages, forced, config, final.is_valid, log_turn, final.reask, final.options, fit=True
    )
    return _close_run(
        toolbox,
        answer,
        steps_exhausted=not (invalid_capped or budget_spent or context_full),
        budget_spent=budget_spent,
    )
