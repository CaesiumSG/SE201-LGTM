"""Token usage of one review: what the models read and wrote, as the backends report it.

``ReviewPipeline.run`` opens a meter with :func:`metering`; every reviewer-model
call made through ``invoke_with_retry`` and every judge reply is added to it,
under the stage the pipeline has set with :func:`stage`. Outside a meter,
recording does nothing, so agents used on their own are unaffected.

Counts come from the reply's ``usage_metadata`` (Ollama's ``prompt_eval_count``
and ``eval_count``; Bedrock's input, cache and output tokens). A reply without
usage is counted in ``unreported_calls`` rather than guessed. Ollama may report
fewer prompt tokens when it reuses its prompt cache, so each stage also keeps
``estimated_input_tokens`` (prompt characters / ``CHARS_PER_TOKEN``) as a
cross-check.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from typing import Any

UNLABELLED = "other"


@dataclass
class StageUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_input_tokens: int = 0
    unreported_calls: int = 0

    def add(self, other: StageUsage) -> None:
        self.calls += other.calls
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.estimated_input_tokens += other.estimated_input_tokens
        self.unreported_calls += other.unreported_calls


@dataclass
class UsageMeter:
    stages: dict[str, StageUsage] = field(default_factory=dict)
    judge_calls: int = 0
    judge_input_tokens: int = 0
    judge_unreported_calls: int = 0

    def _stage(self, name: str) -> StageUsage:
        return self.stages.setdefault(name, StageUsage())

    def add_llm(self, name: str, usage: Mapping[str, Any] | None, estimated_input: int) -> None:
        s = self._stage(name)
        s.calls += 1
        s.estimated_input_tokens += max(0, int(estimated_input))
        input_tokens = _count(usage, "input_tokens")
        output_tokens = _count(usage, "output_tokens")
        if input_tokens is None and output_tokens is None:
            s.unreported_calls += 1
            return
        s.input_tokens += input_tokens or 0
        s.output_tokens += output_tokens or 0

    def add_judge(self, input_tokens: Any) -> None:
        self.judge_calls += 1
        n = _count({"n": input_tokens}, "n")
        if n is None:
            self.judge_unreported_calls += 1
        else:
            self.judge_input_tokens += n

    def summary(self) -> dict[str, Any]:
        """JSON-ready totals: reviewer model overall and per stage, and the judge."""
        total = StageUsage()
        for s in self.stages.values():
            total.add(s)
        return {
            "reviewer": {
                **asdict(total),
                "total_tokens": total.input_tokens + total.output_tokens,
                "by_stage": {name: asdict(s) for name, s in sorted(self.stages.items())},
            },
            "judge": {
                "calls": self.judge_calls,
                "input_tokens": self.judge_input_tokens,
                "unreported_calls": self.judge_unreported_calls,
            },
        }


def _count(usage: Mapping[str, Any] | None, key: str) -> int | None:
    if not isinstance(usage, Mapping):
        return None
    value = usage.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return int(value)


_METER: ContextVar[UsageMeter | None] = ContextVar("lgtm_usage_meter", default=None)
_STAGE: ContextVar[str] = ContextVar("lgtm_usage_stage", default=UNLABELLED)


@contextmanager
def metering() -> Iterator[UsageMeter]:
    """Collect usage for the calls made inside this block."""
    meter = UsageMeter()
    token = _METER.set(meter)
    try:
        yield meter
    finally:
        _METER.reset(token)


@contextmanager
def stage(name: str) -> Iterator[None]:
    """Label the model calls made inside this block."""
    token = _STAGE.set(name)
    try:
        yield
    finally:
        _STAGE.reset(token)


def current_summary() -> dict[str, Any] | None:
    """The open meter's summary, or None outside :func:`metering`."""
    meter = _METER.get()
    return meter.summary() if meter is not None else None


def record_fields(summary: Mapping[str, Any] | None) -> dict[str, Any]:
    """Flat per-case fields for benchmark records, from a :meth:`UsageMeter.summary`."""
    reviewer = (summary or {}).get("reviewer") or {}
    judge = (summary or {}).get("judge") or {}
    return {
        "llm_calls": reviewer.get("calls", 0),
        "input_tokens": reviewer.get("input_tokens", 0),
        "output_tokens": reviewer.get("output_tokens", 0),
        "total_tokens": reviewer.get("total_tokens", 0),
        "estimated_input_tokens": reviewer.get("estimated_input_tokens", 0),
        "llm_calls_without_usage": reviewer.get("unreported_calls", 0),
        "tokens_by_stage": reviewer.get("by_stage", {}),
        "judge_calls": judge.get("calls", 0),
        "judge_input_tokens": judge.get("input_tokens", 0),
    }


def summarize_records(records: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Median tokens per PR over the records that made model calls.

    Records with ``llm_calls`` missing or 0 (sast-only, crashes before any call)
    are left out. ``cases_with_unreported_calls`` counts records where some call
    returned no usage, so their totals are lower bounds.
    """
    import statistics

    rows = [r for r in records if (r.get("llm_calls") or 0) > 0]

    def median(key: str) -> float | None:
        values = [r.get(key) or 0 for r in rows]
        return round(statistics.median(values), 1) if values else None

    return {
        "cases_with_tokens": len(rows),
        "cases_with_unreported_calls": sum(1 for r in rows if r.get("llm_calls_without_usage")),
        "median_total_tokens_per_pr": median("total_tokens"),
        "median_input_tokens_per_pr": median("input_tokens"),
        "median_output_tokens_per_pr": median("output_tokens"),
        "median_estimated_input_tokens_per_pr": median("estimated_input_tokens"),
        "median_llm_calls_per_pr": median("llm_calls"),
        "median_judge_input_tokens_per_pr": median("judge_input_tokens"),
    }


def record_llm_response(response: Any, estimated_input: int = 0) -> None:
    meter = _METER.get()
    if meter is None:
        return
    meter.add_llm(_STAGE.get(), getattr(response, "usage_metadata", None), estimated_input)


def record_judge_reply(reply: Any) -> None:
    meter = _METER.get()
    if meter is None:
        return
    meter.add_judge(reply.get("input_tokens") if isinstance(reply, Mapping) else None)
