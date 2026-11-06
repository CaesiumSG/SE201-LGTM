"""Cost-metrics capture: token usage and tool-call counts per unit."""

from __future__ import annotations

from lgtm.agents.base import validate_tool_call

NOT_RECORDED = "not recorded"


def total(values) -> int | None:
    recorded = [v for v in values if v is not None]
    return sum(recorded) if recorded else None


class Metrics:
    def __init__(self):
        self.input: list = []
        self.output: list = []
        self.tools: dict[str, dict[str, dict[str, int]]] = {}

    def record(self, input_tokens, output_tokens) -> None:
        self.input.append(input_tokens)
        self.output.append(output_tokens)

    def add_agent(self, agent_name: str, run_records, offered_tools) -> None:
        offered = {getattr(t, "name", t): t for t in offered_tools}
        stats = self.tools.setdefault(agent_name, {})
        for name in offered:
            stats.setdefault(name, {"calls": 0, "invalid": 0})
        for record in run_records:
            for call in (c for turn in record.turns for c in turn.get("tool_calls", [])):
                entry = stats.setdefault(call["tool"], {"calls": 0, "invalid": 0})
                entry["calls"] += 1
                if validate_tool_call(call["tool"], offered, call["args"]) is not None:
                    entry["invalid"] += 1


class RecordingLLM:
    """Proxy that records usage_metadata of each reply; other attributes pass through."""

    def __init__(self, llm, metrics: Metrics):
        self._llm, self._metrics = llm, metrics

    def invoke(self, *args, **kwargs):
        reply = self._llm.invoke(*args, **kwargs)
        usage = getattr(reply, "usage_metadata", None) or {}
        self._metrics.record(usage.get("input_tokens"), usage.get("output_tokens"))
        return reply

    def bind_tools(self, *args, **kwargs):
        return RecordingLLM(self._llm.bind_tools(*args, **kwargs), self._metrics)

    def model_copy(self, *args, **kwargs):
        return RecordingLLM(self._llm.model_copy(*args, **kwargs), self._metrics)

    def __getattr__(self, name):
        return getattr(self._llm, name)


def recording_judge(judge, metrics: Metrics):
    def call(request):
        reply = judge(request)
        metrics.record(reply.get("input_tokens"), None)
        return reply

    return call
