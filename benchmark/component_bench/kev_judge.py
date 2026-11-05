"""Kev-4B judge component: verdict accuracy, and severity accuracy on gold-real candidates."""

from __future__ import annotations

from collections.abc import Mapping

from benchmark.component_bench.outcomes import InfraError, NotScored
from lgtm.agents.base import AgentFinding
from lgtm.validation.judge import JUDGE_STATE_MAX_CHARS, RequestTooLarge, build_judge_request

VERDICTS = ("real", "not_real")


def run_item(item, ctx):
    if item["gold"]["verdict"] == "undetermined":
        return NotScored("undetermined candidate")
    model = ctx.config.judge_model if ctx.config is not None else ""
    try:
        finding = AgentFinding(**item["gold_input"])
        request = build_judge_request(
            finding, lambda cited: cited.content, model=model, max_chars=JUDGE_STATE_MAX_CHARS
        )
        reply = ctx.judge(request)
    except RequestTooLarge as exc:
        raise InfraError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - any judge failure is an infra error, never a wrong answer
        raise InfraError(f"judge failed: {exc!r}") from exc
    if not isinstance(reply, Mapping) or reply.get("verdict") not in VERDICTS:
        raise InfraError(f"unusable judge reply: {reply!r}")
    return reply


def acceptable(gold, key):
    """Answers that count as correct: `gold.acceptable[key]`, else the single gold answer."""
    accepted = gold.get("acceptable", {}).get(key)
    if accepted:
        return set(accepted)
    return {gold[key]} if gold.get(key) else set()


def score(item, output):
    gold = item["gold"]
    real = gold["verdict"] == "real"
    verdicts = acceptable(gold, "verdict")
    correct = float(output["verdict"] in verdicts)
    if output["verdict"] == "real":
        severity = float(output.get("severity") in acceptable(gold, "severity"))
    else:
        # A defensible not_real answer leaves no severity to grade.
        severity = None if "not_real" in verdicts else 0.0
    return {
        "verdict_correct": correct,
        "real_verdict_correct": correct if real else None,
        "not_real_verdict_correct": None if real else correct,
        "severity_correct": severity if real else None,
    }
