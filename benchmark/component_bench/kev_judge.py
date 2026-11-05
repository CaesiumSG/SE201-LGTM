"""Kev-4B judge component: verdict accuracy, and severity accuracy on gold-real candidates."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

from benchmark.component_bench.outcomes import InfraError, NotScored
from benchmark.component_bench.schema import load_cases
from benchmark.real_world.fetch import branch, project_of
from lgtm.agents.authz_reviewer import _enclosing_functions
from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.validation.judge import JUDGE_STATE_MAX_CHARS, RequestTooLarge, build_judge_request

VERDICTS = ("real", "not_real")
ANSWERS = ("supported", "verdict", "severity", "provenance_confidence")
CLONE_CACHE = Path(__file__).resolve().parents[1] / "real_world" / ".cache"


def enclosing_views(case_id: str, cited: EvidenceItem) -> list[str]:
    """Views of a cited item, largest first: its enclosing function with decorators, that function cut
    after the cited lines, then the quote. Only the quote when the case clone or function is unavailable."""
    if not cited.lines:
        return [cited.content]
    try:
        case = next(c for c in load_cases() if c["id"] == case_id)
        role = "base" if cited.snapshot == "base" else "pr"
        source = subprocess.run(
            ["git", "show", f"refs/heads/{branch(case_id, role)}:{cited.file}"],
            cwd=CLONE_CACHE / project_of(case), capture_output=True, encoding="utf-8", check=True,
        ).stdout
    except (StopIteration, OSError, subprocess.CalledProcessError, UnicodeDecodeError):
        return [cited.content]
    spans = _enclosing_functions(source, list(range(cited.lines[0], cited.lines[-1] + 1)))
    if not spans:
        return [cited.content]
    lines = source.splitlines()
    start, end = spans[0][0], max(s[1] for s in spans)
    return [
        "\n".join(lines[start - 1 : end]),
        "\n".join(lines[start - 1 : max(cited.lines[-1], start)]),
        cited.content,
    ]


def _fitted_request(finding: AgentFinding, views: dict[int, list[str]], model: str) -> dict:
    """The request with the largest views that fit the bound; raises RequestTooLarge when the quotes alone do not."""
    def build(step: int) -> dict:
        return build_judge_request(
            finding,
            lambda cited: views[id(cited)][min(step, len(views[id(cited)]) - 1)],
            model=model,
            max_chars=JUDGE_STATE_MAX_CHARS,
        )

    for step in (0, 1):
        try:
            return build(step)
        except RequestTooLarge:
            pass
    return build(2)


def run_item(item, ctx):
    if item["gold"]["verdict"] == "undetermined":
        return NotScored("undetermined candidate")
    model = ctx.config.judge_model if ctx.config is not None else ""
    try:
        finding = AgentFinding(**item["gold_input"])
        views = {id(cited): enclosing_views(item["case_id"], cited) for cited in finding.evidence}
        request = _fitted_request(finding, views, model)
        reply = ctx.judge(request)
    except RequestTooLarge as exc:
        raise InfraError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - any judge failure is an infra error, never a wrong answer
        raise InfraError(f"judge failed: {exc!r}") from exc
    if not isinstance(reply, Mapping) or reply.get("verdict") not in VERDICTS:
        raise InfraError(f"unusable judge reply: {reply!r}")
    return {**reply, "detail": {"kev": {key: reply.get(key) for key in ANSWERS}}}


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
