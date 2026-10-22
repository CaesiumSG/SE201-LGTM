"""Kev-4B judge: builds the request for a candidate, calls the endpoint, records the answer.

A candidate the judge fails on stays not judged (``judged`` false, no verdict,
severity or provenance confidence); the review continues.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.config import LGTMConfig

logger = logging.getLogger(__name__)

SYSTEM_ONE_PATH = "/v1/systemone"
JUDGE_STATE_MAX_CHARS = 100_000
JUDGE_REPLY_MAX_BYTES = 1_000_000
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")

VERDICTS = {
    "vulnerable": "The cited code has the described flaw and an attacker can reach it.",
    "possible": "The described flaw is plausible but the evidence does not confirm it.",
    "safe": "The cited code does not have the described flaw.",
    "insufficient_evidence": "The evidence is too thin or wrong to decide.",
}
SEVERITIES = ("low", "medium", "high", "critical")  # ordered, as the score question's levels
QUESTION_VERDICT = "verdict"
QUESTION_SEVERITY = "severity"
QUESTION_CONFIDENCE = "provenance_confidence"

JudgeCall = Callable[[dict], Mapping[str, Any]]


def _questions() -> dict[str, dict]:
    return {
        QUESTION_VERDICT: {
            "type": "choice",
            "instructions": "Judge whether the claimed security flaw is real, given the cited code.",
            "criteria": VERDICTS,
        },
        QUESTION_SEVERITY: {
            "type": "score",
            "instructions": "Rate the severity of the claimed flaw if it is real.",
            "criteria": list(SEVERITIES),
        },
        QUESTION_CONFIDENCE: {
            "type": "noul",
            "instructions": "Does the cited code actually support the claim and its citations?",
        },
    }


def _yes_no(value: bool | None) -> str:
    return "unknown" if value is None else "yes" if value else "no"


def _location(item: EvidenceItem) -> str:
    if item.type == "policy":
        return f"policy {item.source}"
    where = item.file or "(no file)"
    if item.lines:
        where += f":{item.lines[0]}-{item.lines[-1]}"
    return f"{where} at {item.snapshot or 'unlabelled'} snapshot"


def build_judge_request(
    finding: AgentFinding,
    read_code: Callable[[EvidenceItem], str],
    *,
    model: str,
    max_chars: int,
) -> dict:
    """Judge request for one candidate; code is dropped first when the state exceeds ``max_chars``."""
    head = [
        f"Claim: {finding.explanation}",
        f"CWE: {finding.cwe_id}",
        f"Category: {finding.category}",
        f"Location: {finding.file}:{finding.line}",
    ]
    if finding.semgrep_rule_id or finding.semgrep_message:
        head.append(
            f"Semgrep: rule {finding.semgrep_rule_id}, severity {finding.semgrep_severity}, "
            f"message {finding.semgrep_message}"
        )
    head.append(f"Grounding check passed: {_yes_no(finding.evidence_valid)}")
    head.extend(f"Grounding issue: {issue}" for issue in finding.evidence_issues)

    blocks: list[tuple[str, str]] = []
    for item in finding.evidence:
        label = f"Cited item: {_location(item)}"
        if item.type == "policy":
            blocks.append((f"{label}\n{item.content}", ""))
        else:
            label += f"; grounded in PR: {_yes_no(item.grounded_in_pr)}"
            blocks.append((label, read_code(item)))

    budget = max_chars - len("\n".join(head)) - sum(len(b) + 2 for b, _ in blocks)
    parts = list(head)
    for text, code in blocks:
        code = code[: max(budget, 0)]
        budget -= len(code) + 1
        parts.append(f"{text}\n{code}" if code else text)
    return {"model": model, "state": "\n".join(parts)[:max_chars], "questions": _questions()}


def apply_judge_answer(finding: AgentFinding, answer: Mapping[str, Any]) -> None:
    """Record a judge answer, or raise ValueError and change nothing when it is invalid."""
    verdict = answer.get("verdict")
    severity = answer.get("severity")
    confidence = answer.get("provenance_confidence")
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict: {verdict!r}")
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity: {severity!r}")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError(f"provenance confidence outside 0 to 1: {confidence!r}")

    ungrounded = not any(item.grounded_in_pr is True for item in finding.evidence)
    if verdict == "vulnerable" and finding.pr_graph_ok is False and ungrounded:
        verdict = "possible"
    finding.verdict = verdict
    finding.severity = severity if verdict in ("vulnerable", "possible") else ""
    finding.provenance_confidence = confidence
    finding.judged = True


def _parse_kev_reply(reply: Any) -> dict[str, Any]:
    """The one place that reads Kev answer fields."""
    answers = reply["answers"]
    level = answers[QUESTION_SEVERITY]["mean_level"]
    if not 0 <= level <= len(SEVERITIES) - 1:
        raise ValueError(f"severity level outside the scale: {level!r}")
    return {
        "verdict": answers[QUESTION_VERDICT]["choice"],
        "severity": SEVERITIES[round(level)],
        "provenance_confidence": answers[QUESTION_CONFIDENCE]["probability"],
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def http_judge(config: LGTMConfig) -> JudgeCall:
    """Judge call over HTTP to ``config.judge_endpoint``; raises on any failure."""
    url = config.judge_endpoint.rstrip("/") + SYSTEM_ONE_PATH
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def call(request: dict) -> Mapping[str, Any]:
        target = urllib.parse.urlsplit(url)
        if target.scheme != "http" or target.hostname not in LOOPBACK_HOSTS:
            raise ValueError("judge endpoint must be http on a loopback host")
        http_request = urllib.request.Request(
            url,
            data=json.dumps(request).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(http_request, timeout=config.judge_timeout) as response:
            body = response.read(JUDGE_REPLY_MAX_BYTES + 1)
        if len(body) > JUDGE_REPLY_MAX_BYTES:
            raise ValueError("judge reply exceeds the size limit")
        return _parse_kev_reply(json.loads(body))

    return call


def judge_candidates(
    findings: list[AgentFinding],
    read_code: Callable[[EvidenceItem], str],
    config: LGTMConfig,
    judge: JudgeCall | None = None,
) -> list[AgentFinding]:
    """Judge each candidate in place; a failed call leaves only that candidate not judged."""
    judge = judge or http_judge(config)
    for finding in findings:
        finding.verdict = ""
        finding.severity = ""
        finding.provenance_confidence = None
        finding.judged = False
        try:
            request = build_judge_request(
                finding, read_code, model=config.judge_model, max_chars=JUDGE_STATE_MAX_CHARS
            )
            apply_judge_answer(finding, judge(request))
        except Exception as exc:  # noqa: BLE001 - any judge failure leaves the candidate not judged
            logger.warning("Judge failed for %s: %s", finding.finding_id, exc)
    return findings
