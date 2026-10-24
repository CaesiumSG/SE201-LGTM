"""Kev-4B judge: builds the request for a candidate, calls the endpoint, records the answer.

A candidate the judge fails on stays not judged (``judged`` false, no support
answer or provenance confidence, a ``not_judged_reason``); the review continues.
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
from lgtm.validation.cwe_criteria import CWE_CRITERIA
from lgtm.validation.judge_examples import EXAMPLES

logger = logging.getLogger(__name__)

SYSTEM_ONE_PATH = "/v1/systemone"
JUDGE_STATE_MAX_CHARS = 28_000
JUDGE_REPLY_MAX_BYTES = 1_000_000
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")

REASON_REQUEST_TOO_LARGE = "request-too-large"
REASON_JUDGE_FAILED = "judge-failed"
REASON_NO_CITED_SOURCE = "no-cited-source"

SUPPORT_ANSWERS = {
    "yes": "The cited code supports the claimed security flaw.",
    "no": "The cited code does not support the claimed security flaw.",
}
QUESTION_SUPPORT = "supported"
QUESTION_CONFIDENCE = "provenance_confidence"
QUESTION_VERDICT = "verdict"
QUESTION_SEVERITY = "severity"

VERDICT_ANSWERS = {
    "real": "The cited code contains a real vulnerability of the claimed kind.",
    "not_real": "The cited code does not contain a real vulnerability of the claimed kind.",
}
SEVERITY_LEVELS = ("low", "medium", "high", "critical")
SEVERITY_DESCRIPTIONS = {
    "low": "Limited impact, hard to exploit or exposing little.",
    "medium": "Moderate impact or needs specific conditions to exploit.",
    "high": "Serious impact, exploitable with little effort.",
    "critical": "Severe impact, exploitable by anyone with no prerequisites.",
}

JudgeCall = Callable[[dict], Mapping[str, Any]]


class RequestTooLarge(ValueError):
    """The judge request state exceeds the bound."""


REQUEST_FORMATS = ("current", "short_claim", "code_first", "code_only")
SHORT_CLAIM_MAX_CHARS = 200


def _check_format(request_format: str) -> None:
    if request_format not in REQUEST_FORMATS:
        raise ValueError(
            f"unknown request format {request_format!r}; valid formats: {', '.join(REQUEST_FORMATS)}"
        )


def _neutral_questions(subject: str) -> dict[str, dict]:
    return {
        QUESTION_SUPPORT: {
            "type": "choice",
            "instructions": f"Looking only at the cited code, does it contain {subject}?",
            "criteria": {
                "yes": f"The cited code contains {subject}.",
                "no": f"The cited code does not contain {subject}.",
            },
        },
        QUESTION_CONFIDENCE: {
            "type": "noul",
            "instructions": "How confident are you in this answer about the cited code?",
        },
    }


def _questions(few_shot: bool) -> dict[str, dict]:
    questions = {
        QUESTION_SUPPORT: {
            "type": "choice",
            "instructions": "Does the cited code support the claimed security flaw?",
            "criteria": SUPPORT_ANSWERS,
        },
        QUESTION_VERDICT: {
            "type": "choice",
            "instructions": "Is the claimed security flaw a real vulnerability in the cited code?",
            "criteria": VERDICT_ANSWERS,
        },
        QUESTION_SEVERITY: {
            "type": "choice",
            "instructions": "If the claimed flaw is real, how severe is it?",
            "criteria": {level: SEVERITY_DESCRIPTIONS[level] for level in SEVERITY_LEVELS},
        },
        QUESTION_CONFIDENCE: {
            "type": "noul",
            "instructions": "Does the cited code actually support the claim and its citations?",
        },
    }
    if few_shot:
        for qid, question in questions.items():
            question["instructions"] += "\n\n" + EXAMPLES[qid]
    return questions


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
    request_format: str = "current",
    few_shot: bool = True,
) -> dict:
    """Judge request for one candidate; raises RequestTooLarge when the state plus every question's
    instructions exceed ``max_chars`` and ValueError for an unknown ``request_format``.

    ``few_shot`` adds worked examples to the instructions of the current format's questions."""
    _check_format(request_format)
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

    cited = []
    for item in finding.evidence:
        label = f"Cited item: {_location(item)}"
        if item.type == "policy":
            cited.append(f"{label}\n{item.content}")
            continue
        try:
            code = read_code(item)
        except Exception as exc:  # noqa: BLE001 - an unreadable item is left out, the rest is still judged
            logger.warning("Cited code unreadable for %s: %s", finding.finding_id, exc)
            code = ""
        cited.append(f"{label}\n{code}" if code else label)

    if request_format == "current":
        parts = head + cited
        questions = _questions(few_shot)
    elif request_format == "code_only":
        parts = cited
        questions = _neutral_questions("a security flaw")
    else:
        criteria = CWE_CRITERIA.get(str(finding.cwe_id).strip().upper())
        weakness = [f"Weakness: {finding.cwe_id}"] + ([f"Criteria: {criteria}"] if criteria else [])
        if request_format == "short_claim":
            first_line = (finding.explanation.strip().splitlines() or [""])[0]
            claim = f"Claim: {first_line[:SHORT_CLAIM_MAX_CHARS]}"
        else:
            claim = f"Claim to check (it may be wrong): {finding.explanation}"
        parts = cited + weakness + [claim]
        questions = _neutral_questions("the weakness named under Weakness")
    state = "\n".join(parts)
    size = len(state) + sum(len(q.get("instructions", "")) for q in questions.values())
    if size > max_chars:
        raise RequestTooLarge(f"judge request is {size} characters, bound {max_chars}")
    return {"model": model, "state": state, "questions": questions}


def apply_judge_answer(finding: AgentFinding, answer: Mapping[str, Any]) -> None:
    """Record a judge answer, or raise ValueError and change nothing when it is invalid."""
    supported = answer.get(QUESTION_SUPPORT)
    confidence = answer.get(QUESTION_CONFIDENCE)
    if not isinstance(supported, str) or supported not in SUPPORT_ANSWERS:
        raise ValueError(f"unknown support answer: {supported!r}")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError(f"provenance confidence outside 0 to 1: {confidence!r}")
    verdict = answer.get(QUESTION_VERDICT)
    severity = answer.get(QUESTION_SEVERITY)
    if not isinstance(verdict, str) or not verdict:
        raise ValueError(f"missing verdict answer: {verdict!r}")
    if not isinstance(severity, str) or not severity:
        raise ValueError(f"missing severity answer: {severity!r}")

    finding.supported = supported == "yes"
    finding.provenance_confidence = confidence
    finding.kev_verdict = verdict
    finding.kev_severity = severity
    finding.judged = True


def parse_kev_reply(reply: Any) -> dict[str, Any]:
    """The one place that reads Kev answer fields; raises ValueError when an answer is missing."""
    try:
        answers = reply["answers"]
        parsed = {
            QUESTION_SUPPORT: answers[QUESTION_SUPPORT]["choice"],
            QUESTION_VERDICT: answers[QUESTION_VERDICT]["choice"],
            QUESTION_SEVERITY: answers[QUESTION_SEVERITY]["choice"],
            QUESTION_CONFIDENCE: answers[QUESTION_CONFIDENCE]["noul"],
        }
        parsed["input_tokens"] = (reply.get("usage") or {}).get("input_tokens")
    except (KeyError, TypeError) as exc:
        raise ValueError(f"judge reply lacks an answer: {exc!r}") from exc
    return parsed


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
        return parse_kev_reply(json.loads(body))

    return call


def judge_candidates(
    findings: list[AgentFinding],
    read_code: Callable[[EvidenceItem], str],
    config: LGTMConfig,
    judge: JudgeCall | None = None,
    *,
    request_format: str = "current",
    few_shot: bool = True,
) -> list[AgentFinding]:
    """Judge each candidate in place; a failed call leaves only that candidate not judged.

    An unknown ``request_format`` raises ValueError before any candidate is touched."""
    _check_format(request_format)
    judge = judge or http_judge(config)
    for finding in findings:
        finding.supported = None
        finding.provenance_confidence = None
        finding.kev_verdict = None
        finding.kev_severity = None
        finding.judged = False
        finding.not_judged_reason = ""
        finding.unsupported_reason = ""
        if not finding.evidence:
            finding.supported = False
            finding.judged = True
            finding.unsupported_reason = REASON_NO_CITED_SOURCE
            continue
        try:
            request = build_judge_request(
                finding,
                read_code,
                model=config.judge_model,
                max_chars=JUDGE_STATE_MAX_CHARS,
                request_format=request_format,
                few_shot=few_shot,
            )
            apply_judge_answer(finding, judge(request))
        except RequestTooLarge as exc:
            logger.warning("Judge skipped for %s: %s", finding.finding_id, exc)
            finding.not_judged_reason = REASON_REQUEST_TOO_LARGE
        except Exception as exc:  # noqa: BLE001 - any judge failure leaves the candidate not judged
            logger.warning("Judge failed for %s: %s", finding.finding_id, exc)
            finding.not_judged_reason = REASON_JUDGE_FAILED
    return findings
