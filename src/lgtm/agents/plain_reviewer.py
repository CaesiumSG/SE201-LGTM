"""Plain LLM reviewer — the proposal's "LLM only" baseline (Baseline B).

The model sees the same PR diff as LGTM but gets NO Semgrep output, NO
documentation retrieval (RAG), and NO tools. One call per PR returns one
assessment per task (SQL injection and authorization). It exists only to
measure what SAST seeding, policy retrieval, and tool use add on top of a
bare LLM.
"""

from __future__ import annotations

import json
import logging

from lgtm.agents import registry
from lgtm.agents.base import (
    AgentFinding,
    build_llm,
    extract_json_object,
    invoke_with_retry,
    message_text,
    parse_agent_output,
    request_valid_answer,
)
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff

logger = logging.getLogger(__name__)

DEFAULT_CWE = {"sqli": "CWE-89", "authz": "CWE-862"}


def _category_for(item: dict) -> str:
    category = str(item.get("category", "")).strip().lower()
    if category in DEFAULT_CWE:
        return category
    return "sqli" if "89" in str(item.get("cwe_id", "")) else "authz"


class PlainLLMReviewer:
    def __init__(self, config: LGTMConfig | None = None, llm=None):
        self.config = config or LGTMConfig()
        self.llm = llm or build_llm(self.config)

    def review(self, diffs: list[FileDiff]) -> list[AgentFinding]:
        """Review the whole PR in a single tool-free LLM call."""
        from langchain_core.messages import HumanMessage, SystemMessage

        diff_text = "\n\n".join(
            registry.render("plain_reviewer.diff_entry", path=d.path, diff=d.hunk_text())
            for d in diffs
            if d.path.endswith(".py")
        )
        if not diff_text:
            return []
        messages = [
            SystemMessage(content=registry.entry("plain_reviewer.system_prompt")),
            HumanMessage(
                content=registry.render("plain_reviewer.user_prompt", diff_text=diff_text[:12000])
            ),
        ]

        logger.info("Plain LLM review of %d file(s)", len(diffs))
        try:
            response = invoke_with_retry(self.llm, messages, self.config)
            messages.append(response)
            raw = request_valid_answer(
                self.llm, messages, message_text(response), self.config, self._is_parsable
            )
        except Exception as exc:  # noqa: BLE001 - LLM failures must not kill the run
            logger.error("Plain LLM review failed: %s", exc)
            return [
                AgentFinding(
                    finding_id=f"plain:{cat}",
                    verdict="insufficient_evidence",
                    cwe_id=cwe,
                    category=cat,
                    agent="plain_llm",
                    explanation=registry.render("plain_reviewer.failed_explanation", error=exc),
                )
                for cat, cwe in DEFAULT_CWE.items()
            ]
        return self._parse(raw)

    @staticmethod
    def _assessment_items(raw: str) -> list:
        data = extract_json_object(raw)
        if data is None:
            items: list = []
        elif isinstance(data.get("assessments"), list):
            items = data["assessments"]
        else:
            items = [data]  # model answered with a single bare assessment
        return items

    @staticmethod
    def _is_parsable(raw: str) -> bool:
        return any(isinstance(i, dict) for i in PlainLLMReviewer._assessment_items(raw))

    @staticmethod
    def _parse(raw: str) -> list[AgentFinding]:
        items = PlainLLMReviewer._assessment_items(raw)

        findings: list[AgentFinding] = []
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            category = _category_for(item)
            finding = parse_agent_output(
                json.dumps(item), f"plain:{category}:{i}", DEFAULT_CWE[category]
            )
            finding.raw_response = raw[:2000]
            finding.category = category
            finding.agent = "plain_llm"
            finding.file = str(item.get("file") or "")
            try:
                finding.line = int(item.get("line") or 0)
            except (TypeError, ValueError):
                finding.line = 0
            findings.append(finding)

        if not findings:
            logger.warning("Plain LLM review produced no parsable assessments")
            findings.append(
                AgentFinding(
                    finding_id="plain:unparsable",
                    verdict="insufficient_evidence",
                    agent="plain_llm",
                    explanation=registry.entry("plain_reviewer.unparsable_explanation"),
                    raw_response=raw[:2000],
                )
            )
        return findings
