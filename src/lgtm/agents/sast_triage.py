"""SAST Triage Agent.

Takes a single Semgrep finding (SQL injection focus, CWE-89) plus the PR
diff context and decides whether it is a genuine vulnerability or a false
positive (e.g. the query is actually parameterized).
"""

from __future__ import annotations

import logging

from lgtm.agents import prompt_parts, registry
from lgtm.agents.base import AgentFinding, build_llm, parse_agent_output, run_tool_loop
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff
from lgtm.sast.semgrep_runner import SemgrepFinding

logger = logging.getLogger(__name__)


class SASTTriageAgent:
    def __init__(
        self,
        toolbox: AgentToolbox,
        config: LGTMConfig | None = None,
        llm=None,
    ):
        self.config = config or LGTMConfig()
        self.toolbox = toolbox
        self.llm = llm or build_llm(self.config)

    def triage(
        self,
        finding: SemgrepFinding,
        file_diff: FileDiff | None,
        facts: str = "",
    ) -> AgentFinding:
        """Triage one Semgrep finding; returns a structured AgentFinding."""
        self.toolbox.reset_budget()
        tools = self.toolbox.build_tools(graph=False)
        guidance = prompt_parts.tool_guidance(self.toolbox, graph=False)

        diff_text = file_diff.hunk_text() if file_diff else registry.entry("sast_triage.diff_unavailable")
        extra_context = ""
        if self.config.static_facts:
            if facts:
                extra_context += registry.render("sast_triage.static_facts", facts=facts)
            if self.toolbox.retriever is not None:
                try:
                    policy = self.toolbox.retriever.format_results(
                        registry.entry("sast_triage.policy_query")
                    )
                    extra_context += registry.render(
                        "sast_triage.policy_excerpts", policy=policy[:3000]
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Policy pre-retrieval failed: %s", exc)
        system = registry.render(
            "sast_triage.system_prompt",
            tool_section=prompt_parts.render_tool_section(guidance),
            max_tool_calls=guidance.max_tool_calls,
        )
        user = registry.render(
            "sast_triage.user_prompt",
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            severity=finding.severity,
            path=finding.path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            message=finding.message,
            matched_code=finding.matched_code[:1500],
            diff_text=diff_text[:6000],
            extra_context=extra_context,
            max_tool_calls=guidance.max_tool_calls,
        )

        logger.info("SAST triage: %s", finding.finding_id)
        try:
            raw = run_tool_loop(self.llm, tools, system, user, self.config)
        except Exception as exc:  # noqa: BLE001 - LLM/network failures must not kill the run
            logger.error("SAST triage agent failed for %s: %s", finding.finding_id, exc)
            result = AgentFinding(
                finding_id=finding.finding_id,
                verdict="insufficient_evidence",
                cwe_id="CWE-89",
                explanation=registry.render("sast_triage.failed_explanation", error=exc),
            )
        else:
            result = parse_agent_output(raw, finding.finding_id, default_cwe="CWE-89")

        result.category = "sqli"
        result.agent = "sast_triage"
        result.file = finding.path
        result.line = finding.start_line
        result.tool_calls_used = self.toolbox.calls_used
        return result
