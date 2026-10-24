"""Authorization Reviewer Agent.

Examines changed code sections against the repository's documented security
policy to detect authorization flaws:
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from lgtm.agents import prompt_parts, registry
from lgtm.agents.base import (
    AgentFinding,
    build_llm,
    extract_json_object,
    parse_agent_output,
    run_tool_loop,
)
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig

if TYPE_CHECKING:
    # Circular import: lgtm.review.sections imports lgtm.agents.base.
    from lgtm.review.sections import ContextPointer, Section

logger = logging.getLogger(__name__)

POLICY_EXCERPT_CHARS = 5000
_MAX_LINE = 2**31 - 1

ROLE_GUIDANCE = registry.entry("authz_reviewer.role_guidance")


def _semgrep_block(notes: str) -> str:
    if not notes:
        return ""
    escaped = "\n".join(prompt_parts.escape_control(note) for note in notes.split("\n"))
    return registry.render("authz_reviewer.related_sast", notes=escaped)


def _sibling_notice(section: Section) -> str:
    if section.part_count <= 1:
        return ""
    return registry.render(
        "authz_reviewer.sibling_notice",
        part=section.part_index + 1,
        count=section.part_count,
    )


def _context_block(pointers: list[ContextPointer]) -> str:
    if not pointers:
        return ""
    lines = [
        registry.render(
            "authz_reviewer.context_line",
            path=prompt_parts.escape_control(p.path),
            start_line=p.start_line,
            end_line=p.end_line,
            snapshot=p.snapshot,
            symbol=prompt_parts.escape_control(p.symbol),
            why=prompt_parts.escape_control(p.why),
        )
        for p in pointers
    ]
    return registry.render("authz_reviewer.context_block", lines="\n".join(lines))


def _changed_span(section: Section) -> tuple[int, int]:
    changes = [c for h in section.hunks for c in h.changes]
    lines = [c.new_lineno for c in changes if c.kind == "add" and c.new_lineno]
    if not lines:
        lines = [c.old_lineno for c in changes if c.kind == "del" and c.old_lineno]
    return (min(lines), max(lines)) if lines else (0, 0)


def _fallback_line(section: Section) -> int:
    if not section.hunks:
        return 0
    first = section.hunks[0]
    kinds = {c.kind for c in first.changes}
    deletion_only = "del" in kinds and "add" not in kinds
    return first.old_start if deletion_only else first.new_start


def _valid_line(value: object) -> int | None:
    try:
        line = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return line if 0 < line <= _MAX_LINE else None


def failed_finding_id(section_id: str) -> str:
    return f"authz:{section_id}:failed"


def _section_items(raw: str) -> list[dict] | None:
    data = extract_json_object(raw)
    findings = data.get("findings") if data else None
    if not isinstance(findings, list):
        return None
    items = [item for item in findings if isinstance(item, dict)]
    return items if items or not findings else None


def _failure(finding_id: str, explanation: str) -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id,
        verdict="insufficient_evidence",
        cwe_id="CWE-862",
        explanation=explanation,
    )


class AuthzReviewerAgent:
    def __init__(
        self,
        toolbox: AgentToolbox,
        config: LGTMConfig | None = None,
        llm=None,
    ):
        self.config = config or LGTMConfig()
        self.toolbox = toolbox
        self.llm = llm or build_llm(self.config)

    def review_section(
        self, section: Section, semgrep_notes: str = ""
    ) -> list[AgentFinding]:
        from lgtm.review.sections import render_section

        self.toolbox.reset_budget()
        tools = self.toolbox.build_tools()
        tool_info = prompt_parts.tool_guidance(self.toolbox)
        policy_context = self._policy_context(
            registry.render(
                "authz_reviewer.policy_query",
                title=section.title,
                files=" ".join(section.files),
            )
        )
        system = registry.render(
            "authz_reviewer.system_prompt",
            tool_section=prompt_parts.render_tool_section(tool_info),
            max_tool_calls=tool_info.max_tool_calls,
        )
        section_body = registry.render(
            "authz_reviewer.section_body",
            section_id=prompt_parts.escape_control(section.section_id),
            title=prompt_parts.escape_control(section.title),
            rationale=prompt_parts.escape_control(
                section.rationale or registry.entry("authz_reviewer.rationale_none")
            ),
            files=prompt_parts.escape_control(", ".join(section.files)),
            context_block=_context_block(section.context),
            semgrep_context=_semgrep_block(semgrep_notes),
            section_text=render_section(section),
        )
        user = registry.render(
            "authz_reviewer.user_prompt",
            untrusted=prompt_parts.untrusted_block(
                section_body, registry.entry("authz_reviewer.untrusted_label")
            ),
            sibling_notice=_sibling_notice(section),
            policy_context=policy_context[:POLICY_EXCERPT_CHARS],
            guidance=ROLE_GUIDANCE if self.config.authz_role_guidance else "",
            max_tool_calls=tool_info.max_tool_calls,
        )

        first_file = section.files[0] if section.files else ""
        fallback_line = _fallback_line(section)
        first_line, last_line = _changed_span(section)
        where = registry.render(
            "authz_reviewer.location",
            files=", ".join(section.files),
            first_line=first_line,
            last_line=last_line,
        )
        failed_id = failed_finding_id(section.section_id)
        unparsable = _failure(
            failed_id, registry.render("authz_reviewer.unparsable_explanation", where=where)
        )

        logger.info("Authz section review: %s", section.section_id)
        try:
            raw = run_tool_loop(self.llm, tools, system, user, self.config)
        except Exception as exc:  # noqa: BLE001
            logger.error("Authz section review failed for %s: %s", section.section_id, exc)
            failure = _failure(
                failed_id, registry.render("authz_reviewer.failed_explanation", where=where, error=exc)
            )
            return [self._stamp(failure, first_file, fallback_line)]

        items = _section_items(raw)
        if items is None:
            logger.warning("Authz section review for %s had no parsable findings", section.section_id)
            return [self._stamp(unparsable, first_file, fallback_line)]

        findings: list[AgentFinding] = []
        for n, item in enumerate(items, 1):
            finding_id = f"authz:{section.section_id}:{n}"
            try:
                finding = parse_agent_output(json.dumps(item), finding_id, default_cwe="CWE-862")
            except (TypeError, ValueError, OverflowError):
                return [self._stamp(unparsable, first_file, fallback_line)]
            finding.finding_id = finding_id
            findings.append(
                self._stamp(
                    finding,
                    str(item.get("file") or "") or first_file,
                    _valid_line(item.get("line")) or fallback_line,
                )
            )
        return findings

    def _policy_context(self, query: str) -> str:
        if self.toolbox.retriever is None:
            return registry.entry("authz_reviewer.policy_unavailable")
        try:
            return self.toolbox.retriever.format_results(query)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Policy pre-retrieval failed: %s", exc)
            return registry.entry("authz_reviewer.policy_unavailable")

    def _stamp(self, finding: AgentFinding, file: str, line: int) -> AgentFinding:
        finding.category = "authz"
        finding.agent = "authz_reviewer"
        finding.file = file
        finding.line = line
        finding.tool_calls_used = self.toolbox.calls_used
        return finding
