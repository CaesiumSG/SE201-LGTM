"""Authorization Reviewer Agent.

Examines changed code sections against the repository's documented security
policy to detect authorization flaws:
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
"""

from __future__ import annotations

import ast
import json
import logging
from typing import TYPE_CHECKING

from lgtm.agents import prompt_parts, registry
from lgtm.agents.base import (
    AgentFinding,
    RunRecord,
    answer_until_resolved,
    build_llm,
    extract_json_object,
    fill_record,
    parse_agent_output,
    run_tool_loop,
)
from lgtm.agents.tools import AgentToolbox, read_committed_blob, relative_path
from lgtm.config import LGTMConfig

if TYPE_CHECKING:
    # Circular import: lgtm.review.sections imports lgtm.agents.base.
    from lgtm.review.sections import ContextPointer, HunkRef, Section

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


def _hunk_lines(hunk: HunkRef) -> list[tuple[str, list[int]]]:
    """Changed line numbers per snapshot: added lines in the PR, removed lines in the base."""
    added = [c.new_lineno for c in hunk.changes if c.kind == "add" and c.new_lineno]
    removed = [c.old_lineno for c in hunk.changes if c.kind == "del" and c.old_lineno]
    return [("pr", added), ("base", removed)]


def _enclosing_functions(source: str, lines: list[int]) -> list[tuple[int, int, str]]:
    """Innermost function (start, end, qualified name such as "A.get") around each line, in source order."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    spans: list[tuple[int, int, str]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualified = f"{prefix}{child.name}"
                if not isinstance(child, ast.ClassDef):
                    start = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                    spans.append((start, child.end_lineno or child.lineno, qualified))
                visit(child, f"{qualified}.")
            else:
                visit(child, prefix)

    visit(tree, "")
    found: set[tuple[int, int, str]] = set()
    for line in lines:
        inside = [s for s in spans if s[0] <= line <= s[1]]
        if inside:
            found.add(max(inside, key=lambda s: s[0]))
    return sorted(found)


def _strip_comments(code: str, path: str) -> str:
    from lgtm.diff.git_diff import FileDiff, Hunk, LineChange
    from lgtm.diff.sanitizer import sanitize_file_diff

    hunk = Hunk(1, 0, 1, 0, changes=[LineChange("add", text) for text in code.split("\n")])
    return "\n".join(c.content for c in sanitize_file_diff(FileDiff(path, hunks=[hunk])).hunks[0].changes)


def _enclosing_block(toolbox: AgentToolbox, section: Section) -> str:
    found: list[tuple[str, str, str, int, int, str, str]] = []
    seen: set[tuple[str, str, int]] = set()
    cap = toolbox.config.read_file_max_lines
    for hunk in section.hunks:
        rel = relative_path(hunk.file)
        if rel is None or not hunk.file.endswith(".py"):
            continue
        for label, lines in _hunk_lines(hunk):
            if not lines or (toolbox.shas is None and label == "pr"):
                continue
            try:
                sha = toolbox._snapshot_sha(label)
            except KeyError:
                continue
            if sha is None:
                continue
            done = read_committed_blob(toolbox.repo, sha, rel, toolbox.config.git_timeout)
            if done is None or done.returncode != 0:
                continue
            source_lines = done.stdout.splitlines()
            for start, end, name in _enclosing_functions(done.stdout, lines):
                if (label, rel, start) in seen:
                    continue
                seen.add((label, rel, start))
                code = "\n".join(source_lines[start - 1 : min(end, start + cap - 1)])
                found.append((label, rel, hunk.file, start, end, name, code))
    pr_names = {(rel, name) for label, rel, _, _, _, name, _ in found if label == "pr"}
    items = [
        registry.render(
            "authz_reviewer.enclosing_item",
            file=prompt_parts.escape_control(file),
            start=start,
            end=end,
            snapshot=label,
            code=prompt_parts.code_fence(
                _strip_comments(code, file) if toolbox.config.strip_comments else code, "python"
            ),
        )
        for label, rel, file, start, end, name, code in found
        if label == "pr" or (rel, name) not in pr_names
    ]
    if not items:
        return ""
    return registry.render("authz_reviewer.enclosing_block", items="\n".join(items))


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


def _section_items(raw: str) -> list[dict] | None:
    data = extract_json_object(raw)
    findings = data.get("findings") if data else None
    if not isinstance(findings, list):
        return None
    items = [item for item in findings if isinstance(item, dict)]
    return items if items or not findings else None


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
        self.errors: list[dict[str, str]] = []
        self.run_records: list[RunRecord] = []

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
            enclosing_block=_enclosing_block(self.toolbox, section),
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

        def parse(raw: str) -> list[AgentFinding] | None:
            items = _section_items(raw)
            if items is None:
                return None
            findings: list[AgentFinding] = []
            for n, item in enumerate(items, 1):
                finding_id = f"authz:{section.section_id}:{n}"
                try:
                    finding = parse_agent_output(json.dumps(item), finding_id, default_cwe="CWE-862")
                except (TypeError, ValueError, OverflowError):
                    return None
                finding.finding_id = finding_id
                findings.append(
                    self._stamp(
                        finding,
                        str(item.get("file") or "") or first_file,
                        _valid_line(item.get("line")) or fallback_line,
                    )
                )
            return findings

        logger.info("Authz section review: %s", section.section_id)
        record = RunRecord(section.section_id)
        self.run_records.append(record)
        try:
            findings = answer_until_resolved(
                lambda: fill_record(
                    record,
                    self.toolbox,
                    run_tool_loop(self.llm, tools, system, user, self.config),
                ),
                parse,
                self.toolbox,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Authz section review failed for %s: %s", section.section_id, exc)
            message = registry.render("authz_reviewer.failed_explanation", where=where, error=exc)
        else:
            if findings is not None:
                return findings
            logger.warning("Authz section review for %s had no parsable findings", section.section_id)
            message = registry.render("authz_reviewer.unparsable_explanation", where=where)
        self.errors.append({"source": section.section_id, "message": message})
        return []

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
