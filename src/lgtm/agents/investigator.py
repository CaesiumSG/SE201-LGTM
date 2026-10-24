"""Investigator agent: proposes review sections from the unfiltered PR diff."""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import Literal

from lgtm.agents import prompt_parts, registry
from lgtm.agents.base import run_tool_loop
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff
from lgtm.review.coverage import InvestigatorStatus
from lgtm.review.sections import (
    _LINE_PREFIX,
    HunkRef,
    ProposedSection,
    _hunk_ref,
    _section,
    parse_investigator_output,
    render_section,
)

logger = logging.getLogger(__name__)

InputMode = Literal["full", "manifest_only"]

_EXCERPT_LINES = 3

@dataclass
class InvestigatorResult:
    proposed: list[ProposedSection] | None
    status: InvestigatorStatus
    error: str | None
    input_mode: InputMode
    tool_calls: int


def run_investigator(
    diffs: list[FileDiff],
    config: LGTMConfig,
    toolbox: AgentToolbox,
    llm,
) -> InvestigatorResult:
    refs = [
        _display_ref(_hunk_ref(diff, index))
        for diff in diffs
        if diff.path.endswith(".py")
        for index in range(len(diff.hunks))
    ]
    diff_text = render_section(_section("investigator", "investigator", "", "", refs))
    manifest_only = len(diff_text) > config.investigator_diff_chars
    input_mode: InputMode = "manifest_only" if manifest_only else "full"

    logger.info("Investigator: %d hunks, input %s", len(refs), input_mode)
    try:
        toolbox.reset_budget(config.investigator_max_tool_calls)
        tools = toolbox.build_tools()
        tool_info = prompt_parts.tool_guidance(toolbox)
        system = registry.render(
            "investigator.system_prompt",
            tool_section=prompt_parts.render_tool_section(tool_info),
            max_tool_calls=tool_info.max_tool_calls,
        )
        if manifest_only:
            manifest = registry.entry("investigator.excerpt_label") + prompt_parts.code_fence(
                _manifest(refs, excerpt=True), "text"
            )
            diff_section = ""
        else:
            manifest = _manifest(refs, excerpt=False)
            diff_section = registry.render(
                "investigator.diff_section", block=prompt_parts.code_fence(diff_text, "diff")
            )
        user = registry.render(
            "investigator.user_prompt", manifest=manifest, diff_section=diff_section
        )
        investigator_config = replace(
            config, max_agent_iterations=config.investigator_max_iterations
        )
        raw = run_tool_loop(llm, tools, system, user, investigator_config)
        proposed = parse_investigator_output(raw)
    except Exception as exc:  # noqa: BLE001 - reported through the result
        logger.warning("Investigator failed: %s", exc)
        return InvestigatorResult(
            proposed=None,
            status="failed",
            error=str(exc) or type(exc).__name__,
            input_mode=input_mode,
            tool_calls=toolbox.calls_used,
        )
    return InvestigatorResult(
        proposed=proposed,
        status="ok",
        error=None,
        input_mode=input_mode,
        tool_calls=toolbox.calls_used,
    )


def _display_ref(ref: HunkRef) -> HunkRef:
    return replace(
        ref,
        hunk_id=prompt_parts.escape_control(ref.hunk_id),
        file=prompt_parts.escape_control(ref.file),
    )


def _manifest(refs: list[HunkRef], *, excerpt: bool) -> str:
    lines: list[str] = []
    files: set[str] = set()
    for ref in refs:
        if ref.file not in files:
            files.add(ref.file)
            lines.append(registry.render("investigator.manifest_file", file=ref.file, status=ref.status))
        lines.append(
            registry.render(
                "investigator.manifest_hunk",
                hunk_id=ref.hunk_id,
                old_start=ref.old_start,
                old_count=ref.old_count,
                new_start=ref.new_start,
                new_count=ref.new_count,
                change=ref.change,
            )
        )
        if excerpt:
            changed = [change for change in ref.changes if change.kind != "context"]
            lines.extend(
                f"    {_LINE_PREFIX[change.kind]}{change.content}"
                for change in changed[:_EXCERPT_LINES]
            )
    return "\n".join(lines)
