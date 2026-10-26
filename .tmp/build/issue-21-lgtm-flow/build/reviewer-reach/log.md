# Build log

## Decisions
- Q: tests/test_report.py default-budget assertions break after raising investigator budgets; outside Modifies. A: APPROVED by orchestrator: update only those two default-value assertions to the new budgets; no other changes. Source: orchestrator.
- Q: run_tool_loop recorder contract. A: keep the 5-argument recorder callback; fill run records via a separate helper. Source: repository convention at slice base (tests/test_agents_doc.py).
- Q: render_read 8000-char hard clamp prevents the raised read_file line cap from taking effect (AC-S2-2); src/lgtm/graph/format.py outside Modifies. A: APPROVED by orchestrator: change only render_read's clamp to max_chars; render_grep and other callers untouched. Source: orchestrator.
- Q: test_graph_export.py read hard-ceiling test breaks after the clamp lift; outside Modifies. A: APPROVED by orchestrator: change only the render_read case to assert the caller's max_chars bound with header and end marker intact. Source: orchestrator.
- Q: read_file char limit. A: max(8000, read_file_max_lines * 160). Source: build decision (smallest option).
- Q: minor plan corrections from final review (AC-S2-1 wording; invalid-input cap limit_hit). A: APPROVED by orchestrator, wording only; applied to plan/stories.md and slices/reviewer-reach.md; to be published to LGT-166 in the Finish note. Source: orchestrator.
  - AC-S2-1 before: "includes the enclosing function or definition of each changed hunk, including hunks that only remove lines, not only"
  - AC-S2-1 after: "includes the enclosing function or definition of every changed line, including removed lines (a hunk spanning several functions contributes each of them), not only"
  - CT-reviewer-reach-1 before: limit_hit (null, "tool_calls", or "steps").
  - CT-reviewer-reach-1 after: limit_hit (null, "tool_calls", or "steps"; null also when the loop ended at the invalid-tool-input cap).
- Q: High final-03 after re-review with repair budget spent. A: APPROVED by orchestrator: one extra bounded repair for final-03 only and one re-review of that diff; any remaining High finishes blocked/budget. Source: orchestrator.

## Kept scope additions
- src/lgtm/graph/format.py: render_read clamp changed from min(8000, max_chars) to max_chars.
- tests/test_report.py: two default-budget assertions (investigator_max_tool_calls 24, investigator_max_iterations 32).
- tests/test_graph_export.py: render_read case of test_read_and_grep_hard_ceiling asserts the caller's max_chars bound.
