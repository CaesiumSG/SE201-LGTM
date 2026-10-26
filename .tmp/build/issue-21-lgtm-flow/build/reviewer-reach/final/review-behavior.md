# Behavior review: reviewer-reach (7f642e1..012fe4b)

Findings (all inspected; nothing reproduced, none High):

1. Medium - src/lgtm/agents/authz_reviewer.py `_enclosing_block`: the enclosing block is not bounded in total size.
   Each function is capped at read_file_max_lines (600) but the block has no count or char cap, and section_max_chars (12000) applies only to section_text. A section with several large functions can add thousands of lines to the initial prompt. Fix: cap the block total (for example section_max_chars multiplied by a factor) and add a "[truncated]" marker; also mark the per-function cut at `min(end, start+cap-1)`, which is silent today.
2. Medium - AC-S1-4 / slice outcome "reports bugs introduced by deleted code": only enclosing-definition context was added. No prompt or logic change addresses deletion-only reasoning, and the AC-S1-4 test passes against a fake model, so it was already passing at base. The criterion is unverified until INTEGRATE (DEC-9). Not a code defect, but do not count it as delivered.
3. Low - run records lost on failure: if run_tool_loop raises (investigator or section), the RunRecord keeps empty tool_calls, empty raw_answer and limit_hit None, because fill_record runs only after the loop returns. Calls made before the failure and any limit already hit are invisible (CT-reviewer-reach-1, "visible, not silent"). Fix: fill tool_calls from toolbox.call_log in a finally block.
4. Low - re-ask in answer_until_resolved reuses one record; last attempt overwrites earlier answer and limit_hit. A limit hit on attempt 1 can be cleared by a clean attempt 2. Note: reset_budget is not called between re-asks, so call_log accumulates, which partly masks this.
5. Low - renamed files: removed-only hunk looks up the base snapshot under the new path, so the enclosing block is skipped (AC-S2-1 gap for renames; edit.md acknowledges). Non-Python files and hunks outside functions (module level, class body) also get no enclosing definition.
6. Low - provenance budgets omit read_file_max_lines. AC-S2-5 is met (value in LGTMConfig), but reports do not record the cap.
7. Low - `steps_exhausted` is stale state on the toolbox, set only at loop exit and not cleared by reset_budget. An exception between runs could leak into the next record; currently masked because every loop exit overwrites it.

Confirmed OK
- AC-S2-5: tool-call budget 12->24, steps 16->32, read cap 200->600, all in LGTMConfig, validated positive.
- AC-S2-2: read_file_impl uses the config cap and the char cap max(8000, 600*160); render_read clamp lifted. render_read is used elsewhere, but the other callers pass their own max_chars, so I saw no regression (graph/format.py scope addition is logged and approved).
- AC-S2-1: removed-only hunks anchor on the base snapshot at old line; added hunks use the PR snapshot; innermost function with decorators is chosen; dedup per (snapshot, file, function).
- limit_hit semantics: "tool_calls" is set only when a call was refused (len(call_log) > budget); "steps" takes precedence; invalid-input cap is not counted as steps. Contract CT-reviewer-reach-1 fields present on ReviewResult.run_records (investigator first, then sections); [] in sast-only and llm-only modes.
- CON-3: additive; the new ReviewResult field has a default. CON-2: no new dependencies (ast is stdlib).

Coverage: read the slice, criteria, decisions, package reports, the log, the full src diff and the budget and record paths in tools.py and base.py. No tests run; no live-model runs (DEC-9). Cleanup: the tmp/behavior folder was never created, so nothing to remove.
