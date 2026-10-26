# reach: edit report

Nothing run or verified; no commit.

Files changed (worktree reviewer-reach, all under src/lgtm):
- config.py: `read_file_max_lines=600` (new, validated positive), `investigator_max_tool_calls` 12->24, `investigator_max_iterations` 16->32.
- agents/tools.py: removed `MAX_READ_LINES`; `read_file_impl` caps at `config.read_file_max_lines` (AC-S2-2, AC-S2-5).
- agents/base.py: new `RunRecord(section, tool_calls, raw_answer, limit_hit)`. `run_tool_loop(..., record=None)` fills it on both exits. tool_calls is a copy of `toolbox.call_log`. limit_hit is "steps" when the iteration cap forced the answer, else "tool_calls" when `len(call_log) > budget`, else None. The invalid-input cap is not counted as "steps".
- agents/investigator.py: `InvestigatorResult.run_record`, with section "investigator".
- agents/authz_reviewer.py: `review_section` appends one `RunRecord` per section to `self.run_records`, and adds an "Enclosing definitions" block to the section body (AC-S2-1, AC-S1-4). Anchor: PR snapshot at the first added line when the hunk has additions; removed-only hunks use the base snapshot at the first deleted line. Lookup: `ast` innermost enclosing function, decorators included; blob read through `read_committed_blob` -> `lgtm.agents.tools.run_git`, not charged to the tool budget. One entry per (snapshot, file, function), each capped at `read_file_max_lines`. Skips non-.py files, unreadable blobs, parse errors, hunks outside any function, and "pr" when the toolbox has no shas.
- agents/prompts.toml: `{enclosing_block}` placeholder in `authz_reviewer.section_body`; new entries `enclosing_block` and `enclosing_item`.
- pipeline.py: `ReviewResult.run_records` = investigator record followed by section records (CT-reviewer-reach-1); `[]` in sast-only and llm-only modes.

Not edited: sections.py, coverage.py, prompt_parts.py, git_diff.py, provenance.py.

Observations:
- tests/model_input_lock/expected.json changes (every authz section prompt gains the enclosing block); needs regenerating.
- provenance.py `budgets` omits `read_file_max_lines`; tests/test_coverage.py (~395) and tests/test_report.py (51) assert exact budgets dicts.
- Run records are not persisted to reports or benchmark results (AC-S2-3, benchmark-scope-trace).
- If an LLM call raises mid-run, the record keeps defaults (empty tool_calls, no raw_answer).
- Renamed files: removed-only hunk looks up the base snapshot under the new path, so the enclosing block is skipped.
- Reasks reuse one record: last attempt's answer and limit_hit.
