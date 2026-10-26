# reach: production repair 1 (after check.md)

Nothing run or verified; no commit.

1. Recorder contract fixed: `run_tool_loop` in agents/base.py back to 5 arguments; recorder callback unchanged. It sets `toolbox.steps_exhausted` on both exits. New `fill_record(record, toolbox, answer)` in agents/base.py fills RunRecord and returns answer; limit_hit = "steps" if steps_exhausted, else "tool_calls" if len(call_log) > budget, else None. authz_reviewer.py (inside each re-ask attempt) and investigator.py wrap run_tool_loop results in fill_record.
2. Read cap vs 8000 chars blocked: render_read in src/lgtm/graph/format.py:112 clamps with `min(8000, max_chars)` (file outside Modifies). Needed change: replace with `max_chars`. agents/tools.py adds READ_CHARS_PER_LINE = 160; read_file_impl passes `max(MAX_OUTPUT_CHARS, cap * READ_CHARS_PER_LINE)` to render_read (cap 600 -> up to 96000 chars).

Notes: fill_record reads toolbox.call_log and toolbox.budget directly; a fake toolbox without them would fail.
