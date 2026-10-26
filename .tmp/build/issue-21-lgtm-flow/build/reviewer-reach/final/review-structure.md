# Structure review: reviewer-reach (7f642e1..012fe4b)

Verdict: CLEAN. High 0, Medium 0, Low 3.

structure-01 (Low) src/lgtm/agents/authz_reviewer.py `_enclosing_block`, `_hunk_anchor`, `_enclosing_function`: calls the toolbox's private `_snapshot_sha(label)` and reads `toolbox.shas` / `toolbox.repo` directly; ~70 lines of AST enclosing-definition extraction in a prompt-assembly module. Fix: public toolbox method returning committed text for a snapshot and path.

structure-02 (Low) src/lgtm/agents/base.py `_close_run`, `fill_record`: `run_tool_loop` sets undeclared `toolbox.steps_exhausted`; `fill_record` reads it with `getattr(..., False)`; `AgentToolbox.__init__` and `reset_budget` do not declare or reset it. Fix: declare in `__init__`, clear in `reset_budget`, read directly.

structure-03 (Low) src/lgtm/agents/tools.py, src/lgtm/graph/format.py: `READ_CHARS_PER_LINE = 160` local policy; `render_read` trusts caller `max_chars` while `render_grep` keeps the 8000 clamp. Both approved scope additions. No stale `MAX_READ_LINES` references.

Checked and fine: `read_file_max_lines` single owner in `LGTMConfig`, validated positive; `RunRecord` defined once in base.py, produced by `AuthzReviewerAgent.run_records` and `InvestigatorResult.run_record`, aggregated in `ReviewResult.run_records`; dependency direction preserved; `TYPE_CHECKING` guard for `HunkRef` matches existing pattern; new templates in prompts.toml beside existing blocks.

Not inspected: tests not run; package reports and plan/architecture.md not read.
