**Build closed: accepted**

- Branch: `build/issue-21-lgtm-flow/reviewer-reach`
- Base: `7f642e1fe5315f34db43935b9ee1a5bdd112fea9`
- Head: `ebe9dff9d5970a5678eb5f721230a33d0eee1d0c`

**Summary.** The reviewer now gets the enclosing definition of every function a changed hunk touches. Added lines come from the PR snapshot and removed lines from the base snapshot, so a deletion-only change is reviewed against the code it came out of. The investigator tool-call budget is raised from 12 to 24, the step budget from 16 to 32, and the `read_file` line cap from 200 to 600. All three values are in `src/lgtm/config.py`. `ReviewResult.run_records` holds one record for the investigator and one per section, each with `section`, `tool_calls`, `raw_answer` and `limit_hit` (CT-reviewer-reach-1).

**Evidence**
- Tests: the full `pytest tests/` suite at head gave 2716 passed, 8 skipped (environment skips), 0 failed. The model-input lock (`tests/model_input_lock/expected.json`) was regenerated, and every diff in it comes from the budget and read-cap changes.
- Review:
  - Lens reviews found no Critical or High issues. Behavior, test quality, common sense and structure were reviewed.
  - The final review found 1 High (final-01) and 1 Medium (final-02), both repaired.
  - The first re-review found 1 High (final-03). It was repaired in one extra bounded round the orchestrator approved.
  - The second re-review is clean.
- Criteria: AC-S2-1, AC-S2-2 and AC-S2-5 are met at Unit tier with fake models. AC-S1-4 is met at Unit tier only; the live-model check is INTEGRATE's (DEC-9).

**Approved scope additions** (outside Modifies)
- `src/lgtm/graph/format.py`: `render_read` now uses the caller's `max_chars` instead of a hard 8000-character clamp. This lets the raised line cap take effect. `render_grep` is unchanged.
- `tests/test_graph_export.py`: only the `render_read` case of `test_read_and_grep_hard_ceiling` changed.
- `tests/test_report.py`: two default-budget assertions changed.

**Plan corrections applied (wording only)**
- AC-S2-1 now reads: "includes the enclosing function or definition of every changed line, including removed lines (a hunk spanning several functions contributes each of them), not only".
- CT-reviewer-reach-1 `limit_hit` now reads: null, "tool_calls", or "steps"; null also when the loop ended at the invalid-tool-input cap.

**needs_replan:** none.

**Pending integration**
- Live-model AC-S1-4.
- AC-S1-1, AC-S1-2 and AC-S2-4 (DEC-9).
- Regenerate `tests/model_input_lock/expected.json` after the final merge.

**Outstanding (Medium and Low)**
- The enclosing-definitions block has no total size cap, and each definition is cut silently at the line cap.
- `_enclosing_functions` recurses, so code nested about 2000 levels deep raises RecursionError (final-04).
- Some enclosing edge cases have no tests: line-cap truncation, dedupe within one function, the `.py` filter, nested innermost.
- Nothing specifies or tests the run record's `limit_hit` at the invalid-input cap.
- The AC-S1-4 unit test only proves that nothing crashes.
- A run record is lost when the LLM raises mid-run. On a re-ask, the record keeps only the last attempt.
- Renamed files, non-Python files and module-level hunks get no enclosing definition.
- The provenance `budgets` omit `read_file_max_lines`.
- `authz_reviewer` uses the toolbox's private `_snapshot_sha`.
