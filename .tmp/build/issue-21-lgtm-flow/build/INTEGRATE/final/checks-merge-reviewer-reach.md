# Merge check: reviewer-reach ebe9dff into bad831d (uncommitted, worktrees/INTEGRATE)

HEAD bad831d; resolution is uncommitted/on disk (index still shows UU for the paths below).

## Step 1
- `git diff --check`: no whitespace errors (only LF->CRLF warnings for tests/test_baselines.py, test_graph_tools.py, test_mitigation_defaults.py).
- Unmerged (UU) in index: src/lgtm/agents/base.py, src/lgtm/cli.py, src/lgtm/config.py, src/lgtm/pipeline.py, tests/model_input_lock/expected.json, tests/test_baselines.py, tests/test_graph_pipeline.py, tests/test_graph_tools.py. Not yet `git add`ed.
- grep for `^<<<<<<< `, `^>>>>>>> `, `^=======$` across the worktree (excluding .venv, .git): no hits.

## Step 2: full pytest
`.venv/Scripts/python -m pytest -rA -q --junitxml=.../merged-2.xml` (no xdist installed, serial). Log: build/INTEGRATE/tmp/verifier/merged-2.log
Result: **8 failed, 2734 passed, 7 skipped**, 602.74s. (Reference: base 0 failed, feat 0 failed.) Skips not investigated.

## Step 3
Lint/type-check: none documented in plan/repo.md; ruff and mypy are not installed in the venv. Not run.

## Failures
1. tests/model_input_lock/test_model_input_lock.py::test_model_visible_text_matches_the_recorded_base_values[follow_ups]
   - list of follow-up labels differs at index 10 ('text_tool_call_result' vs expected 'tool_raises'; one extra item). Expected: model_input_lock, regenerated later.
2-4. tests/test_graph_tools.py::TestFailedCallsSpendSlots::test_five_failed_text_calls_then_the_loop_stops_without_backend[authz_reviewer]
   and TestRejectedAttemptAfterBudgetIsSpent::test_text_sixth_attempt_is_never_taken[authz_reviewer-unknown_name] / [authz_reviewer-missing_argument]
   - IndexError at tests/test_graph_tools.py:193 (`review_section(...)[0]` on empty list); log: "Authz section review for s1 had no parsable findings".
   - Not model_input_lock. Likely cause: src/lgtm/agents/authz_reviewer.py ~lines 294-312 (feature's answer_until_resolved flow) records the failure in `self.errors` and returns `[]`, while main's version (HEAD authz_reviewer.py ~lines 203-206) returned a stamped failure finding `[unparsable]`. The test (run_agent fixture, test_graph_tools.py:170-193, from main) takes `[0]` and reads `result.tool_calls_used`. Either the test fixture needs to handle `[]` (read tool_calls_used from `agent.run_records`) or authz_reviewer should keep returning a failure finding. Decision for the integrator; the feature's no-finding-on-failure behaviour looks deliberate (errors list).
5-8. tests/test_integration_flags.py::TestScoring::{test_vulnerable_outside_target_is_still_a_false_alarm (TN != FP), test_vulnerable_on_target_is_a_hit (FN != TP), test_possible_on_safe_is_a_true_negative (predicted 'safe' != 'possible'), test_summary_reports_outside_target_rate (overall fp 0 != 1)}
   - Not model_input_lock. File exists only on main (not in ebe9dff). Cause: benchmark/evaluate.py:230-232 `is_judged_row` returns True for any row with "pin" and default mode "lgtm" (JUDGED_MODES at line 613 includes "lgtm"); the main-side test rows have `pin: {}` and no `mode`, with `verdict` fields, so they are scored via `finding_verdict` (evaluate.py:293-296, `supported`-based) and every finding becomes "safe". Feature's judged scoring and main's verdict-based scoring collide; fix is in the test rows (add `mode`/legacy marker or `supported`) or `is_judged_row` (e.g. require `supported`/judged fields on findings).

## Cleanup
Only wrote merged-2.xml/.log and this report. No processes left (pytest finished). No project files edited.

Required verification NOT complete: 7 failures beyond the expected model_input_lock one.
