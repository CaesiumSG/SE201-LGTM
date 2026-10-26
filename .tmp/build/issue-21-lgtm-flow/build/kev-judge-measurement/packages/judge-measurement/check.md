# judge-measurement: package check

Verdict: FAILED (4 existing tests fail; not yet verified).

Revision: worktree HEAD efc85996 (slice base) plus uncommitted package changes (M README.md, benchmark/README.md, benchmark/evaluate.py, benchmark/judge_eval.py, src/lgtm/cli.py, src/lgtm/reporting/report_builder.py, tests/test_cli.py, tests/test_judge_eval.py, tests/test_report.py; new benchmark/kev_model_labels.json, docs/kev-labeling-criteria.md; stray benchmark/README_append.tmp ignored). Tree not modified during checks.

## Checks
1. Slice Checks command (`.venv/Scripts/python -m pytest <slice list> -q -rs`): 4 failed, 806 passed, 1 warning (115s). Baseline was 763 passed; +43 new passing tests. No skips reported. Model-input lock tests (tests/model_input_lock) passed with the current expected.json, so no regeneration was needed or run.
2. Diagnostic split runs (same tests, to list failures): 3 failed / 747 passed in the judge_eval/judge/report/kev_support/baselines/replay/graph files; 1 failed / 59 passed in e2e_review_judge, model_input_lock, e2e_judged_bench, test_cli. Failures identical to run 1.
3. Lint, type-check: not defined by the repo (plan/repo.md); not run.

## Failures (existing tests, all in the same family: they assert Kev verdict does not change results)
- tests/test_judge_eval.py::TestKevMetricsInSyntheticSummary::test_existing_scores_and_gating_equal_those_of_the_same_run_without_kev_answers[lgtm] and [lgtm-no-sast]: `assert 'safe' == 'vulnerable'` ("predicted"). A supported + not_real candidate now scores safe, as AC-S5-3 requires.
- tests/test_judge_eval.py::TestKevInJudgeEvalReport::test_existing_report_measures_equal_those_of_the_same_run_without_kev_answers: report now carries a populated `kev_agreement` (verdict_vs_supported n=2) that differs from the no-Kev-answers run (n=0). Expected from the new key.
- tests/test_e2e_review_judge.py::test_review_report_and_exit_code_do_not_change_with_kev_verdict_and_severity: exit code 1 vs 0 between Kev variants (variant with not_real now exits 0 by the AC-S5-4 rule).
Cause: product behavior is as the new criteria intend; these old tests encode the superseded Kev-independence rule (test defect / needs update by the package owner). Not changed by me. Proposed correction: scope the equality assertions to Kev-neutral fields or to variants without not_real; the e2e test should assert exit 0 for a supported+not_real-only variant. Note these files include tests/test_e2e_review_judge.py, which the slice lists as Modifies but the tests-unit report left untouched. Cause not confirmed beyond the assertion output above.

## Passed
New tests in tests/test_judge_eval.py, tests/test_cli.py (exit-code rows, README rule), tests/test_report.py (TestSupportedButNotReal) pass within run 1 (AC-S5-1..4, AC-S6-1..5 at Unit tier, including stale-candidate DEC-13 tests and stored label/criteria tests).

## Gaps and notes
- quote_absence is empty for run6-final (authz_10/12_vulnerable absent from it); AC-S6-3 proven by synthetic Unit tests only.
- Labels: 73 units from claim and quote, not Kev answers; three flagged by the editor for review (sqli_05_safe/1.0, sqli_06_safe/0.0, sqli_08_safe/0.0). Not checked here.
- Kev HTTP server simulated in tests only; no real resource touched.

## Cleanup
No throwaway files left (tmp/change-verifier created empty and removed). No leases or processes. benchmark/README_append.tmp still present (ignored, removed at commit).

Required verification: incomplete (4 failing).

## Round 2

Verdict: PASSED (H1 resolved).

Revision: worktree HEAD efc85996 plus uncommitted package changes; now also M tests/test_e2e_review_judge.py. benchmark/README_append.tmp ignored.

Slice Checks command (same as round 1, `-q -rs`): 812 passed, 0 failed, 0 skipped, 1 warning (120s). Baseline 763; round 1 had 806 passed and 4 failed. All four H1 tests now pass. Model-input lock passed with the current expected.json; no regeneration needed. Lint and type-check: not defined by the repo.

Spot check: the rewritten e2e test now asserts exit 0, stats.supported 0 and no [SUPPORTED] for (not_real, low), and baseline equality for (real, critical). That matches AC-S5-3 and AC-S5-4. The Kev judge server is simulated, so this is not proof against a real server.

Gaps unchanged from round 1: quote_absence on run6-final is empty (synthetic Unit tests only); three editor-flagged labels not reviewed here.

Cleanup: no throwaway files, leases or processes.

Required verification: complete for the Unit tier.
