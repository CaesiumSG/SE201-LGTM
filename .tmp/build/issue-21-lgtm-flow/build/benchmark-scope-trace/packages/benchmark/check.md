# benchmark package check (benchmark-scope-trace)

Worktree: .tmp/build/issue-21-lgtm-flow/worktrees/benchmark-scope-trace, HEAD ebe9dff, uncommitted changes (14 modified files, no untracked) are the target. Diff hash identical before and after the runs. Note: packages/benchmark/edit.md did not exist and was not read.

## Checks (each run once, venv python, pytest -p no:cacheprovider)
1. Named suite: `pytest tests/test_evaluate_real.py tests/test_benchmark_cases.py tests/test_real_world_cases.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py` -> 2 failed, 632 passed, 0 skipped. FAILED.
2. `pytest tests/test_benchmark_cases.py -k shoply_safe -rs` (AC-S4-7, real Semgrep, sqli_04/07/11_safe) -> 3 passed, none skipped. PASSED (also inside run 1).
3. Other modules referencing benchmark/evaluate (test_agents, test_e2e_judged_bench, test_e2e_kev_bench_http, test_e2e_review_judge, test_graph_benchmarks, test_judge_eval, test_kev_confidence, test_kev_deploy, test_kev_support_bench, test_semgrep, test_validation) -> 470 passed, 0 failed. PASSED.
4. Lint / type-check: plan/repo.md defines none. NOT RUN.

## Failures (both are in the package's new tests; production not shown at fault)
F1 tests/test_evaluate_real.py::TestScopeAndTraceOnRealWorldRecords::test_off_category_findings_are_listed_without_changing_the_outcome
- `rec["off_category"] == []`, expected `["sqli:9"]`. Mode is lgtm (judged). benchmark/evaluate.py scope_fields counts an off-category finding only when finding_verdict is "vulnerable", which in judged modes means `supported` is truthy. The test's fake finding dumps only `verdict: "vulnerable"` with no supported/kev fields, so it is never "vulnerable" in a judged row. Likely TEST defect: fixture should give the sqli finding supported=True (or run in llm-only if verdict form is intended). Residual question for the parent: whether unsupported judged findings should list as off-category (current code says no; consistent with the baselines test using _as_judged).
F2 tests/test_baselines.py::TestOffCategoryFindings::test_summary_lists_the_off_category_finding
- `(tp, tn) == (1, 0)`, expected `(1, 1)`. Row "a" (expected safe, only a sqli finding, authz case) scores outcome UNCREDITED / predicted no_candidate (no own-category finding), so it is not a TN. Pre-existing scoring (predict_case_verdict ignores other-category findings); the new code listed "sqli:7" correctly (earlier asserts passed). TEST defect: give row "a" an authz safe finding, as the sibling test does, or drop the tn assertion.

## Coverage notes
- AC-S4-7 verified with the real Semgrep binary (3/3).
- AC-S4-3/S4-5 real-world measurement on stored runs: deferred (DEC-9), no network or model endpoint used.
- Required verification is NOT complete: 2 failing tests.

## Cleanup
Throwaway dir tmp/change-verifier removed. pytest ran with no bytecode/cache writes by the checks (-p no:cacheprovider; PYTHONDONTWRITEBYTECODE for later runs; the first run may have refreshed existing tests/__pycache__, which is untracked/ignored). No other resources created.
