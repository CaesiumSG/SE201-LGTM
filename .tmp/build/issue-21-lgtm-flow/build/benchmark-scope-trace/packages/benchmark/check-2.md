# benchmark package re-check (benchmark-scope-trace), check-2

Worktree .tmp/build/issue-21-lgtm-flow/worktrees/benchmark-scope-trace, HEAD ebe9dff, 14 modified files (uncommitted, the target; same list as check 1). Diff hash 19642648...bad1 identical before and after all runs. No edits made.

## Checks (each run once, venv python, pytest -p no:cacheprovider, PYTHONDONTWRITEBYTECODE=1)
1. Named suite (`pytest tests/test_evaluate_real.py tests/test_benchmark_cases.py tests/test_real_world_cases.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py -rs`) -> 634 passed, 0 failed, 0 skipped. PASSED. Includes AC-S4-7 on real Semgrep (shoply_safe cases ran, not skipped; passed in check 1 and inside this run).
2. Other modules touching benchmark/evaluate etc. (test_agents, test_e2e_judged_bench, test_e2e_kev_bench_http, test_e2e_review_judge, test_graph_benchmarks, test_judge_eval, test_kev_confidence, test_kev_deploy, test_kev_support_bench, test_semgrep, test_validation) -> 470 passed, 0 failed, 1 DeprecationWarning (chromadb). PASSED.
3. Lint / type-check: none defined in plan/repo.md. NOT RUN.

## Previous failures
- F1 (test_evaluate_real.py off-category test): now passes. The fix runs mode llm-only with an authz safe finding plus sqli "vulnerable" finding "sqli:9"; asserts off_category == ["sqli:9"] and outcome == "TN". Criterion intent kept (off-category finding listed, outcome unchanged from the in-category TN).
- F2 (test_baselines.py summary off-category test): now passes in the 634.

## Coverage notes
- AC-S4-3/S4-5 real-world measurement on stored runs deferred (DEC-9), no network or model endpoint used.
- Residual question from check 1 (judged-mode unsupported findings are not listed as off-category) is unchanged; the test now avoids it by using llm-only.
- Required verification for the package: complete for the named checks; lint/type-check not defined.

## Cleanup
No throwaway files created (tmp/change-verifier not used). No other resources created.
