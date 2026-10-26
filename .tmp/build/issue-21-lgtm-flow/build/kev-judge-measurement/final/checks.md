# Checks: kev-judge-measurement

Revision: f18272b7df2f7692f524df133b69a059e118743c (HEAD confirmed before and after). Working tree clean before and after.

## Check 1: slice pytest command (single run)
Command (worktree root, .venv python): `python -m pytest tests/test_judge_eval.py tests/test_judge.py tests/test_cli.py tests/test_report.py tests/test_e2e_judged_bench.py tests/test_e2e_review_judge.py tests/test_kev_support_bench.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py tests/test_graph_benchmarks.py tests/model_input_lock -rs -q`
Status: Passed. Exit 0; 812 passed, 0 failed, 0 skipped (no skip lines under -rs), 1 DeprecationWarning (chromadb). 169 s.
Tier: Unit; Kev judge HTTP server simulated in tests; no real resource touched.

## Gaps
Pass totals show no per-criterion mapping (AC-S5/S6 not individually traced). Real-world parts of AC-S6-1/2 and AC-S6-6 are INTEGRATE-only, not run.

## Cleanup
No resources created; tmp/change-verifier not needed. Nothing remains.

## Round 2
Revision: HEAD f18272b7df2f7692f524df133b69a059e118743c plus uncommitted repairs. `git status --porcelain` before and after lists exactly 5 modified paths: benchmark/README.md, benchmark/judge_eval.py, benchmark/kev_model_labels.json, docs/kev-labeling-criteria.md, tests/test_judge_eval.py. HEAD unchanged.
Check: same slice pytest command as Check 1, single run. Status: Passed. Exit 0; 815 passed (3 more than round 1), 0 failed, 0 skipped, 1 chromadb DeprecationWarning. 106 s.
Gaps and cleanup: unchanged from above; nothing created.
