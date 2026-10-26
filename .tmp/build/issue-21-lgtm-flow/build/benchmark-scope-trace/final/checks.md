# Checks: benchmark-scope-trace

- Branch: build/issue-21-lgtm-flow/benchmark-scope-trace
- Head SHA: 026b87296929ee70ef72300ac22b39c308980980
- Worktree: clean (git status --porcelain empty before and after; only ignored caches present)

## Check 1: pytest (slice Checks command, venv python)
Command: .venv/Scripts/python.exe -m pytest tests/test_evaluate_real.py tests/test_benchmark_cases.py tests/test_real_world_cases.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py -rs -p no:cacheprovider
Status: Passed. Exit 0, 634 collected, 634 passed, 0 failed, 0 skipped (no skip lines under -rs), 56.75s.
Per file: test_evaluate_real, test_benchmark_cases, test_real_world_cases, test_baselines, test_e2e_benchmark_replay (4 tests) all ran.

## Notes
- AC-S4-7 (real Semgrep on Shoply patches) is covered by the suite; no skips were reported, so it executed. I did not separately inspect that test's assertions.
- Doc statements (AC-S4-1, AC-S4-2) are covered only as far as the tests assert them; no manual doc read.
- No network, no real-world fetch, no lease needed. No throwaway files created; tmp/checks not used.
