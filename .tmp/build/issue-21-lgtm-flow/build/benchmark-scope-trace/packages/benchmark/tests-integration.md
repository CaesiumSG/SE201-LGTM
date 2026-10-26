# benchmark: Integration tests

Tier Integration. AC-S4-7 only. File: tests/test_benchmark_cases.py (appended `test_shoply_safe_sql_case_triggers_semgrep_in_the_diff`, parametrized sqli_04_safe, sqli_07_safe, sqli_11_safe).

Method: copy the module's base repo, apply the case patch on branch `pr`, scan the PR-version .py files with the real venv Semgrep binary using the bundled rules dir (as pipeline._run_sast does), filter_to_diff, assert at least one in-diff finding and all are SQLi. Skipped if semgrep is not installed. Temp data under pytest tmp paths; no network; no throwaway files.

Run once: `.venv/Scripts/python.exe -m pytest tests/test_benchmark_cases.py -k shoply_safe -q` -> 3 failed.
- All 3 fail with `AssertionError: <id>: Semgrep reports no in-diff warning` (`assert []`): Semgrep ran and returned nothing; behavior absent (patches not yet regenerated). Not fixture/config errors.

Not covered here: "stay in headline metrics" (scope "in") is handed to Unit tier / test_baselines scope tests (not written here). Assumes bundled rules (src/lgtm/sast/rules) are the Semgrep config; if the registry "auto" config were intended, offline run is impossible.
No other suites, lint, or type checks run.
