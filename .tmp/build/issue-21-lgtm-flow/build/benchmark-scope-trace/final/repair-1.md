# Repair 1: M2 out_of_scope_cases (Unit)

Change: added `assert summary["out_of_scope_cases"] == ["out_sql", "out_sql_safe"]` to `test_headline_counts_only_in_scope_rows` in `tests/test_baselines.py` (worktree benchmark-scope-trace). No production change.

Command: `.venv/Scripts/python.exe -m pytest -q tests/test_baselines.py -k test_headline_counts_only_in_scope_rows`
Result: 1 passed, 266 deselected. The behavior already existed, so the assert passes on first run (existing coverage gap closed, not a red test).

Not run: other suites (verification scheduled separately). Not acted on: M1, M3, L1.
Risk: assert fixes list order to input order; the reviewer-specified expectation.
