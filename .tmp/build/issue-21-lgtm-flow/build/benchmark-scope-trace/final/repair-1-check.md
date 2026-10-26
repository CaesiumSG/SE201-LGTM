# Repair 1 check

Revision: 026b87296929ee70ef72300ac22b39c308980980 plus uncommitted tests/test_baselines.py (one added line, the out_of_scope_cases assert). Only that file modified, before and after the run.

Command: `.venv/Scripts/python.exe -m pytest tests/test_baselines.py -rs` (run once, Unit tier, no external services)
Result: Passed. 267 passed, 0 skipped, 0 failed, exit 0 (2.74s). The collected count (267) matches the 266 deselected plus 1 selected from repair-1.md.

The new assert `summary["out_of_scope_cases"] == ["out_sql", "out_sql_safe"]` is in `test_headline_counts_only_in_scope_rows` and holds.
Not run: other suites. Risk: the assert pins list order to input order.
Cleanup: nothing created.
