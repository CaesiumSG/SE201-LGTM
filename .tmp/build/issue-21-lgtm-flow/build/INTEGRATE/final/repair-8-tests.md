# repair-8-tests (Unit tier)
File: tests/test_removed_line_citation.py (only file written).
Added:
- rereview-01: TestReadCitedCodeRemovedLines::test_removed_line_citation_whose_text_survives_elsewhere_in_pr_returns_base_lines (two-handler fixture SIBLING_BASE/SIBLING_PR, cites [7,8], expects base lines).
- rereview-02: TestCitationExportRemovedLines::test_unlabelled_removed_line_citation_exports_base_code[pr-lines-exist|pr-lines-past-end]; ::test_removed_line_citation_whose_text_survives_elsewhere_in_pr_exports_base_code. `export` fixture gained optional `base` arg.
- Null-snapshot cases in tests/test_judge_eval.py:1561-1580 untouched (content "c" matches neither snapshot); they pass.
Failing baseline: first run (before the parallel developer change landed) 4 failed/215 passed, all 4 new tests: read returned PR code; export returned PR-head read (empty/unreadable code). Right reason.
Final run: `.venv/Scripts/python -m pytest tests/test_removed_line_citation.py tests/test_judge_eval.py tests/test_cli.py -q` -> 219 passed, 1 warning (the developer's evidence.py/citation_export.py edits were in the worktree by then).
Not run: lint/type checks, full suite. No existing expectations changed.
