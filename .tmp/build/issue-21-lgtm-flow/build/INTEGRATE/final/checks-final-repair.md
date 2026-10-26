# checks-final-repair

Target: worktrees/INTEGRATE at bf6391595a6f, uncommitted. `git status --porcelain` = exactly: M README.md, benchmark/citation_export.py, benchmark/real_world/README.md, src/lgtm/cli.py, src/lgtm/validation/evidence.py, tests/test_cli.py; ?? tests/test_removed_line_citation.py. `git diff --check`: clean (exit 0).

Full suite (once, no -x): `.venv/Scripts/python.exe -m pytest --junitxml=tmp/verifier/full-final-repair.xml -rA -q` (log: tmp/verifier/full-final-repair.log). Exit 1: 2 failed, 2937 passed, 7 skipped (639.67s). Previous: 2907 passed, 7 skipped.
Collected 2946 (previous 2914): +32 vs previous checks-repair. Skips unchanged at 7 (POSIX-only tests, e.g. test_graph_runtime.py:1003, :1022).

Failures (both FAILED = Failed status):
- tests/test_judge_eval.py::TestNullSnapshotCitationsAreReadAtPrHead::test_null_snapshot_citation_unresolved_at_pr_head_is_unreadable_and_not_judged_without_base_fallback[file-only-at-base]
- same test [lines-only-at-base]
Error: KeyError: 'unreadable' at tests/test_judge_eval.py:1580 (units[1] has no unreadable flag; code is read from base).
Cause: product change contradicts a stale test. benchmark/citation_export.py export_run (~lines 91-105, repair-7 final-01) now falls back from pr to base for null-snapshot citations when base holds the quoted content; the test (lines 1561-1580) asserts there is no base fallback and expects unreadable + not judged. [file-nowhere] passes. Not a flaky/env issue. Resolution needed: update the two parametrizations' expectation (or change the fix), a parent decision. Note repair-7-tests.md only ran test_cli.py and test_removed_line_citation.py, so this was not caught earlier.

Test-function delta vs bf63915 (name sets from `def test_` in tests/): 0 missing; 11 new names (test_removed_line_citation.py etc.). Total def count 1578 -> 1589. No existing test deleted.

Cleanup: only wrote files under tmp/verifier (xml, log, base.txt/now.txt/b.n/n.n name lists) and this report. Tracked files unchanged (status identical before/after).
Verification NOT complete/green: 2 failures.
