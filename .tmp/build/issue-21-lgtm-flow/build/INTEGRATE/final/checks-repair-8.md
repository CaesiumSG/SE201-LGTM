# checks-repair-8

Target: worktrees/INTEGRATE at 5cec8e15ad20, uncommitted. `git status --porcelain` = exactly: M benchmark/citation_export.py, M src/lgtm/validation/evidence.py, M tests/test_removed_line_citation.py (same before/after). `git diff --check`: clean (exit 0).

Full suite (once, no -x): `.venv/Scripts/python.exe -m pytest --junitxml=tmp/verifier/full-repair-8.xml -rA -q` (log: tmp/verifier/full-repair-8.log). Exit 0: 2941 passed, 7 skipped, 0 failed, 1 warning (684.83s). Previous run: 2937 passed + 2 failed + 7 skipped.
The 2 previous failures (test_judge_eval.py null-snapshot [file-only-at-base], [lines-only-at-base]) now pass.
Skips (7, unchanged, host-related): test_coverage.py:510 (Windows filename), test_graph_export.py:1473 x2 (symlink privilege), test_graph_runtime.py:804, :969, :1003, :1022 (POSIX/symlink). Not passes.
ERROR lines in log are captured logging from passing tests.

Test-function delta vs 5cec8e1 (def test_ names per file): 0 missing; 3 new names (all in tests/test_removed_line_citation.py; two parametrized). Base 1595 -> now 1598.

Not run: lint/type checks. Cleanup: wrote only tmp/verifier files (xml, log, base8.txt, now8.txt) and this report.
Verification complete for the full suite: green.
