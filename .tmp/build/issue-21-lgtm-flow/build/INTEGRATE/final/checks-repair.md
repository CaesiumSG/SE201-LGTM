# checks-repair

Target: worktrees/INTEGRATE at 84bece6 plus uncommitted edits (before and after the run, `git status --porcelain` showed only base.py, tools.py, test_agents.py, test_baselines.py, test_graph_pipeline.py, test_graph_tools.py modified).

| Check | Status | Result |
| --- | --- | --- |
| `git diff --check` | Passed | exit 0; only a CRLF-conversion warning for tests/test_graph_pipeline.py |
| Full suite: `.venv/Scripts/python -m pytest tests --junitxml=.../tmp/verifier/full-repair.xml -rA -q -p no:cacheprovider` (no -x) | Passed | exit 0; 2907 passed, 7 skipped, 1 warning, 653s. Log: tmp/verifier/full-repair.log |
| No test function from 84bece6 missing | Passed | AST comparison of test function names (class::name) in the four test files, 84bece6 vs working tree |

Failures: none.

Collected-test delta: previous 2869 passed + 7 skipped; now 2907 passed + 7 skipped (+38 passed, skips unchanged; the same 7 POSIX/symlink skips in test_graph_runtime.py).
Function-name delta (script tmp/verifier/names.py): test_baselines.py 167 -> 183 (+16), test_agents.py 95 -> 104 (+9), test_graph_pipeline.py 61 -> 61, test_graph_tools.py 127 -> 127; missing from HEAD: none, duplicates: none. The +25 functions vs +38 passed gap is presumably parametrized cases; not itemized. The comparison was by function name, not by pytest-collected id, so a changed parametrize set at an unchanged name would not show.

Notes: a first launch via nohup/& died with its launcher shell (log 47 bytes) before running tests; the full run above is a single clean re-launch, not a rerun of a failure. Only files under tmp/verifier and this report were written.
