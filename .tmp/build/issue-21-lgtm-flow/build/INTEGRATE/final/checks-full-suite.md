# Check: pytest (full suite)

- Revision: 84bece67c8708217d1f8f6b0293178fd43ee1466 (worktree INTEGRATE), working tree clean before and after (HEAD unchanged).
- Command (cwd = worktree): `.venv/Scripts/python -m pytest --junitxml=<run-dir>/build/INTEGRATE/tmp/verifier/full-84bece6.xml -rA -q` (no -x, no xdist; xdist not installed). Log: `.../verifier/full-84bece6.log`.
- Status: PASSED. Exit 0; 2869 passed, 0 failed, 7 skipped, 1 warning, 662.10s.
- Baseline (origin/main bad831d): 2177 passed, 7 skipped, 0 failed. Same 7 skips, +692 passing tests.

## Failures
None.

## Skipped (7, all host-related, same set as baseline)
- tests/test_coverage.py:510 - '*' not valid in Windows file names
- tests/test_graph_export.py:1473 (x2) - host denies symlink creation (WinError 1314)
- tests/test_graph_runtime.py:804 - needs POSIX non-root
- tests/test_graph_runtime.py:969 - host denies symlink creation
- tests/test_graph_runtime.py:1003 - POSIX directory permission bits
- tests/test_graph_runtime.py:1022 - POSIX symlink and permission semantics

Line numbers shifted versus baseline (746/911/945/964 -> 804/969/1003/1022), so the graph_runtime tests moved. The symlink and POSIX-permission paths are unexercised on this Windows host.

## Warning
1 DeprecationWarning from chromadb (asyncio.iscoroutinefunction), in a third-party package.

## Not covered by this check
The other whole-feature items (CLI and benchmark commands, dependency diff, README) are not part of this check. Tests tagged requires_codegraph ran as the suite selected them; none appeared in the skip list.

Cleanup: no resources created besides the log, xml and exit files in the verifier dir.
