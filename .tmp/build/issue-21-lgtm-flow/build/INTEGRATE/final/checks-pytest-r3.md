# pytest (full suite), INTEGRATE, round 3
Revision: 6d0072945260ebd59f2ef1b5fd13602049d4c811, worktree clean (git status empty before and after).
Command: `.venv/Scripts/python.exe -m pytest -rfEs -q -p no:cacheprovider` (cwd worktrees/INTEGRATE, no model/judge servers)
Status: PASSED. 2947 passed, 0 failed, 0 errors, 7 skipped, 1 warning, 770.65s, exit 0.
Failures: none.
Skips (all host/OS related, none for missing servers): test_coverage.py:510 ('*' invalid in Windows filenames); test_graph_export.py:1473 x2 (symlink creation denied, WinError 1314); test_graph_runtime.py:804 (POSIX non-root), :969 (symlink denied), :1003 (POSIX dir permission bits), :1022 (POSIX symlink/permissions). Those 7 are unexercised on this host.
Warning: chromadb DeprecationWarning (asyncio.iscoroutinefunction), tests/test_cli.py judge override test.
tests/test_tool_loop_context.py: passes (diagnostic run of that file alone after the full run: 6 passed; it also passed inside the full run).
Cleanup: tmp/verifier already existed with other sessions' files (not mine, left untouched); I created nothing there. No other resources.
