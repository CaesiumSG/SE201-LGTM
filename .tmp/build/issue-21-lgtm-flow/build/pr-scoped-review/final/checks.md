# Slice checks: pr-scoped-review

Revision: f036cc545dda8972b2ceb011c289a49bf63cf66f, worktree pr-scoped-review, working tree clean (git status empty before run).

## Check: pytest (full suite, repo config, testpaths=tests)
Command (worktree root): `.venv/Scripts/python.exe -m pytest -q -rs -p no:cacheprovider`
Result: exit 0; 2745 passed, 8 skipped, 0 failed, 1 chromadb DeprecationWarning; 664s. Status: Passed.
Includes the model input lock (tests/model_input_lock), tests/test_graph_prompts.py (ScopeRule class), test_agents, test_validation, test_graph_evidence, test_diff.

Skips (all environmental, none attempt live endpoints or real-world repos):
- test_coverage.py:510 '*' invalid in Windows filenames
- test_graph_export.py:1473 x2 symlink privilege denied
- test_graph_runtime.py:799, 964, 998, 1017 POSIX-only semantics / symlinks
- test_semgrep.py:227 semgrep not installed
No test reported reaching a live model endpoint or real-world repo. Not otherwise instrumented for network access.

Failures: none, so no base (ebe9dff) comparison needed.

## Not covered
INTEGRATE-only: AC-S3-3, 5, 6, 7, litellm part of AC-S3-2. Lint/type checks not defined by repo. Prompt tests prove wording only, not model behaviour.
Earlier package reports (scope-rule check.md failure from 0x08 test defect) are superseded; the repaired tests pass here.

Cleanup: no tmp files created; no project files edited.
