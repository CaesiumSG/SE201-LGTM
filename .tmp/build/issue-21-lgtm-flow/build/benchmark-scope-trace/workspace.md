# Workspace

- Worktree: C:/JR Cache/se201-lgtm/.tmp/build/issue-21-lgtm-flow/worktrees/benchmark-scope-trace
- Branch: build/issue-21-lgtm-flow/benchmark-scope-trace
- Slice base: ebe9dff9d5970a5678eb5f721230a33d0eee1d0c (head of build/issue-21-lgtm-flow/reviewer-reach)

## Setup
- git worktree add -b build/issue-21-lgtm-flow/benchmark-scope-trace <wt> build/issue-21-lgtm-flow/reviewer-reach: ok
- python -m venv .venv (in worktree): ok
- .venv/Scripts/python -m pip install -e ".[dev]" semgrep: ok (semgrep 1.182.1)
- codegraph init (in worktree): ok (4,770 nodes, 14,836 edges)

## Pytest
C:/JR Cache/se201-lgtm/.tmp/build/issue-21-lgtm-flow/worktrees/benchmark-scope-trace/.venv/Scripts/python -m pytest  (run from the worktree)
