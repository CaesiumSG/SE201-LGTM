# Workspace: pr-scoped-review

- Worktree: C:\JR Cache\se201-lgtm\.tmp\build\issue-21-lgtm-flow\worktrees\pr-scoped-review
- Branch: build/issue-21-lgtm-flow/pr-scoped-review (new, from build/issue-21-lgtm-flow/reviewer-reach)
- Slice base SHA: ebe9dff9d5970a5678eb5f721230a33d0eee1d0c
- Primary checkout confirmed (git-dir .git); .tmp/ excluded via .git/info/exclude; pytest testpaths = ["tests"]; slice has no Setup section

## Setup commands
1. git worktree add -b build/issue-21-lgtm-flow/pr-scoped-review <worktree> build/issue-21-lgtm-flow/reviewer-reach : ok
2. python -m venv .venv : ok
3. .venv/Scripts/python.exe -m pip install -e ".[dev]" : ok; semgrep not installed (not needed by this slice)
4. codegraph init -i : ok (4,770 nodes, 14,836 edges)

## Checks (run from the worktree)
- Tests: .venv/Scripts/python.exe -m pytest tests/ -q
- Lint / type-check: not defined by the repo
