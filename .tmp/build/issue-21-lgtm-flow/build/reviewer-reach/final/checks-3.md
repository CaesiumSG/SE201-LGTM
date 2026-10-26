# checks-3: reviewer-reach
- HEAD: 442229899d71dc326acf33c77632ac4395f81f37 (confirmed at start and end)
- git status --porcelain: empty at start and at end
- Command: .venv/Scripts/python.exe -m pytest tests/ -q -p no:cacheprovider (from worktree), exit 0
- Result: 2712 passed, 8 skipped, 0 failed, 1 warning (chromadb DeprecationWarning), 575.75s
- Skips (8): reasons not enumerated (-q run without -rs); not treated as passes.
- Lint/type-check: none defined by repo.
- Status: Passed (Checks: pytest). Live-model/real-world criteria remain INTEGRATE.
- Cleanup: tmp/checks removed.
