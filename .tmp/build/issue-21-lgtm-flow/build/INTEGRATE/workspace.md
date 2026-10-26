# Workspace

- Worktree: C:/JR Cache/se201-lgtm/.tmp/build/issue-21-lgtm-flow/worktrees/INTEGRATE
- Branch: build/issue-21-lgtm-flow/INTEGRATE
- Integration base: bad831d99fbf91dcbed703625ce4ef4e81cef791 (origin/main after fetch)
- Python: 3.14.8 (venv at <wt>/.venv)
- plan/repo.md present; feature slices have no Setup sections (default Setup only, no extra preparation)

## Upstream commits since base_commit 7f642e1
bad831d Merge pull request #17 from CaesiumSG/feat/injection-mitigations-default
8b8a26d Merge pull request #19 from CaesiumSG/integrate/stack
8d1eafa Record the default-on mitigation runs: injection ASR 0/6, dev split unchanged
a56175e docs: describe the default-on mitigations (run numbers to follow)
55445e7 Turn the prompt-injection mitigations on by default for the LGTM modes
4597a3c Integrate the section/graph pipeline as the default, with the old behaviour behind flags
f67000f Merge branch 'main' into integrate/stack
6ede46c Merge pull request #18 from CaesiumSG/feat/field-trial
79b86d9 Merge pull request #16 from CaesiumSG/docs/ai-use-logs
61e1d25 Field trial: 12 ordinary merged PRs, no crashes, no false alarms, 10/12 unreviewed
6b9944b Field-trial harness: run LGTM on ordinary merged PRs from real projects
fe92132 Commit the per-member AI-use logs folder with a stub file for every member

## Commands
- git fetch origin main: ok (exit 0)
- git worktree add -b build/issue-21-lgtm-flow/INTEGRATE <wt> bad831d99fbf91dcbed703625ce4ef4e81cef791: ok
- python -m venv .venv: ok
- .venv/Scripts/python -m pip install -e ".[dev]" semgrep: ok (exit 0)
- codegraph init: ok (indexed 94 files, 3487 nodes, 10760 edges)
