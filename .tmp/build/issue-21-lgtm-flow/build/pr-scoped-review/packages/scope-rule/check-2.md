# scope-rule check-2 (after test repair)

Verdict: PASSED.
Revision: worktree HEAD 14a8e25 (removed-line-grounding committed). Uncommitted: src/lgtm/agents/prompts.toml, tests/model_input_lock/expected.json, tests/test_graph_prompts.py. Untouched during runs.

## Runs
1. .venv/Scripts/python.exe -m pytest tests/test_graph_prompts.py tests/test_agents.py tests/model_input_lock tests/test_agents_doc.py tests/test_e2e_review_judge.py tests/test_graph_tools.py tests/test_registry.py tests/test_registry_edit.py tests/test_report.py -q (fake models only): 742 passed, 0 failed, 0 skipped, 1 unrelated chromadb DeprecationWarning, 250s. Previous run: 8 failed, 734 passed; the 8 ScopeRule failures now pass (734+8=742, same test count).
2. grep -c $'\x08' tests/test_graph_prompts.py: 0.

## Pattern review
The diff against HEAD (git diff, cat -v) shows TestSectionReviewScopeRule with \b word boundaries as real two-character escapes (no ^H). Patterns match the intent recorded in check.md: cite/changed/removed|deleted; newly expos + pr/change; already exist/pre-existing/unchanged + not/never/omit; same + empty; system-message check. The class was never committed, so the original bytes are not in git; comparison is against check.md's description and the repair note (only the 6 byte-to-\b fixes). No assertion weakened or removed.

## Coverage gaps
litellm_authz_safe false-positive effect is INTEGRATE, not run. Lint/types not defined by repo. test_validation.py, test_graph_evidence.py, test_diff.py not run (excluded). Prompt tests prove wording only, not model behavior.
Cleanup: no tmp files created; no project files edited.
