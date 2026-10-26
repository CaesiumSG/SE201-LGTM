# scope-rule check

Verdict: FAILED (test defect in new tests; production change looks correct).
Revision: worktree HEAD ebe9dff (slice base), uncommitted changes verified (prompts.toml, expected.json, test_graph_prompts.py plus removed-line-grounding files, not run by me).

## Runs
1. pytest tests/test_graph_prompts.py tests/test_agents.py tests/model_input_lock tests/test_agents_doc.py tests/test_e2e_review_judge.py tests/test_graph_tools.py tests/test_registry.py tests/test_registry_edit.py tests/test_report.py -q (fake models only): 8 failed, 734 passed, 277s.
2. Diagnostic rerun tests/test_graph_prompts.py tests/model_input_lock: 8 failed, 165 passed. Same 8: all TestSectionReviewScopeRule except test_scope_rule_sits_in_the_system_message (passed). Model input lock: all pass (expected.json consistent with prompts.toml).
3. Disposable diagnostic (deleted): rendered system prompt checked with word-boundary regexes equivalent to the tests' intent: rule sentence matches cite/changed/removed, newly expos, already exists/unchanged + not + empty. Passed.

## Cause
tests/test_graph_prompts.py has 6 lines with literal 0x08 (backspace) characters in the regex strings where r"\b" was intended (e.g. line 396: r"<BS>cit(e|es|ing)<BS>"). The patterns can never match, so the new tests fail on a test defect, not on the prompt. Prompts.toml diff adds the rule bullet in [authz_reviewer].system_prompt (lines 182-184), rendered in the system message.
Proposed fix: replace each 0x08 byte with the two characters \b (grep -c $'\x08' tests/test_graph_prompts.py gives 6 lines). Rerun -k ScopeRule afterwards.

## Coverage
AC-S3-1 / AC-S3-2 Unit: not yet demonstrated by a passing durable test (blocked by the test defect). litellm_authz_safe false-positive part is INTEGRATE, not run. No finding-level filtering test (by design). Lint/types: not defined by repo, not run. Excluded per assignment: test_validation.py, test_graph_evidence.py, test_diff.py.
Cleanup: tmp files removed; no project files edited by me.
