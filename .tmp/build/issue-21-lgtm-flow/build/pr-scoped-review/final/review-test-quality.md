# Test-quality review (Unit): pr-scoped-review, ebe9dff..f036cc5

Verdict: no High findings. 2 Medium, 2 Low.

## Findings
1. Medium, fault detection (inspected): AC-S3-1/2 scope rule is proven only by regex over the prompt text (tests/test_graph_prompts.py TestSectionReviewScopeRule). Any prompt containing the keywords passes, e.g. "Never say newly exposes; unchanged code is not not reported". No test shows a reviewer output for an unchanged-code weakness is dropped; fake models cannot prove model behavior (litellm part is INTEGRATE). Correction: accept as a known limit, and add a deterministic check that findings whose evidence is not grounded_in_pr and which carry no exposure explanation are not reported as vulnerabilities, if the story intends enforcement beyond the prompt. Decision needed: is the prompt the only enforcement of AC-S3-1?
2. Medium, coverage (inspected): AC-S3-1 "cites a changed line" is checked by grounding. An item labelled snapshot "pr" is grounded unconditionally (evidence.py: `labelled and snapshot == "pr"` returns True) even if the cited lines are unchanged; no test pins that unchanged.py with "pr" is grounded or not (existing test only checks validity). Add a case with an unchanged file at "pr" and state the expected grounded value.
3. Low, independence: test_removed_text_joins_deletions_across_hunks builds its input with `.replace(" b = 2", " b = 2")` (no-op) plus a string-edit of MULTI_HUNK_DIFF. Use a literal diff.
4. Low, independence: prompt tests couple to wording via regexes such as `\bcit(e|es|ing)\b`; harmless rewording could fail them. Acceptable.

## Verified strong
- Changed expectation `valid-base` False to True is justified by AC-S3-4; a `valid-base-unchanged` case retains the False protection.
- Removed-only evidence test asserts resolved, grounded, verdict unchanged, explanation unchanged (not downgraded/rejected).
- Mutations run against evidence.py (reverted, worktree clean): always include added text for labelled items, return True for any removed-eligible item, and fold added text into removed text were all caught by the `shifted.py "import os" base False` case. Baseline 388 passed.
- Parameterization covers labelled/unlabelled, fabricated snippet, wrong snapshot, shifted, unchanged. Edge cases not covered: empty or whitespace content (`_snippet_in_text` returns True for empty snippet, but item.content.strip() is guarded), CRLF removed lines, very short common snippets matching removed text by substring/fuzzy match.
- model_input_lock/expected.json: only the authz system prompts changed (scope sentence); regeneration is consistent with the prompts.toml diff. Not independently regenerated.

## Coverage statement
Tier: Unit. Inspected the diff, tests, evidence.py, git_diff.py, prompts.toml. Ran 4 test files baseline and 3 mutations. Not verified: live-model behavior, report_builder rendering, full suite.
