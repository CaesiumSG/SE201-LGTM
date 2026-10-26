# removed-line-grounding: unit tests (AC-S3-4)

Tier: Unit. Worktree: C:\JR Cache\se201-lgtm\.tmp\build\issue-21-lgtm-flow\worktrees\pr-scoped-review

## Behaviors covered
- Evidence citing only lines the PR removed is grounded_in_pr=True (unlabelled and `base`-snapshot items), is not rejected (resolves) and the finding's verdict/explanation are untouched.
- Negative boundaries: base context/unchanged lines, `pr`-labelled citation of a deleted file, fabricated snippet are not grounded.
- `FileDiff` removed-text access (additive).

## Tests
- tests/test_validation.py: `test_evidence_citing_only_removed_lines_is_grounded_in_the_pr` (+ REMOVAL_DIFF)
- tests/test_graph_evidence.py: `test_removed_line_evidence_is_grounded_only_when_the_pr_removed_that_text` (9 params), `test_removed_only_evidence_is_not_rejected_or_downgraded`; new kind `valid-base-unchanged`
- tests/test_diff.py: `TestRemovedText` (5 tests)

## Updated expectations
- test_graph_evidence.py kind `valid-base` (deleted.py cited at `base`, removed text): grounds_pr False -> True; `test_each_item_records_its_own_grounding...`: `[True, False, False]` -> `[True, True, False]`. Justification: AC-S3-4.

## Run (once)
`.venv/Scripts/python.exe -m pytest tests/test_validation.py tests/test_graph_evidence.py tests/test_diff.py -q -p no:cacheprovider` -> 11 failed, 209 passed.

Fail because behavior absent (all):
- test_validation: removed_lines_is_grounded_in_the_pr
- test_graph_evidence: kind[valid-base]; each_item_records_its_own_grounding; removed_line param deleted.py/base, shifted.py/base, shifted.py/None (3 of 9); removed_only_evidence_is_not_rejected_or_downgraded (grounded assertion)
- test_diff: 4 TestRemovedText tests, `AttributeError: 'FileDiff' object has no attribute 'removed_text'`

Pass as existing coverage: the 6 negative params of the removed_line test, `valid-base-unchanged`, `test_added_text_is_unchanged_by_removed_text_access`, rest of the 3 files.

## Open decisions / limits
- Interface name `FileDiff.removed_text` (property, deleted lines joined by "\n", mirrors `added_text`) is assumed; plan names none. If production picks another name, only test_diff.py changes.
- Grounding tests go through public `validate`; they do not depend on that name.
- Not run: lint, types, other suites. Production files untouched.
