# Common-sense review: pr-scoped-review (ebe9dff..f036cc5)

Production change is minimal and justified: 3-line prompt rule (AC-S3-1/2), `FileDiff.removed_text` (additive, AC-S3-4), `_diff_removed` plus grounding change in evidence.py. No new deps, no signature changes, report_builder untouched. No High or Medium findings.

## Findings

1. Low - tests/test_graph_prompts.py (+54): six tests (with a 4-way parametrization) pin a three-line prompt rule through regex sentence matching. Two tests re-assert the same two regexes (`newly expos`, `already exist|unchanged`) already asserted by the first four, and the model_input_lock expected.json already pins the exact prompt text. Replace with one test on the system message asserting the three clauses; delete the guidance-flag/notes parametrization and the "empty list" duplicate. Helpers `_scope_sentences` and `_has` then shrink or go.

2. Low - tests/test_diff.py (+26): `test_removed_text_joins_deletions_across_hunks` builds its input with `.replace(" b = 2", " b = 2")`, a no-op, plus a second replace; hard to read and not clearly testing what its name says. `test_added_text_is_unchanged_by_removed_text_access` is trivial. Keep: holds-only-deleted, deleted-file, empty-without-deletions. Delete the other two (or write the multi-hunk diff literally).

3. Low - tests/test_validation.py vs tests/test_graph_evidence.py: the removed-line grounding case is covered in both (test_validation +1 test; test_graph_evidence parametrized 9 cases plus a not-rejected test plus `valid-base-unchanged` kind). The parametrized set is the real coverage; the test_validation one adds only the diffs-from-parse path. Keep one of the two, preferably the parametrized table.

4. Low - src/lgtm/validation/evidence.py `_item_grounds_in_pr`: the `texts` list with a conditional append is more indirect than needed. Equivalent:
   ```
   if item.file not in self._diff_added: return False
   if self._snippet_in_text(item.content, self._diff_removed[item.file]): return True
   return not labelled and self._snippet_in_text(item.content, self._diff_added[item.file])
   ```
   Behavior is unchanged; this is readability only. `_diff_removed` is populated in the same loop as `_diff_added`, so the `item.file in _diff_added` guard covers both lookups.

## Checked, no issue
- Prompt wording is flat, no process leakage; no new comments added in src.
- `removed_text` docstring matches the sibling property's style.
- expected.json diff is the 7 authz prompts regenerated for the new bullet, as the slice states; the `<SystemMessage>` rows differ only in that line (diff truncated to prefix, not fully compared).
- authz_reviewer.py was listed in Modifies but unchanged; nothing in the rule required it.

## Limits
Did not run pytest. Did not read package reports under build/pr-scoped-review/packages. Compared expected.json by stat and prefix only.
