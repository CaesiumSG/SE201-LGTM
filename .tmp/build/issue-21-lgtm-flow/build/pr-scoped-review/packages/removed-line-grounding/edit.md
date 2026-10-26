# removed-line-grounding: edit (AC-S3-4)

Files changed (worktree pr-scoped-review):
- src/lgtm/diff/git_diff.py: added property `FileDiff.removed_text` (deleted lines joined by "\n", mirrors `added_text`). No existing field changed.
- src/lgtm/validation/evidence.py: `EvidenceValidator` keeps `_diff_removed` (normalized removed text per file). `_grounds_pr` now returns True for a valid item when: label `pr` (unchanged); or its snippet is found in the file's removed text (`base`-labelled and unlabelled items); unlabelled items also still ground on added text. Base-labelled items no longer ground on added text; `pr`-labelled items with no shas unchanged except removed text is also accepted. `validate`/`validate_all`/`resolves` signatures and rejection logic untouched; verdict/explanation not modified.

Out of scope observations: report_builder.py untouched. Empty-content items remain ungrounded.

Not run, not verified: no tests, lint, or type checks executed.

Skipped: no new tests (supplied).
Risk: `valid-base` expectation flip depends on `base` blob validation passing (existing behavior); a base-labelled snippet that merely fuzzy-matches removed text counts as grounded (same 0.75 threshold as added text).
