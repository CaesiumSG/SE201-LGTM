# Behavior review: pr-scoped-review (ebe9dff..f036cc5)

Verdict: no High or Medium findings. 2 Low, 1 open decision. Static inspection only (pytest could not run: `langchain_core` not installed in this environment).

## Base-label question (developer note)
`_grounds_pr` (evidence.py ~288): a labelled item now grounds when snapshot is `pr`, or when snapshot is `base` and the validated snippet matches the file's removed text. For labelled items added text is no longer consulted. Correct for every caller:
- Labelled items (strict mode, `shas` set; pipeline and `validate_candidates`): a `base` snippet is verified against the base blob, so it cannot genuinely be an added line. Matching it to added text could only be coincidental, so dropping it is right. `pr` stays unconditionally grounded (unchanged).
- Unlabelled items (non-strict, or strict without snapshot): both removed and added text are tried. Added behavior unchanged, removed is new (AC-S3-4).
- Deleted files: `FileDiff.path` falls back to `old_path`, so removed text is keyed and reachable. Empty removed text cannot match (ratio 0).
- Only consumer of the flag is report_builder rendering; no gating on it, so no downstream regression.

## Findings
1. Low, inspected. Renamed files: `_diff_removed` is keyed by new `path`; a `base`-labelled item citing the old path is not in `_diff_added`, so removed-line evidence for a renamed-and-edited file is not grounded. Edge case; AC-S3-4 examples unaffected. Fix: also key by `old_path`.
2. Low, inspected. Grounding is a snippet match against the whole file's removed text (fuzzy, 0.75, no line-range check). A short or generic `base` snippet (e.g. `}`, `return x`) citing unchanged lines can be marked grounded if it fuzzily matches any removed line in that file. Same looseness already existed for added text; flag is display-only.

## Open decision
AC-S3-1/DEC-5 enforcement is prompt-only (prompts.toml bullet) plus the existing flag. A `pr`-snapshot item citing unchanged code is still `grounded_in_pr=True`, and nothing drops ungrounded findings. This matches the slice (report_builder and validate signatures out of scope; INTEGRATE covers litellm), but the business decision is whether a code-level scope gate is wanted later.

## Coverage
Inspected: evidence.py, git_diff.py, prompts.toml diff, callers (pipeline.py, validation/__init__.py, base.py answer_until_resolved, report_builder). No tests executed; no resources created (tmp/behavior not needed).
