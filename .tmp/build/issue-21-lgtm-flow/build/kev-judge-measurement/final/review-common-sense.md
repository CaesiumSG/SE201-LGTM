# Common-sense review: kev-judge-measurement (efc85996..f18272b7)

Verdict: no High or Medium findings. 3 Low.

## Low

L1. benchmark/judge_eval.py `report()` and `label_summary()`: duplicate guard.
`report` calls `label_summary(labels) if labels.get("labeling_model") else None`, while `label_summary` raises ValueError when `labeling_model` is missing. The raise is unreachable from the only caller. Delete the raise (or the caller's conditional). Required behavior unchanged: the `labels` key is None without a model.

L2. benchmark/judge_eval.py `report()` quote-absence branch.
`if read_pr_file or not any(...)` with a `lambda *_: None` stand-in exists only to avoid creating a temp dir. `quote_absence` already skips non-matching cases. Simplest replacement: build the temp-dir reader only when a QUOTE_ABSENCE case is present, else `rows = []`. Smaller, no dummy lambda.

L3. docs/kev-labeling-criteria.md "Stale candidates" section duplicates the stale note in benchmark/README.md and STALE_REASON. Delete the section from the criteria document. Stale candidates are a measurement exclusion, not a labeling criterion. Also `_labelled_judged` docstring restates its name and signature.

## Checked, no finding
- Counting rule appears in evaluate.finding_verdict, cli, and report_builder. Each acts on a different data shape, so no shared helper was warranted.
- New report keys (kev_accuracy, kev_agreement, supported_by_kind, safe_case_acceptance, stale, labels) each map to AC-S6 items or DEC-13. No unrequested options.
- No process leakage found in code, docs, or README. "model-generated, not human-reviewed" states a real limitation.

Inspected: the full non-test diff, the label file head, the slice file, and the log. Tests (about 500 added lines) were skimmed by stat only. Did not run the suite.
