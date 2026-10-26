# repair-2: undetermined labels

Nothing was run or verified.

benchmark/judge_eval.py:
- `_labelled_judged` skips units with verdict `undetermined`; `kev_accuracy` (supported, verdict, severity), `supported_by_kind` and `safe_case_acceptance` all go through it.
- `supported_agreement` skips them too. The criteria doc says undetermined units are "excluded from accuracy", so the placeholder `supports: yes` is not counted.
- `kev_agreement(outcomes, labels=None)`: new optional `labels`; undetermined unit ids are left out of both rates. `report` passes the labels.
- `label_summary` adds `undetermined: {"n", "units"}` (sorted unit keys); `report["labels"]` carries it.
- Label validation (`_validate_labels`) checks only `supports`, so `undetermined` verdicts are already accepted.

benchmark/README.md: the `labels` bullet mentions `undetermined`.

`report["undetermined"]` is a top-level sorted list of undetermined unit ids; the duplicate `undetermined` entry in `label_summary` / `report["labels"]` was dropped (no test used it), and the benchmark/README.md bullet now describes the top-level key.

`confidence_agreement` now skips undetermined units as well. (Nothing open.)
