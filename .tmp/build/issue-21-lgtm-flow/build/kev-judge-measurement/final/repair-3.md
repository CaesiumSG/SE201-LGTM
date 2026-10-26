
## test-developer: undetermined labels (Unit)

Changed `tests/test_judge_eval.py` only.

- `TestStoredLabelsAndCriteria::test_stored_labels_hold_supported_verdict_kind_and_origin_for_each_unit` now accepts verdict real, not_real or undetermined.
- New `TestUndeterminedLabels`: `kev_accuracy` leaves undetermined units out of the verdict n; `kev_agreement(outcomes, labels)` leaves them out of both verdict measures (new optional `labels` argument, my chosen interface); `report()["undetermined"]` is the list of undetermined unit ids and the report's verdict n and agreement n exclude them.
- Supported and severity accuracy are not asserted for undetermined units (criteria doc says "excluded from accuracy" without distinguishing).

Run once: `.venv/Scripts/python -m pytest tests/test_judge_eval.py`: 138 passed, 1 failed. Failure: `TestUndeterminedLabels::test_report_lists_the_undetermined_units` with `KeyError: 'undetermined'` (behavior absent: report has no `undetermined` key). The accuracy and agreement tests pass against the current production code (existing coverage of the exclusion).
