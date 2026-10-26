# repair-1

Nothing was run or verified. `triage-merge-2.md` does not exist at the given path; fixes were derived from the merged code and tests/test_baselines.py.

## Files changed
- benchmark/evaluate.py
  - G1: `score_case` (coverage-row branch) computes `judged = is_judged_row(result)` and passes `judged=` to both `predict_case_verdict` calls.
  - G2: `_relevant_verdicts(row, files=None, grounded=False)`; with `grounded` on a non-judged row, an unsupported "vulnerable" becomes "possible". `derive_case_labels` now builds `grounded_label` from grounded verdicts in all four branches (no coverage, non-authz, authz via `_verdict_label(..., missing)`).
- src/lgtm/pipeline.py (G4): removed the failure pseudo-finding, `failed_findings`, and the `failed_finding_id` import. `_section_result(findings, error)` now takes the agent error message: failed `SectionResult` with `error`; the error still reaches `meta.agent_errors` through `section_stage.errors`. `findings=dedup_findings(section_findings)`.
- src/lgtm/agents/authz_reviewer.py (G4): removed `failure_finding` and `failed_finding_id` (no remaining users).

## G3 UNCREDITED: not restored, conflict
Slice test tests/test_baselines.py `TestOutcomeTable::test_baseline_only_labels_score_as_before` (llm-only, possible/insufficient label, safe expected -> UNCREDITED) contradicts upstream tests that assert TN for the same rows:
- `TestOutcomeTable::test_outcome_by_label_and_expectation` (possible_vulnerability / insufficient_evidence, safe -> "TN")
- `TestSummaryContract::test_metrics_score_every_non_error_row` (s3/s4 safe rows are TN, "nothing is excluded or uncredited under the round-2 rule", tn == 5, accuracy 0.5)
- `test_no_relevant_finding_on_safe_case_is_a_true_negative`

The decision belongs to the feature-wide scoring criterion (round-2 rule: flagged iff a `vulnerable` finding, otherwise TN/FN). Left as upstream (TN); `outcome_for_label` stays dead code in evaluate.py.

## Observations
- `test_outcome_by_label_and_expectation` passes `mode=mode, **_scenario(label)`; for the possible/insufficient scenarios `_scenario` also contains `mode`, so the call raises TypeError (duplicate keyword). Test bug, not touched.
- `outcome_for_label` / `EXCLUDED` filters in `summarize.metrics` remain dead.
