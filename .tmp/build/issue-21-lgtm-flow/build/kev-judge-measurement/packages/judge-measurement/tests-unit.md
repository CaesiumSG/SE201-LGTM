# judge-measurement: Unit tests

Tier: Unit. Worktree: `.tmp/build/issue-21-lgtm-flow/worktrees/kev-judge-measurement`. No throwaway files left in the run dir.

## Files changed (tests only)

- `tests/test_judge_eval.py`: appended classes `TestSupportedButNotRealIsNotAVulnerability`, `TestKevAccuracy`, `TestKevAgreement`, `TestStaleCandidates`, `TestLabelSummary`, `TestSupportedByKindAndSafeCaseAcceptance`, `TestQuoteAbsence`, `TestJudgeEvalReportWiring`, `TestStoredLabelsAndCriteria`.
- `tests/test_cli.py`: two new `_finding` kinds (`supported-real`, `supported-not-real`), six new rows in the exit-code parametrization, one README test.
- `tests/test_report.py`: class `TestSupportedButNotReal`.
- Untouched (nothing at Unit tier to add): `tests/test_judge.py`, `tests/test_e2e_judged_bench.py`, `tests/test_e2e_review_judge.py`, `tests/test_kev_support_bench.py`, `tests/model_input_lock/expected.json`.

## Interface contract the developer must implement (names chosen by me)

New file paths: `benchmark/kev_model_labels.json`, `docs/kev-labeling-criteria.md`.

Label file: `{"labeling_model": str, "criteria": "docs/kev-labeling-criteria.md", "units": {unit_id: {"supports": "yes|no", "verdict": "real|not_real", "severity": "low|medium|high|critical" (optional), "kind": str, "origin": "shoply|real_world"}}}`. `unit_id` is `case_id/finding.evidence` as in `citation_export.unit_id`. Stale cases have no units.

`benchmark/judge_eval.py` (outcomes are the `run_outcomes` dicts; `run_outcomes` must also add `agent_verdict` = recorded `finding["verdict"]`):

- `kev_accuracy(labels, outcomes) -> {"supported"|"verdict"|"severity": {"n","correct","accuracy"}}`. Judged and labelled units only. Severity only over units whose label has a severity. `accuracy` None when n is 0. Stale-case units are left out.
- `kev_agreement(outcomes) -> {"verdict_vs_supported": {"n","disagree","rate"}, "verdict_vs_agent": {"n","equal","rate"}}`. Disagree = (supported yes, verdict not_real) or (supported no, verdict real). Agent verdict "vulnerable" maps to "real", "safe" to "not_real"; an empty agent verdict is excluded from n. Judged only, stale left out.
- `stale_candidates(outcomes) -> [{"case_id","reason"}]`, one entry per stale case present (`sqli_04_safe`, `sqli_07_safe`, `sqli_11_safe`); reason contains "predate" (case-insensitive).
- `label_summary(labels) -> {"n","origins":{origin:count},"source":"model","labeling_model"}`; ValueError naming `labeling_model` when missing.
- `supported_by_kind(labels, outcomes) -> {kind: {"n","correct","accuracy"}}` (judged, labelled; correct = `supported` equals label `supports == "yes"`).
- `safe_case_acceptance(labels, outcomes, safe_cases: set[str]) -> {"shoply"|"real_world": {"n","accepted","share"}}`; accepted = `supported` True; origin from the label; share None when n is 0; both keys always present.
- `quote_absence(records, read_pr_file, case_ids=("authz_10_vulnerable","authz_12_vulnerable")) -> [{"case_id","file","lines","absent","cause"}]`; `read_pr_file(case_id, file) -> str|None`. One row per code evidence item (`content` is the quote). Present as contiguous text in the PR file: absent False, cause None. File unreadable or cited range outside the file: absent True, cause `repository_mismatch`. Otherwise absent: cause `agent_quote`.
- `report(...)` adds keys `kev_accuracy`, `kev_agreement`, `labels` (= `label_summary`), `supported_by_kind`, `safe_case_acceptance` (safe cases = records with `expected == "safe"`), `stale`.

`benchmark/evaluate.py`: `finding_verdict(f, judged=True)` returns "vulnerable" only if `supported` and `kev_verdict != "not_real"` (a missing `kev_verdict` keeps the old rule, for `--rescore` of old results). All of `score_case`, `scope_fields` and `judge_eval.verdict_accuracy` already go through it.

`src/lgtm/cli.py`: a finding with `kev_verdict == "not_real"` is not counted as supported for exit 1; rest unchanged. README exit-code section must mention "not_real"/"not real".

`src/lgtm/reporting/report_builder.py`: a supported finding with `kev_verdict == "not_real"` is excluded from `stats.supported` and is not rendered with `[SUPPORTED]`. How it is labelled instead is the developer's choice.

## Criteria map

- AC-S5-1: `TestKevAccuracy` (supported and verdict as separate numbers), wiring in `TestJudgeEvalReportWiring`.
- AC-S5-2: `TestKevAgreement`, wiring test.
- AC-S5-3: `TestSupportedButNotRealIsNotAVulnerability` (authz_09_safe TN, FN on a vulnerable case, FP kept for real, off_category, `je.verdict_accuracy`), `TestSupportedButNotReal` in test_report.
- AC-S5-4: new exit-code rows in `tests/test_cli.py`, `test_readme_exit_code_rule_covers_...`.
- AC-S6-1: `TestLabelSummary`, wiring test. The real-world part is INTEGRATE-only.
- AC-S6-2: `TestSupportedByKindAndSafeCaseAcceptance`.
- AC-S6-3: `TestQuoteAbsence`.
- AC-S6-4: severity cases in `TestKevAccuracy`.
- AC-S6-5: `TestStoredLabelsAndCriteria`; DEC-13 stale rule in `TestStaleCandidates`, `TestKevAccuracy`, `TestKevAgreement`, last test of `TestStoredLabelsAndCriteria`.

## Skipped as already covered / handed off

- Benchmark scoring keeps the stale cases (AC-S4-7, DEC-11): not restated here; covered by the benchmark-scope-trace suites.
- Supported-only accuracy against labels (`supported_agreement`) already exists in `TestSupportedAgreement` in `tests/test_judge_eval.py`; the new `kev_accuracy["supported"]` repeats that number only inside the combined result.
- AC-S6-6 and real-world parts of AC-S6-1/AC-S6-2: INTEGRATE.
- `tests/test_judge.py`, `tests/test_e2e_*`, `tests/test_kev_support_bench.py`: no Unit-tier behavior of these criteria lives there (`apply_judge_answer` already stores `kev_verdict` and `kev_severity`; `kev_support` fixtures already carry `live_shaped`).

## Run (once)

`.venv/Scripts/python -m pytest tests/test_judge_eval.py -k "<new classes>"` and `tests/test_cli.py tests/test_report.py -k "exit_code or readme_exit or SupportedButNotReal"`.

- test_judge_eval new tests: 36 failed with the above run (counts include 4 CLI + 2 report in the earlier combined run). Reasons: 6x+5x+4x+2x+2x+2x+1x `AttributeError` (function absent), 4 `FileNotFoundError` (label file and criteria doc absent), 1 `KeyError: 'kev_accuracy'`, 6 `AssertionError` (`finding_verdict` and scoring still return "vulnerable"/FP/TN wrong). All are behavior absent.
- test_cli: 4 exit-code rows fail (`supported-not-real` expecting 0 and 2: rows `kinds15`, `kinds16`, `kinds18`, `kinds19`) and the README test fails. These are behavior absent. The other new rows (`supported-real`, `supported-not-real`+`supported-real`) pass as existing coverage.
- test_report: 2 fail (stats count, `[SUPPORTED]` in markdown) because behavior absent; `test_markdown_still_flags_a_real_supported_finding` passes as existing coverage.
- Existing tests in the touched files were not run beyond the `-k` selections; no lint, type check or other suites run.

## Assumptions and risks

- "Verdict of the agent": lgtm-mode findings record `verdict == ""`; I assumed "vulnerable"/"safe" maps to real/not_real and empty is excluded. If the owner means "every agent candidate claims real", change `TestKevAgreement` (second test).
- "Kev accepted" on safe cases = `supported` True.
- Unsupported-but-`real` stays "safe" in `finding_verdict` (existing rule kept).
- `[SUPPORTED]` wording in test_report is the existing markup, not new.
- `TestStoredLabelsAndCriteria` asserts file content only (no real-world units required; INTEGRATE adds those).

## Round 2 (check finding H1)

Run once: `.venv/Scripts/python -m pytest tests/test_judge_eval.py tests/test_e2e_review_judge.py` gave 142 passed. No test removed or merged, so `log.md` is unchanged.

Changed expectations (old rule: the Kev verdict never changes scores, report or exit code; superseded by AC-S5-3 and AC-S5-4 / DEC-7):

- `tests/test_judge_eval.py::TestKevMetricsInSyntheticSummary::test_existing_scores_and_gating_equal_those_of_the_same_run_without_kev_answers[lgtm, lgtm-no-sast]`: the injected `not_real` verdict on a supported candidate is replaced by a severity-only change (`critical`) on two candidates; scores, gating and summary (except `kev`) must equal the run without Kev answers. Stronger on severity, unchanged for `real`/absent verdicts. AC-S5-3.
- New `test_supported_candidate_the_kev_verdict_rules_not_real_no_longer_scores_as_detected[lgtm, lgtm-no-sast]`: the removed `not_real` data case now asserts TP becomes FN (plain run TP, TN; Kev run FN, TN; summary tp 0, fn 1, tn 1). AC-S5-3.
- `TestKevInJudgeEvalReport::test_existing_report_measures_equal_those_of_the_same_run_without_kev_answers`: comparison now excludes the Kev-derived keys `kev` and `kev_agreement` (agreement is computed from Kev answers by definition); all other report measures must still equal. Its data has no supported-but-`not_real` candidate, so no `not_real` effect is asserted there (AC-S5-2 covers `kev_agreement`).
- `tests/test_e2e_review_judge.py::test_review_report_and_exit_code_do_not_change_with_kev_verdict_and_severity` renamed `..._change_with_the_kev_verdict_only_when_it_rules_a_supported_candidate_not_real` and rebuilt with a local `_answer_with(verdict, severity)` responder over three runs: (real, low) baseline, (real, critical) must equal baseline in exit code (1), `stats.supported` (2), `[SUPPORTED]` flag, per-finding fields, keys and confidence text; (not_real, low) gives exit 0, `stats.supported` 0, no `[SUPPORTED]`, while per-finding `supported`/`judged`/confidence, keys and confidence text stay unchanged. AC-S5-3, AC-S5-4.
