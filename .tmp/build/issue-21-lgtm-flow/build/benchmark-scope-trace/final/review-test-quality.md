# Test quality review: benchmark-scope-trace (Unit, Integration)

Verdict: no High. 0 High, 3 Medium, 3 Low. Tests are mostly meaningful and discriminating; gaps are error-row scope, out_of_scope_cases, and rescore of old sqli rows.

Method: mutated a throwaway copy (src, tests, benchmark, docs) with the worktree venv, 16 single mutations over the new tests. Caught: grounded_only.overall and by() counting out rows, no-sast scope ignoring category, SQL count including authz, run_records tool_calls dropped, real-world run_records dropped, same-category counted as off-category, off-category ids replaced, README and proposal exclusion sentence removed, postgraas scope flag removed. Survived: M1, M2, M8, M16 below. Copy removed, worktree status clean.

## Findings

M1 Medium, fault detection (reproduced). Error rows lose scope.
- Removing `**scope_fields(result)` from `evaluate.mark_error`, or `case_scope` from `evaluate_real.error_result`, leaves all 60 selected tests green.
- Consequence: an errored out-of-scope sqli row (alerta, postgraas_safe, or any no-sast sqli row) lacks `scope`, reads as "in", and enters headline metrics. CT-benchmark-scope-trace-1 says every per-case result keeps scope.
- Fix: unit test that `mark_error` on a sqli lgtm-no-sast row has scope "out" and off_category == []. Add a real-world test with `error_result` or a failing `run_unit` for `alerta_sqli_safe` that asserts scope "out".

M2 Medium, coverage (reproduced). `out_of_scope_cases` is untested.
- Setting it to `[]` passes everything. benchmark/README.md documents it.
- Fix: in `test_headline_counts_only_in_scope_rows`, assert `summary["out_of_scope_cases"] == ["out_sql", "out_sql_safe"]`.

M3 Medium, coverage. AC-S7-3 rescore test does not exercise a changed-by-scope case.
- The old fixture rows are authz and the first is lgtm-no-sast authz, so "in" is the same before and after the change.
- Untested: `--rescore` of a pre-change lgtm-no-sast sqli row now becomes "out" and leaves the headline.
- Fix: add an old no-sast sqli row and a case_scope-absent row. Assert it is listed under `out_of_scope_cases` and excluded from overall.
- If rescoring old results must keep their old headline, that decision is unspecified. Resolve before asserting either way.

L1 Low, independence. Docs tests are loose keyword checks.
- The benchmark/README "why" (M16 removal) passes.
- The scope test only needs "out of scope" anywhere in the doc, plus the words semgrep, sql injection and authz. It does not check that the exclusion sits next to the two jobs.
- Acceptable for prose. The "why" for each out-of-scope entry in AC-S4-2 is unverified.

L2 Low, independence. Misnamed real-world scope test.
- `test_sql_case_without_in_diff_semgrep_warning_is_out_of_scope` and the "with warning" in-scope test imply the Semgrep count drives scope. Production uses the `cases.json` `scope` flag, and the metadata count is ignored.
- Rename to `..._flagged_out_in_cases_json_...`, or assert that the count is ignored.
- Nothing ties the flag to actual Semgrep behavior on those cases. That check is DEC-9 deferred (real fetch).

L3 Low, coverage. Off-category and run-record edge cases.
- Judged-mode findings with `supported` false are not listed (residual question noted in check-2, a decision needed).
- Not covered: finding without `finding_id` ("unknown"), empty or absent `run_records` (reviews from older code or sast-only modes), `run_records` on the real-world error path.
- AC-S4-6 for `evaluate.py` CLI (new keys written by `main`) is covered only through `evaluate_case`. Real-world `main` is covered.

## Per-criterion mapping
- AC-S4-1: tested (README and proposal parametrized). Loose.
- AC-S4-2: tested, loose (see L1).
- AC-S4-3: tested (flag removal caught; headline exclusion via `write_dir_summary`). Error row gap (M1).
- AC-S4-4: tested (score_case, summarize, real-world run_unit; no-sast sqli out, authz in).
- AC-S4-5: tested, with key-name search `semgrep` and `sql`. This is loose, not tied to the documented `sql_cases_semgrep_warns_on`. A wrong key name that still contains both words would pass.
- AC-S4-6: partial (L3).
- AC-S4-7 (Integration): real Semgrep, real git, bundled rules, temp paths, skipped if the binary is absent. Boundary is correct. Fails before the patch regeneration. Asserts at least one in-diff finding, all SQLi. Not asserted: the in-diff finding sits on the changed function (filter_to_diff guarantees this). Check-2 confirms it ran, not skipped. The skipif could silently hide the criterion on a machine without Semgrep, but check-2 reports 0 skipped.
- AC-S7-1 / AC-S2-3: tested for evaluate_case and run_unit. `RunRecord` is built by the test, so the producer (agents/base.py) is another slice's concern.
- AC-S7-2: tested (outcome unchanged FN/TN, summary lists it).
- AC-S7-3: partial (M3).

## Other checks
- Tier boundary: Unit tests mock pipeline, index, and pin; use tmp_path only (small file I/O under tmp, acceptable for existing suite style). No network. No duplication of note; parametrized cases are appropriate.
- Self-asserting: expected values are literals, not recomputed from production logic. The `_find_key` and `_flatten` helpers are test-side search, not production reproduction.
- Changed existing tests: none modified, only appended. Check-1 M1/M2 fixture fixes (judged findings, llm-only) were justified and keep intent. Using llm-only to dodge scan_failure/EXCLUDED means the lgtm-mode off-category path in `run_unit` is untested (the baselines parametrization covers `score_case` in lgtm).

## Not verified
Full suite not rerun. Real-world measurement on stored runs deferred (DEC-9). No lint or type check.
