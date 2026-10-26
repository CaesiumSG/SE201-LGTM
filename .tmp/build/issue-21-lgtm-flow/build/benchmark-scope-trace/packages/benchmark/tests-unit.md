# benchmark: Unit tests

Tier Unit. Files changed (appended classes/tests only): tests/test_baselines.py, tests/test_evaluate_real.py, tests/test_benchmark_cases.py. tests/test_real_world_cases.py and tests/test_e2e_benchmark_replay.py unchanged (no behavior of this tier needed them). AC-S4-7 not written (Integration).

## Coverage
- AC-S4-1/S4-2 (docs): test_benchmark_cases.py::test_scope_statement_names_both_jobs_and_the_exclusions[README|project-proposal], ::test_benchmark_readme_lists_out_of_scope_cases_and_modes. Loose keyword assertions (semgrep, sql injection, authz|authorization, "out of scope"; alerta_sqli, postgraas_sqli_safe, lgtm-no-sast).
- AC-S4-3: test_evaluate_real.py::TestScopeAndTraceOnRealWorldRecords (alerta_sqli pair, postgraas_sqli_safe scope "out" via run_unit with 0 in-diff Semgrep findings in sast-only/llm-only/lgtm; in-scope controls pyload/postgraas_vulnerable/aegra); headline exclusion via write_dir_summary.
- AC-S4-4: test_baselines.py::TestScopeInCaseResults (score_case/summarize); real-world run_unit lgtm-no-sast sqli out, authz in, mode still produces a non-ERROR result.
- AC-S4-5: ::test_summary_reports_how_many_sql_cases_semgrep_warns_on (key with "semgrep" and "sql" in name, value 2).
- AC-S4-6: real-world main writes case JSON + summary.json with existing keys (passes). evaluate.py commands: skipped, covered by test_baselines.py::TestResume and test_benchmark_* CLI tests.
- AC-S7-1, AC-S2-3: TestRunRecordsInCaseResults (evaluate_case) and real-world run_unit test: per-section tool_calls, raw_answer, limit_hit (tool_calls, steps, null) with section id; JSON plain objects.
- AC-S7-2: TestOffCategoryFindings + real-world off-category test: off_category lists finding ids, outcome unchanged, summary lists it.
- AC-S7-3: TestRescoreOfResultsWrittenBeforeScope (rows without scope rescore, count as in).
- CT-benchmark-scope-trace-1: scope "in"/"out", off_category, additive keys, absent scope reads as "in".

## Assumed interface (not fixed by plan)
- Case result keys: `scope`, `off_category` (list of `finding_id`), `run_records` (list of dicts section/tool_calls/raw_answer/limit_hit, from ReviewResult.run_records).
- Scope rule: category sqli AND (mode lgtm-no-sast OR semgrep_findings_in_diff == 0) -> "out". Real-world tests drive it through run_unit with fake meta, so a cases.json-flag implementation passes only if it agrees on those ids.
- Summary off_category and the SQL Semgrep count are found by key search (`off_category`; key containing "semgrep" and "sql"), not by fixed path.
- Headline = summary.overall, grounded_only.overall, per_category counting only scope in.

## Run (tests-only selection, -k "Scope or OffCategory or RunRecords or scope_statement or out_of_scope")
Command: `.venv/Scripts/python.exe -m pytest tests/test_baselines.py tests/test_evaluate_real.py tests/test_benchmark_cases.py -k ...`
Result: 37 failed, 8 passed (ran more than once: first run exposed one fixture mistake, fixed, rerun).
- Fail, behavior absent: all 37 (KeyError 'scope'/'off_category'/'run_records', headline counts 4 not 2, SQL count missing, docs lack out-of-scope statement).
- Pass, existing coverage: test_out_of_scope_row_keeps_its_own_outcome, test_result_without_scope_key_counts_as_in_scope, test_off_category_finding_does_not_change_the_outcome (outcome logic already ignores other-category findings), TestRunRecordsInCaseResults::test_existing_keys_are_kept, TestRescoreOfResultsWrittenBeforeScope (rescore already works), real-world main writes results/summary. 2 matched `-k` incidental tests in TestNewAuthzPairLocationExtent also passed (unrelated).

## Hand-offs / skipped
- AC-S4-7: Integration tier, separate call.
- Real-world measurement of AC-S4-3/S4-5 on stored runs: INTEGRATE (DEC-9).
- No lint, type check, or other suites run.

## Fix of check findings M1, M2
- M1 (test_evaluate_real.py): the fake finding now carries `supported` and `judged`, so a judged-mode "vulnerable" finding counts as vulnerable. The off-category test runs in llm-only because the fake lgtm review has no coverage and would score scan_failure/EXCLUDED, which hides the outcome assertion. Intent kept: off_category lists `sqli:9`, outcome stays TN.
- M2 (test_baselines.py): row "a" gets an own-category safe finding (`authz:2`), so it scores TN and the summary assertion tn == 1 holds.
- Run once: the two tests, worktree venv: 2 passed (the worktree production code now supports off_category; the tests are green, not red).
