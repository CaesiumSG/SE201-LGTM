# Behavior review: benchmark-scope-trace (inspected; no runs, no tmp folder created)

Verdict: no High or Medium findings. 2 Low.

## Verified
- CT-benchmark-scope-trace-1: score_case and mark_error both add `scope` and `off_category`, so evaluate_case, error paths, --rescore and real-world run_unit/error_result all write them. Old keys are unchanged; new summary keys are `out_of_scope_cases` and `off_category`. A row without `scope` reads "in" (summarize `.get("scope","in")`).
- AC-S4-3/S4-4: lgtm-no-sast sqli and cases.json `scope: out` (alerta x2, postgraas_safe) become scope "out" and are excluded from overall, per_category, per_split and grounded_only. The mode still runs. Authz rows stay "in".
- AC-S4-5: `sql_cases_semgrep_warns_on` is also written in the no-results branch (value 0).
- AC-S7-2: off-category is derived by the same helper for the case result and the summary; the outcome is untouched. AC-S7-1/S2-3: `run_records` added on both write paths (evaluate_case, run_unit).
- AC-S7-3: --rescore recomputes scope from `mode`/`case_scope`; no new required input. Old no-sast results carry `mode`, so they get "out" correctly.
- AC-S4-7: the three Shoply patches use a constant-interpolated query; the check-2 report shows the real Semgrep test ran and passed (634 passed).

## Findings
1. Low (inspected), benchmark/evaluate.py summarize: scope filtering applies only to the four metric blocks. `scored`, `errors`, `error_rate`, `off_category_alarm_rate`, `off_category_alarms`, `evidence_grounding_rate`, `possible_rate`, median latency and tokens, `case_labels` and `graph_states` still include out rows. For lgtm-no-sast, the alarm and error rates therefore mix in SQL rows the story calls out of scope. CT says only "headline metrics"; this is not a defect if those are not headline. Decision needed. If they are headline, compute them from `headline`.
2. Low (inspected), real_world/evaluate_real.py: the real-world scope comes from `case_scope`, which is stored only in new results. `--summarize-only` on real-world dirs written before this slice never re-reads cases.json, so alerta and postgraas rows stay "in" and count in the headline until the cases are re-run. The CT says an old result reads "in", so this is compatible. Anyone comparing old and new real-world summaries must know the numbers differ. Smallest fix if wanted: in write_dir_summary, fill a missing `case_scope` from cases.json.

## Residual question (from check-2)
Judged-mode findings that are unsupported are not listed as off-category (finding_verdict with judged row). This matches the prior behavior of off_category_alarms; it is not a regression.

## Consumer note (kev-judge-measurement)
The CT keys are present on every write path. The consumer must read `scope` with a default "in" for old rows. `off_category` is a list of finding ids, with "unknown" for a finding without an id.

Coverage: read the diff, the slice, the stories and decisions, and the check reports. The tests were not re-run; I relied on check-2. Cleanup: nothing created.
