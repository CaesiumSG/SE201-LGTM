Source: LGT-169 https://linear.app/se201-lgtm/issue/LGT-169/kev-judge-measurement-kev-verdict-and-support-are-scored-separately-on
Retrieved: 2026-10-26 (time of day not captured)

# kev-judge-measurement: Kev verdict and support are scored separately on real LGTM output

Outcome: Benchmark output reports verdict and support accuracy separately with judge-agent agreement, a supported-but-not_real candidate is not a vulnerability in scores, report, and exit code, and a judge-eval report measures Kev on model-labeled LGTM candidates under written labeling criteria.
Prerequisites: benchmark-scope-trace (CT-benchmark-scope-trace-1)
Criteria: AC-S5-1, AC-S5-2, AC-S5-3, AC-S5-4, AC-S6-1, AC-S6-2, AC-S6-3, AC-S6-4, AC-S6-5   Constraints: CON-1, CON-2, CON-3   Decisions: DEC-3, DEC-7, DEC-8, DEC-9, DEC-10, DEC-13   External: none

## Scope

| Field | Entries |
| -- | -- |
| Owns | Supported and verdict accuracy and agreement metrics; counting rule for supported-but-not_real; lgtm review exit code rule; labeling criteria, stored model labels, and judge-eval report; severity accuracy; quote-absence report for authz_10_vulnerable and authz_12_vulnerable |
| Creates | A labeling-criteria document under docs/; the stored label file under benchmark/ |
| Modifies | benchmark/judge_eval.py, benchmark/citation_export.py, benchmark/evaluate.py, benchmark/kev_support/runner.py, benchmark/kev_support/fixtures.py, src/lgtm/validation/judge.py, src/lgtm/cli.py, src/lgtm/reporting/report_builder.py; tests/test_judge_eval.py, tests/test_judge.py, tests/test_cli.py, tests/test_report.py, tests/test_e2e_judged_bench.py, tests/test_e2e_review_judge.py, tests/test_kev_support_bench.py |
| Appends | README.md (exit-code rule), benchmark/README.md |
| Regenerated | tests/model_input_lock/expected.json |
| Consumes | CT-benchmark-scope-trace-1 (scope labels and per-case results); src/lgtm/validation/cwe_criteria.py, src/lgtm/validation/judge_examples.py, src/lgtm/validation/evidence.py, and src/lgtm/pipeline.py unchanged; the Shoply candidates in the stored lgtm run under benchmark/runs/run6-final/lgtm/ |
| Resources | Kev judge HTTP server (simulate in tests); stored run benchmark/runs/run6-final/lgtm/ (read only) |
| Out of scope | The held-out rule for judge criteria and the real-world parts of the judge-eval report (INTEGRATE); improving or retraining Kev on live_shaped candidates; stabilizing severity (measurement only); reviewer behavior (earlier slices) |

## Rules

* Package judge-measurement, tier Unit (DEC-13): the stored candidates sqli_04_safe, sqli_07_safe and sqli_11_safe cite text that predates the regenerated Shoply patches of benchmark-scope-trace. The labels and the judge-eval accuracy and agreement numbers leave them out, and the report lists them as stale with that reason. Benchmark scoring and headline metrics keep these cases (AC-S4-7, DEC-11).

## Packages

| Package | Criteria (tier) | Production files | Test files |
| -- | -- | -- | -- |
| judge-measurement | AC-S5-1 (Unit), AC-S5-2 (Unit), AC-S5-3 (Unit), AC-S5-4 (Unit), AC-S6-1 (Unit), AC-S6-2 (Unit), AC-S6-3 (Unit), AC-S6-4 (Unit), AC-S6-5 (Unit) | benchmark/judge_eval.py, benchmark/citation_export.py, benchmark/evaluate.py, benchmark/kev_support/runner.py, benchmark/kev_support/fixtures.py, src/lgtm/validation/judge.py, src/lgtm/cli.py, src/lgtm/reporting/report_builder.py, README.md, benchmark/README.md, labeling-criteria document (new, docs/), stored label file (new, benchmark/) | tests/test_judge_eval.py, tests/test_judge.py, tests/test_cli.py, tests/test_report.py, tests/test_e2e_judged_bench.py, tests/test_e2e_review_judge.py, tests/test_kev_support_bench.py, tests/model_input_lock/expected.json |

AC-S6-6 is proven by INTEGRATE only (architecture, Decisions and the cut). The real-world parts of AC-S6-1 and AC-S6-2 are INTEGRATE-only; this slice proves their logic on Shoply labels and fixtures.

## Checks

* `pytest tests/test_judge_eval.py tests/test_judge.py tests/test_cli.py tests/test_report.py tests/test_e2e_judged_bench.py tests/test_e2e_review_judge.py tests/test_kev_support_bench.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py tests/test_graph_benchmarks.py tests/model_input_lock`: verdict and support metrics, counting and exit-code rule, judge-eval report, label file, the existing suites covering benchmark/evaluate.py and benchmark/citation_export.py, and the model-input lock.
