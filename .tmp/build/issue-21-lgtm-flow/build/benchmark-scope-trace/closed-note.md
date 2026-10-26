Build closed: accepted

Branch: build/issue-21-lgtm-flow/benchmark-scope-trace
Head: efc85996e400c09c124cfa9366f58da9b3298214
Base: ebe9dff9d5970a5678eb5f721230a33d0eee1d0c (reviewer-reach head)

Summary: The README, docs/project-proposal.md and benchmark/README.md now state LGTM's two jobs and that other vulnerability classes are out of scope. Every per-case result and summary.json carries `scope` and `off_category`, and headline metrics count only in-scope cases. The three Shoply safe SQL cases now trigger Semgrep in the diff, and per-case results keep their section run records and limit hits.

Tests and review evidence:
- Slice checks: pytest tests/test_evaluate_real.py tests/test_benchmark_cases.py tests/test_real_world_cases.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py, 634 passed, 0 skipped. AC-S4-7 ran against the real Semgrep binary. Another 470 tests in related modules passed.
- Lens reviews (behavior, test quality, common sense, structure): no Critical or High findings. One Medium test gap was repaired.
- Final review: clean, with 2 Medium findings deferred.

Plan correction (approved): the CT-benchmark-scope-trace-1 wording now defines headline metrics (overall, grounded_only.overall, per_category, per_split). It says other summary counts include all rows, that a result with no `scope` reads "in", and it lists the added keys run_records, out_of_scope_cases, sql_cases_semgrep_warns_on and case_scope.

needs_replan:
- kev-judge-measurement: the regenerated Shoply safe patches (sqli_04/07/11_safe) shift the lines cited by the run6-final candidates it reads.
- INTEGRATE: re-summarizing or resuming older tracked real-world runs (for example gpu-qwen3.8-27b/real_world/lgtm) still counts alerta_sqli_vulnerable, alerta_sqli_safe and postgraas_sqli_safe as "in". This needs a cases.json-based scope on rescore or a fresh run.

Outstanding (Medium and Low):
- Error rows and real-world error rows have no test asserting `scope`.
- The --rescore test does not cover an old no-sast sqli row.
- Non-headline rates include out-of-scope rows.
- benchmark/README.md duplicates the case id list from cases.json and has one rationale clause.
- `case_scope` duplicates `scope`.
- The docs tests use loose keyword checks.
