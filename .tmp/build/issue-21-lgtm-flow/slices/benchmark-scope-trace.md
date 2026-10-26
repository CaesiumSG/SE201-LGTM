Source: LGT-168 https://linear.app/se201-lgtm/issue/LGT-168/benchmark-scope-trace-documented-scope-honest-headline-numbers-and
Retrieved: 2026-10-26 (time of day not captured)

# benchmark-scope-trace: Documented scope, honest headline numbers, and explainable per-case results

Outcome: The README and benchmark docs state the two jobs of LGTM, headline metrics exclude or label out-of-scope cases and modes, the three Shoply safe SQL cases trigger Semgrep in the diff, and each per-case result keeps the section runs, limit hits, and off-category findings.
Prerequisites: reviewer-reach (CT-reviewer-reach-1)
Criteria: AC-S4-1, AC-S4-2, AC-S4-3, AC-S4-4, AC-S4-5, AC-S4-6, AC-S4-7, AC-S7-1, AC-S7-2, AC-S7-3, AC-S2-3   Constraints: CON-1, CON-2, CON-3   Decisions: DEC-3, DEC-9, DEC-10, DEC-11, DEC-12   External: none

## Scope

| Field | Entries |
| -- | -- |
| Owns | Scope statements in README.md, docs/project-proposal.md (DEC-12), and benchmark/README.md; out-of-scope case and mode handling in metrics; Semgrep-warning count in the real-world summary; Semgrep-visible Shoply safe SQL cases; per-case section runs and limit-hit statement; off-category listing; --rescore on older results |
| Modifies | benchmark/evaluate.py, benchmark/real_world/evaluate_real.py, benchmark/real_world/cases.json, benchmark/tools/generate_cases.py, README.md, docs/project-proposal.md, benchmark/README.md; tests/test_evaluate_real.py, tests/test_benchmark_cases.py, tests/test_real_world_cases.py, tests/test_baselines.py, tests/test_e2e_benchmark_replay.py |
| Regenerated | benchmark/labels.json and the Shoply patches under benchmark/cases/sqli/ (produced by benchmark/tools/generate_cases.py) |
| Consumes | CT-reviewer-reach-1; the per-case result and summary.json formats at the base commit |
| Resources | benchmark/runs/ outputs (isolate); Semgrep binary (isolate) for AC-S4-7; real-world fetch and runs (defer), per DEC-9 |
| Out of scope | Reviewer behavior (reviewer-reach, pr-scoped-review); Kev verdict and support scoring and judge metrics (kev-judge-measurement) |

## Provides

### CT-benchmark-scope-trace-1 Scope-labelled case results

Consumers: kev-judge-measurement
Every per-case result and every summary.json produced by benchmark/evaluate.py and benchmark/real_world/evaluate_real.py keeps all keys written at the base commit and adds scope (the string "in" or "out" per case) and off_category (list of finding ids). Headline metrics, defined as summary.json overall, grounded_only.overall, per_category, and per_split, count only cases with scope "in". Other summary counts (errors, rates, latency, tokens) include all rows. A result written before this slice has no scope key and reads as "in", even where AC-S4-3 would now score it "out". The slice adds run_records (per-case), out_of_scope_cases (summary), sql_cases_semgrep_warns_on (real-world summary), and case_scope (real-world per-case, the input to scope).

## Packages

| Package | Criteria (tier) | Production files | Test files |
| -- | -- | -- | -- |
| benchmark | AC-S4-1 (Unit), AC-S4-2 (Unit), AC-S4-3 (Unit), AC-S4-4 (Unit), AC-S4-5 (Unit), AC-S4-6 (Unit), AC-S4-7 (Integration), AC-S7-1 (Unit), AC-S7-2 (Unit), AC-S7-3 (Unit), AC-S2-3 (Unit) | README.md, docs/project-proposal.md, benchmark/README.md, benchmark/evaluate.py, benchmark/real_world/evaluate_real.py, benchmark/real_world/cases.json, benchmark/tools/generate_cases.py | tests/test_evaluate_real.py, tests/test_benchmark_cases.py, tests/test_real_world_cases.py, tests/test_baselines.py, tests/test_e2e_benchmark_replay.py |

## Checks

* `pytest tests/test_evaluate_real.py tests/test_benchmark_cases.py tests/test_real_world_cases.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py`: all criteria, including the doc statements of AC-S4-1 and AC-S4-2; AC-S4-7 runs the real Semgrep binary on the regenerated Shoply patches.
