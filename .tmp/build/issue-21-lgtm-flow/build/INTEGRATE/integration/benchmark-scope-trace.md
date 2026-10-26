# Integration intake: benchmark-scope-trace

Slice branch `build/issue-21-lgtm-flow/benchmark-scope-trace`, base `ebe9dff` (reviewer-reach head), head `efc8599` (2 commits, 14 files, +504/-30). result.json status accepted, no blockers. Survey only; no tests run, nothing fetched.

## Findings

| ID | Sev | Item |
| -- | -- | -- |
| I-1 | High | `base_commit` 7f642e1 is not an ancestor of `origin/main` (bad831d); merge-base is ae5406c. 12 upstream commits (PRs #16-#19: section/graph pipeline made default, mitigations default-on, field trial) are outside the run's lineage. Local `main` (ff110c3) is an ancestor of the base, so stale. INTEGRATE target needs confirming. |
| I-2 | High | Upstream `origin/main` deleted or rewrote what this slice's tests and Modifies rely on (see Upstream drift); merging the slice into it conflicts. |
| I-3 | Medium | `RunRecord` / `review.run_records` exist only on the reviewer-reach lineage, absent on `origin/main`. `run_record_fields` uses `getattr(..., None) or []`, so no crash, but rows hold `[]` there. |
| I-4 | Medium | Upstream `score_case`/`summarize` scoring changes overlap the slice's scope edits in evaluate.py (textually clean, semantically needs a read). |
| I-5 | Low | Slice Modifies lists `tests/test_real_world_cases.py` and `tests/test_e2e_benchmark_replay.py`; the diff touches neither. The latter is absent on `origin/main`. |
| I-6 | Low | result.json outstanding items carried (below). |

## Expected conflicts (git merge-tree; checkout untouched)

* Slice into `origin/main`: content conflicts in `tests/test_baselines.py` (slice-owned) and in reviewer-reach-lineage files carried by the slice base: `src/lgtm/agents/base.py`, `src/lgtm/cli.py`, `src/lgtm/config.py`, `src/lgtm/pipeline.py`, `tests/model_input_lock/expected.json`, `tests/test_graph_pipeline.py`, `tests/test_graph_tools.py`. `benchmark/evaluate.py`, `README.md`, `benchmark/README.md`, `tests/test_evaluate_real.py` merge textually but need a read.
* With `reviewer-reach` (its base): clean.
* With `pr-scoped-review`: clean; no shared files (it touches src/lgtm/** and tests, plus expected.json which the slice does not touch).
* With `kev-judge-measurement`: a descendant of the slice head; merge clean. It edits the same files sequentially (README.md, benchmark/README.md, evaluate.py, evaluate_real.py, cases.json, generate_cases.py, labels.json, the 3 Shoply patches, docs/project-proposal.md, test_baselines.py, test_benchmark_cases.py, test_evaluate_real.py). Keep both sides of README.md and benchmark/README.md.
* reviewer-reach and pr-scoped-review do not edit README.md or benchmark/README.md.

## Upstream drift (origin/main)

* Since merge-base ae5406c, touching slice files: README.md, benchmark/README.md, benchmark/evaluate.py, tests/test_baselines.py, tests/test_evaluate_real.py. Untouched upstream: cases.json, generate_cases.py, labels.json, the Shoply patches, evaluate_real.py, docs/project-proposal.md.
* Against 7f642e1, origin/main removes `benchmark/judge_eval.py`, `benchmark/kev_support/`, `src/lgtm/validation/judge*.py`, `tests/test_e2e_benchmark_replay.py`, `test_judge*.py`, `test_kev_*.py`, `test_e2e_*`; `evaluate_real.py` and `tests/test_evaluate_real.py` shrink heavily. The slice check command names `tests/test_e2e_benchmark_replay.py`, absent there.
* evaluate.py: upstream `score_case` scores by `predict_case_verdict`/`outcome_for`, adds `alarms_outside_target` and summary keys `alarms_outside_target(_rate)`, plus new flags (`--graph`, `--authz-planner`, mitigation toggles). The slice adds `result.update(scope_fields(result))` at the end of `score_case`, `scope_fields` (uses `finding_verdict`), and `headline` filtering in `summarize`. A merge must keep scope on every `score_case` branch, headline-only counting for overall/per_category/per_split/grounded_only, and reconcile `off_category` with upstream `off_category_alarms`/`alarms_outside_target`.
* Shoply patches and labels.json are unchanged upstream, so regenerating them is uncontested.

## Contract drift: CT-reviewer-reach-1 vs CT-benchmark-scope-trace-1

* Persisted (reviewer-reach, ebe9dff): `RunRecord` in `src/lgtm/agents/base.py` with `section`, `tool_calls`, `raw_answer`, `limit_hit` (`tool_calls` | `steps` | null); `run_records` on the pipeline review and authz reviewer.
* Consumed (slice): `asdict(r)` over `review.run_records` into per-case `run_records` (evaluate.py, evaluate_real.py); benchmark/README.md documents `raw_answer` and `limit_hit` values `tool_calls`, `steps`, `null`. No key drift against ebe9dff.
* Risk: pr-scoped-review also edits base.py and pipeline.py; re-check `RunRecord` fields after merging it. Not persisted on `origin/main` (I-3).
* kev-judge-measurement keeps `scope`, `off_category`, `run_records`, `case_scope` and changes `finding_verdict` to `supported and kev_verdict != "not_real"`; `scope_fields` calls `finding_verdict`, so off_category follows that rule. INTEGRATE.md requires scope exclusions and off-category handling to survive it.

## Artifacts to regenerate

* `benchmark/labels.json` and `benchmark/cases/sqli/case_04_safe.patch`, `case_07_safe.patch`, `case_11_safe.patch` via `python benchmark/tools/generate_cases.py` after the final merge; confirm no diff in the merged tree.
* Stale: run6-final candidate citations for sqli_04_safe, sqli_07_safe, sqli_11_safe (line shift); owned by kev-judge-measurement and INTEGRATE journey 4 (DEC-13).
* `tests/model_input_lock/expected.json`: not touched by this slice; INTEGRATE regenerates once.
* Fresh real-world output directory for scope on alerta_sqli_vulnerable, alerta_sqli_safe, postgraas_sqli_safe (DEC-14).

## Pending-integration checks

* result.json `pending_integration`: real-world stored-run measurement (DEC-9): run once into an empty directory, no `--resume` or `--summarize-only` on stored runs; failures reported, not tuned.
* result.json `needs_replan` (INTEGRATE): older tracked runs (`benchmark/runs/gpu-qwen3.8-27b/real_world/`, `benchmark/runs/real_world/`) re-summarized or resumed read the three out-of-scope cases as in. Not valid evidence for AC-S4-3 or AC-S4-5.
* Slice check: `pytest tests/test_evaluate_real.py tests/test_benchmark_cases.py tests/test_real_world_cases.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py`; AC-S4-7 needs the real Semgrep binary on the regenerated patches (`sql_cases_semgrep_warns_on`). Re-run after merge; not run in this survey.
* INTEGRATE.md: full pytest; all four evaluate.py modes; `generate_cases.py`; no new dependency (CON-2); README documents outputs (CON-3); journey 3 observes `scope`, `off_category`, `run_records` in per-case results and summary.json.

## Outstanding items carried from result.json

No test asserts scope on evaluate.py or real-world error rows (code sets it in `mark_error` and `error_result`); `--rescore` test lacks an old no-sast sqli row; non-headline rates (errors, grounding, latency) include out-of-scope rows; benchmark/README.md duplicates cases.json out-of-scope ids and has one rationale clause (delete on merge); `case_scope` duplicates `scope` on real-world results; docs tests use loose keyword checks.

## Other

* If the integration target is `origin/main` rather than a branch from base_commit, the whole run conflicts, and the Kev bench tooling kev-judge-measurement modifies does not exist there.
