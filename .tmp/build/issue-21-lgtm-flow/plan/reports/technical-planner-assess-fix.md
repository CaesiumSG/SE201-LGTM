# technical-planner: assessment fixes

## Changes
- reviewer-reach: Checks keeps `pytest`; removed the pending-integration real-world line (INTEGRATE journeys 1 and 2 hold it).
- pr-scoped-review: AC-S1-3, AC-S3-3, AC-S3-6 removed from Packages; they and AC-S3-5/S3-7 and the litellm part are listed INTEGRATE-only. Live `--split dev` and real-world checks deleted (INTEGRATE journeys 2 and 3). Checks: `pytest` only.
- benchmark-scope-trace: docs and benchmark packages merged into one `benchmark` package. AC-S4-1 and AC-S4-2 are Unit with doc-assertion tests in the listed test files; benchmark/real_world/README.md dropped; Regenerated outputs removed from the Production cell (ready-08); "except the docs statements" wording and the live 3-case check deleted (ready-06, ready-07 moot).
- kev-judge-measurement: Setup section deleted (ready-09, sep-01); pytest check now adds tests/test_baselines.py, tests/test_e2e_benchmark_replay.py, tests/test_graph_benchmarks.py (ready-10); pending-integration line deleted (INTEGRATE journey 4); package cell no longer says "under docs/ / under benchmark/" with builder-chosen names (ready-11, package part).

## Why docs and benchmark merged
All five Scope test files serve the benchmark lane, Scope has no Creates, and a doc-assertion test would share a file with that lane. Packages must be disjoint, so the docs files join the one package.

## DEC-8 coverage
AC-S6-5 (Unit) demands the written criteria and stored labels that record the labeling model, so the labeling work stays demanded after Setup was deleted. No criterion states who produces the labels or that they come from the stored run6-final lgtm run; that is Scope Consumes plus DEC-8. No hand-off needed.

## Hand-offs (Scope, not mine)
- reviewer-reach Scope Modifies: delete "(records config budgets in the run pin)" (ready-01).
- pr-scoped-review Scope Modifies: delete the two parentheticals on evidence.py and git_diff.py (ready-04).
- benchmark-scope-trace Scope Resources: "model endpoint (serialize) only for the Shoply replay check" is now stale (no live check); delete it. Consumes/Resources lists benchmark/runs/ isolate remains valid.
- kev-judge-measurement Scope Creates: "(names chosen by the builder)" names no file (ready-11); Resources line duplicates Out of scope (ready-12). Architecture/run.json resource mapping should drop the model endpoint from benchmark-scope-trace and kev-judge-measurement.
- INTEGRATE.md: DEC-8 risk text names run6-final labeling; consistent. No change.
