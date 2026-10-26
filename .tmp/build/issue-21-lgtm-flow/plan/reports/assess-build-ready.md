# Build-ready assessment: issue-21-lgtm-flow

Verified at base 7f642e1: every Modifies/Consumes file named in the four slices exists (including src/lgtm/validation/judge_examples.py, tests/test_e2e_*.py). Every cited CT- exists in its producer's Provides (CT-reviewer-reach-1, CT-benchmark-scope-trace-1). Concurrent slices (pr-scoped-review, benchmark-scope-trace, kev-judge-measurement) have disjoint Owns/Modifies; shared files (README.md, benchmark/README.md, expected.json, benchmark/evaluate.py) are ordered by prerequisite or Appends. Every cited criterion is in exactly one package or named INTEGRATE-only (also listed in INTEGRATE.md). Packages within each slice are disjoint. No Critical or High findings.

## reviewer-reach
Build-ready after the deletions below.

- ready-01 (Low) Over-specification: Scope Modifies line 11 holds "(records config budgets in the run pin)". Fix: delete that parenthetical.
- ready-02 (Low) Package `reach` (single package, 12 production and 9 test files) is fine as one lane; no finding beyond noting that AC-S1-4 and AC-S2-5 are Unit with a fake model, which is correct.

## pr-scoped-review
- ready-03 (Medium) Tier mismatch: AC-S3-3 and AC-S3-6 are tiered Integration (line 20) but need a live model run on Shoply dev; no package test file proves them, and the Integration tier is defined for real stores and services. They are the same journey INTEGRATE.md journey 3 already runs. Fix: mark both "INTEGRATE-only" in the scope-rule row and the line 23 list, and delete the Check on line 27 (`python benchmark/evaluate.py --mode lgtm --split dev`) or relist it as pending integration. If the plan keeps them in the slice, name the Unit fake-model tier instead.
- ready-04 (Low) Over-specification: delete the parentheticals "(grounding of cited code against added text only)" and "(removed text of a file diff)" in Modifies, line 11. They describe the approach.
- ready-05 (Low) AC-S3-2 is split between the package and INTEGRATE ("Unit; litellm part INTEGRATE"). Acceptable; no change needed.

## benchmark-scope-trace
- ready-06 (Medium) Check/tier mismatch: AC-S4-6, AC-S7-1, AC-S2-3 are Unit, covered by the listed pytest check, yet line 30 adds a live model run for them (lease llm-endpoint). INTEGRATE journey 3 already runs the same command. Fix: delete line 30, or list it as pending integration.
- ready-07 (Low) Package `docs` tier text "review in INTEGRATE" is not a tier. Fix: write "INTEGRATE-only (review)" so it reads as the INTEGRATE-only case. No file defect.
- ready-08 (Low) Package `benchmark` production-file cell "benchmark/labels.json and benchmark/cases/sqli/ (regenerated)": these are Regenerated outputs, not authored production files. Fix: delete them from the Production files cell; Scope Regenerated already holds them.

## kev-judge-measurement
- ready-09 (Medium) Setup holds work, not setup: lines 29-30 describe a labeling procedure (live run, build agent labels, records model). Setup lists only code generation, env files, database seeds, isolate start commands. It repeats DEC-8 and AC-S6-5. Fix: delete the whole `## Setup` section.
- ready-10 (Medium) Missing suites: the slice modifies benchmark/evaluate.py (and citation_export.py), but the pytest check omits the existing suites covering them (tests/test_baselines.py, tests/test_e2e_benchmark_replay.py, tests/test_graph_benchmarks.py reference the benchmark entry points). Fix: add those paths to the pytest check on line 26, or replace the check with `pytest` once.
- ready-11 (Low) Creates names no file ("names chosen by the builder"). Entries must name a file or directory. Fix: write "docs/ (labeling-criteria document)" and "benchmark/ (stored label file)" as directories only, and delete "(names chosen by the builder)" and the phrase "the labeling-criteria document under docs/, the stored label file under benchmark/" from the package cell; replace with the directories.
- ready-12 (Low) Resources line mixes defer items with Out-of-scope content; delete "real-world candidate collection and labeling (defer), per DEC-9" duplication in Setup context (covered by line 23). Minor.
