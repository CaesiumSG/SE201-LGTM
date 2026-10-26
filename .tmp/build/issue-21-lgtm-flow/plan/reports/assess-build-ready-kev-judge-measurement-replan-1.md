# Build-ready assessment: kev-judge-measurement (replan 1)

Verdict: NOT build-ready. Three Medium and three Low findings; every fix is a deletion or a one-line rewrite. No finding reopens the cut.

Checked: criteria AC-S5-1..4, AC-S6-1..5 each map to one package (judge-measurement) and one tier (Unit). CT-benchmark-scope-trace-1 exists in the producer's Provides. One package, so disjointness and parallelism hold trivially. Not verified: files such as judge.py, judge_eval.py and kev_support/ are not in the current checkout (branch authz-pr); the slice builds from efc8599, so their existence was not checked. plan/repo.md is absent.

## Findings

* assess-ready-01 (Medium) DEC-13 exclusion rule has no package or tier. It appears in the header Decisions, Scope Consumes, and Rules bullets 1 and 2, but the Packages table names it nowhere and no criterion carries it. The builder cannot tell which package and tier proves it. Fix: keep the rule once, in Rules bullet 1, and add to that bullet the package judge-measurement and tier Unit. Delete the DEC-13 restatement in Consumes (see 02) and in Rules bullet 2.
* assess-ready-02 (Medium) Scope Consumes names symbols and a rendering behavior: "EvidenceValidator validate and validate_all signatures and FileDiff fields", "the grounded_in_pr rendering in report_builder.py stays as at base". Scope entries name files, not symbols. Fix: delete these two clauses. Also delete "except sqli_04_safe, sqli_07_safe and sqli_11_safe (see Rules)" from the Consumes stored-run entry (see 01), leaving the run directory.
* assess-ready-03 (Medium) The package lists "docs/ and benchmark/ (new files per Scope Creates)" as production files. These are whole directories. benchmark/ holds files owned by benchmark-scope-trace (evaluate.py, labels.json, cases/), and benchmark/runs/ is read-only here. Fix: list only the two new files, as the Creates entry does: the labeling-criteria document under docs/ and the stored label file under benchmark/. The plan cannot name them until the builder picks the names, so write "labeling-criteria document (new, docs/)" and "stored label file (new, benchmark/)". Delete the directory-wide entries.
* assess-ready-04 (Low) Rules bullet 1 closes with "Files under benchmark/runs/run6-final/ and benchmark/cases/ are not edited". The Scope already lists runs/run6-final as read only and neither path is in Modifies. Fix: delete the sentence. Also delete the parenthetical "(CT-benchmark-scope-trace-1 slice, Regenerated)".
* assess-ready-05 (Low) Rules bullet 2 restates DEC-13 and AC-S6-1/AC-S6-2, and the Packages note repeats the INTEGRATE-only split. Fix: delete Rules bullet 2. Keep only the Packages note "the real-world parts of AC-S6-1 and AC-S6-2 are INTEGRATE-only". The labels of the three excluded cases belong to INTEGRATE journey 4; that is stated by DEC-13.
* assess-ready-06 (Low) Checks: no lint or type-check line. The plan/repo.md file is absent, so whether the repository defines them could not be confirmed. The pyproject.toml in the current checkout has no ruff or mypy entry. Fix: if repo.md defines them, add one line each; otherwise nothing.

## Package and overlap review

* One package; no shared files; no needs on other packages. Pass.
* All package files fall inside Scope Modifies, Appends, Creates or Regenerated, apart from the two directory entries (03).
* tests/model_input_lock/expected.json is listed as a package test file and as Regenerated. Acceptable.
* Overlap with benchmark-scope-trace on benchmark/evaluate.py, README.md and benchmark/README.md is covered by the prerequisite path (the Appends are additive). Pass.
* Tiers: all Unit. AC-S5-4 (CLI exit code) and AC-S6-5 (label file) are provable at Unit. No retry, idempotency or concurrency criterion, so no open decision.

## Check review

* One pytest line. It overlaps no other line. The extra suites (test_baselines, test_e2e_benchmark_replay, test_graph_benchmarks) are existing suites covering evaluate.py and citation_export.py. They were not run. test_baselines and test_e2e_benchmark_replay also appear in benchmark-scope-trace's check; that is fine, as the slices run in sequence.
* No pending-integration items are needed.

## DEC-13 placement summary

The rule is stated four times (Decisions header, Consumes, Rules 1, Rules 2) and placed in no package. After fixes 01, 02 and 05 it sits once, in Rules bullet 1, under package judge-measurement, tier Unit.

Skipped: file existence at efc8599 and test content were not checked; no plan files edited.
