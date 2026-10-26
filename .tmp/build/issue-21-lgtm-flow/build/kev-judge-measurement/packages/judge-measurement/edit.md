# judge-measurement: edit report (rounds 1 and 2)

Nothing was run or verified.

## Files (worktree .tmp/build/issue-21-lgtm-flow/worktrees/kev-judge-measurement)

- benchmark/evaluate.py: `finding_verdict` is "vulnerable" only if `supported` and `kev_verdict != "not_real"`.
- benchmark/judge_eval.py: `kev_accuracy`, `kev_agreement`, `stale_candidates`, `label_summary`, `supported_by_kind`, `safe_case_acceptance`, `quote_absence`; `run_outcomes` adds `agent_verdict`; `report` adds `kev_accuracy`, `kev_agreement`, `labels`, `supported_by_kind`, `safe_case_acceptance`, `stale`, `quote_absence`. New optional `read_pr_file` argument of `report`; default reader builds the case repo from `benchmark/labels.json` `patch_file` and reads `pr:<file>`.
- src/lgtm/cli.py: `not_real` finding does not count as supported for exit 1.
- src/lgtm/reporting/report_builder.py: supported + `not_real` is labelled "not real", excluded from `stats.supported`, counted in `stats.not_real`, no suggested fix.
- README.md, benchmark/README.md: exit-code rule, metric and label documentation.
- docs/kev-labeling-criteria.md (new).
- benchmark/kev_model_labels.json (new): 73 units, all `origin: shoply`, `kind: live_shaped`, labeling_model `claude-sonnet-5-5`. Covers every code evidence item of every finding in benchmark/runs/run6-final/lgtm/ (authz_01..06, sqli_01..12, safe and vulnerable) except sqli_04_safe, sqli_07_safe, sqli_11_safe (DEC-13, stale, reported by `stale`).
- Not edited: benchmark/citation_export.py, benchmark/kev_support/runner.py, benchmark/kev_support/fixtures.py (no change needed by the tests).

## Labeling limits (round 2)

- The stored run records no `supported` or Kev answers per finding, only agent claim, cited code and policy text. Labels come from the claim, the cited quote and the case's known vulnerable/safe status.
- Findings with several code items (authz_03_safe f0, sqli_09_safe f0/f1, sqli_12_safe f0/f1) give every code item of the finding the finding's label; the items were not judged individually.
- Candidates whose quote was not read in full, labeled from the claim and case status: sqli_05_safe/1.0, sqli_06_safe/0.0, sqli_08_safe/0.0 (claim of whitelist validation not checked against code). Please review.
- Severity set only on `real` units: critical authz_03_vulnerable, medium authz_06_vulnerable, high elsewhere.
- authz_10_vulnerable and authz_12_vulnerable are not in run6-final; `quote_absence` is empty for this run and needs a run containing them. Their patches are not in the worktree's benchmark/labels.json cases directory listing (labels.json names them; patch files not found by glob in the worktree).

## Open items

- benchmark/README_append.tmp (content "x") is a stray file I created; I cannot delete it (no shell, Write only overwrites). Recorder must delete it.
- Real-world labels are INTEGRATE's.
