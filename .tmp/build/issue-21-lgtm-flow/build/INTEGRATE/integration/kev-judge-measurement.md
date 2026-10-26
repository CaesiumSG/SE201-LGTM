# Integration intake: kev-judge-measurement

Slice branch build/issue-21-lgtm-flow/kev-judge-measurement, base efc8599 (= head of benchmark-scope-trace), head 41560a0. Run base_commit 7f642e1. Read-only survey; no tests or live Kev server run.

## Verdict
ACTION: 0 Critical, 2 High, 4 Medium, 3 Low.

## Findings

### H1 High: slice diff is far smaller than the slice file's Modifies list
Diff efc8599..41560a0 touches 12 files: README.md, benchmark/README.md, benchmark/evaluate.py (1 line), benchmark/judge_eval.py, benchmark/kev_model_labels.json (new), docs/kev-labeling-criteria.md (new), src/lgtm/cli.py, src/lgtm/reporting/report_builder.py, tests/test_cli.py, test_e2e_review_judge.py, test_judge_eval.py, test_report.py.
Listed in Modifies/package but unchanged: benchmark/citation_export.py, benchmark/kev_support/runner.py, benchmark/kev_support/fixtures.py, src/lgtm/validation/judge.py, tests/test_judge.py, test_e2e_judged_bench.py, test_kev_support_bench.py, and tests/model_input_lock/expected.json (Regenerated; INTEGRATE does it).
Consequence: the verdict/support metrics, agreement, severity accuracy and quote-absence report (AC-S5-1..4, AC-S6-x) must live entirely in judge_eval.py. Confirm each criterion is met there; evaluate.py only gained the not_real rule. The runner calls below are the base ones, not slice code.

### H2 High: supported-but-not_real is not applied everywhere in benchmark scoring
Only `finding_verdict` (benchmark/evaluate.py:321) got the rule. Still counting not_real as supported: evaluate.py:550 (`grounded` list), evaluate.py:691 (`grounded` count in summarize), benchmark/real_world/evaluate_real.py:284 (`grounded`). Lines 343 and 403 go through finding_verdict and are consistent. Outstanding final-03 (`safe_case_acceptance` counts not_real as accepted, against DEC-7) and structure M1 (rule written three times: cli.py, report_builder.py, evaluate.py) are the same gap. Fix in INTEGRATE with one shared "supported and verdict != not_real" predicate used by those sites and judge_eval.

### M1 Medium: evaluate.py rule vs benchmark-scope-trace
Compatible. The one-line change is inside `finding_verdict`, which scope-trace's `scope_fields` calls for `off_category`. Scope exclusion (`scope`, `out_of_scope_cases`, `headline` filter) is untouched. Side effect: a not_real off-category finding no longer lands in `off_category` on judged rows (intended). merge-tree slice vs benchmark-scope-trace: clean. Keep after merge: `headline = [... scope == "in"]`, `scope_fields`, `run_record_fields`. Add a test that a not_real finding on an out-of-scope sqli row stays excluded from headline and off_category.

### M2 Medium: runner.py calls into EvidenceValidator, compared with pr-scoped-review evidence.py (no drift)
Calls in benchmark/kev_support/runner.py:
- `EvidenceValidator(repo, "HEAD")` (runner.py:51, :189): ctor (repo, base_ref, diffs=None, config=None, *, shas=None) unchanged in signature; pr-scoped-review adds only `self._diff_removed`. Matches.
- `validator._validate_policy_item(item)` (runner.py:54): present, same signature (line 266 vs base 264). Matches.
- `validator._validate_code_item(item)` (runner.py:54): present, same signature (line 204 vs base 202). Matches.
- `validators[repo].read_cited_code` (runner.py:197, passed as callable to build_judge_request): present at line 301, same signature. Matches.
pr-scoped-review changes `_grounds_pr` (also accepts snippets found in removed text) and ctor state. The runner passes no diffs, so `_diff_removed` is empty and `_grounds_pr` is not reached. validate/validate_all signatures unchanged (lines 320/327). Run tests/test_kev_support_bench.py after the merge anyway.

### M3 Medium: origin/main is a different lineage with overlapping edits
Local main (ff110c3) is an ancestor of base 7f642e1, so local main has no commits since base. origin/main (bad831d, not fetched) is ahead of main but does not contain base. main..origin/main changes overlapping files: README.md, benchmark/README.md, benchmark/evaluate.py (+658), benchmark/real_world/evaluate_real.py, src/lgtm/cli.py, src/lgtm/reporting/report_builder.py, src/lgtm/validation/evidence.py (+108), tests/test_cli.py, test_report.py, test_graph_evidence.py. `git merge-tree origin/main slice` conflicts: src/lgtm/agents/base.py, cli.py, config.py, pipeline.py, tests/model_input_lock/expected.json, tests/test_baselines.py, test_graph_pipeline.py, test_graph_tools.py. The cli.py conflict is the click options block and signature (origin/main's `--graph`, `--authz-planner`, tri-state strip/detect flags vs the branch's `--judge-endpoint/--judge-model/--judge-timeout` and boolean flags), not the slice's exit-code hunk. Most of these conflicts predate this slice. If the integration branch must land on origin/main, keep both flag sets and re-check the supported-count hunk (cli.py:131-134), `_support_label`, and `finding_verdict` against origin/main's versions. origin/main's evidence.py has no `read_cited_code`, which runner.py needs.

### M4 Medium: pr-scoped-review overlap
merge-tree slice vs pr-scoped-review: clean. Shared file: tests/test_report.py (pr-scoped-review 2-line change, slice +26). The slice does not edit evidence.py or git_diff.py. The surfaces INTEGRATE names: report_builder.py `grounded_in_pr` rendering untouched (slice edits only label, emoji, stats, suggested-fix gating); validate/validate_all signatures unchanged; FileDiff fields unchanged by the slice (pr-scoped-review uses `removed_text`). Regression targets: tests/test_kev_confidence.py, test_pipeline_request_format.py, test_judge.py, test_kev_support_bench.py.

### L1 Low: README.md and benchmark/README.md
Slice edits the exit-code paragraph in README.md and adds 23 lines to benchmark/README.md; benchmark-scope-trace edits both too (slice is built on it; clean). Keep both sides on any further merge. The cli.py `Exit codes:` docstring changed as well; keep it consistent with README.

### L2 Low: not_real visibility
report.json stats gain `not_real`, but per-finding `kev_verdict` is omitted (SEC-1), so an exit-1 suppression cannot be audited from the JSON. The cli.py guard also drops baseline vulnerable findings that carry not_real (SEC-2).

### L3 Low: labeling judgment
Manager-gated authz listing/bulk claims are labeled not_real without manager-visibility policy text (result.json outstanding). DEC-8/DEC-10 pending approval.

## Artifacts to regenerate
- tests/model_input_lock/expected.json: not regenerated by this slice; regenerate once after the final merge (conflicts in every slice and in the origin/main merge-tree).
- benchmark/kev_model_labels.json and the judge-eval report: labels cover benchmark/runs/run6-final/lgtm/ (read only); journey 4 relabels integrated output. sqli_04_safe, sqli_07_safe, sqli_11_safe are stale after scope-trace's regenerated patches (DEC-13).

## Contract drift
- CT-benchmark-scope-trace-1: evaluate.py edit does not alter persisted keys. Confirm judge_eval.py reads the keys scope-trace writes (`scope`, `case_scope`, `off_category`, `run_records`).
- final-01: run6-final records lack `mode`, so live rejudge in judge_eval.py skips them (Kev measures n=0) until it defaults to `lgtm`. Fix before journey 4.
- final-02: 7 of 8 undetermined units (sqli_*/2.0) likely fail only an exact quote match; relabel and loosen the criteria sentence in docs/kev-labeling-criteria.md.
- Slice "Consumes ... unchanged": judge.py, cwe_criteria.py unchanged by every branch surveyed; evidence.py and pipeline.py are changed by pr-scoped-review (no drift for runner, see M2).
- Untracked src/lgtm/validation/judge_examples.py in the primary checkout is on no slice branch; keep it out of the merge.

## Pending-integration checks
From result.json: real-world parts of AC-S6-1 and AC-S6-2, and AC-S6-6 (INTEGRATE only); regenerate expected.json after the final merge.
From the slice file, run after merge: pytest tests/test_judge_eval.py tests/test_judge.py tests/test_cli.py tests/test_report.py tests/test_e2e_judged_bench.py tests/test_e2e_review_judge.py tests/test_kev_support_bench.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py tests/test_graph_benchmarks.py tests/model_input_lock; plus tests/test_kev_confidence.py and tests/test_pipeline_request_format.py.
Test gaps to add (result.json): quote_absence edge cases, report not_real count and fix suppression, stale handling through report().

## Merge needs
- Merge after benchmark-scope-trace (already its base); pr-scoped-review in either order, no conflict.
- Add the shared not_real predicate (H2).
- No pyproject.toml or requirements.txt change in the slice diff (CON-2).
