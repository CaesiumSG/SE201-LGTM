# Final review: benchmark-scope-trace (ebe9dff..efc8599)

Verdict: APPROVE (CLEAN). Critical 0, High 0, Medium 2, Low dropped.

## Acceptance criteria checked
- AC-S4-1: met. The scope statement is in README.md and docs/project-proposal.md (DEC-12).
- AC-S4-2: met. benchmark/README.md "Scope" lists the lgtm-no-sast sqli rows and the three real-world cases, each with a reason.
- AC-S4-3: met for new results (cases.json scope out becomes case_scope, then scope "out", and the rows leave every headline block). Not met when an older stored real-world run is re-summarized (final-01). The real-world part belongs to INTEGRATE.
- AC-S4-4: met. Reproduced by rescoring a copy of the stored Shoply run with mode lgtm-no-sast: all 24 sqli rows are "out", overall counts 12 authz rows, and the mode still runs.
- AC-S4-5: met (sql_cases_semgrep_warns_on). Re-summarizing the stored gpu-qwen3.8-27b real_world/lgtm run gives 3, which matches the three in-scope sqli rows.
- AC-S4-6: met. A rescore and a write_dir_summary on stored runs drop no summary keys from the base commit. CLI argument parsing is unchanged.
- AC-S4-7: met. The patches use constant percent-format or f-string interpolation. Check-2 ran the real Semgrep test with 0 skips. Side effect: final-02.
- AC-S7-1, AC-S2-3: met on success paths. run_records is asdict(RunRecord), which holds section, tool_calls, raw_answer and limit_hit.
- AC-S7-2: met. The outcome is untouched, and the case result and summary list the output of the same helper.
- AC-S7-3: met. Reproduced by running rescore on a copy of benchmark/runs/run6-final/lgtm: it succeeds and F1 is unchanged (0.944).
- CT-benchmark-scope-trace-1: honored. scope and off_category appear on every write path (score_case, mark_error, real-world error_result). A row with no scope reads "in". The keys kev-judge-measurement needs are present.

## Findings

### final-01 Medium (reproduced): re-summarizing an older real-world run counts the out-of-scope cases as "in"
- Location: benchmark/real_world/evaluate_real.py write_dir_summary, and its --summarize-only and --resume paths.
- Trigger: write_dir_summary on a copy of benchmark/runs/gpu-qwen3.8-27b/real_world/lgtm, which is the tracked stored run.
- Expected (AC-S4-3): alerta_sqli pair and postgraas_sqli_safe have scope "out" and are left out of the headline.
- Actual: out_of_scope_cases is empty, and overall still counts 12 cases. Rows without case_scope read "in", which is what the CT literally specifies. A --resume run that mixes old and new rows behaves the same way.
- Relation to lens findings: behavior L2 and structure L2 raised this as Low. It is Medium here for two reasons. The stored real-world runs are tracked in the repo. DEC-9 defers real-world runs, so INTEGRATE may re-summarize them instead of re-running.
- Smallest correction: in write_dir_summary, before summarizing, fill a missing case_scope from cases.json by id. In evaluate.rescore, do the same from the scope field of the case. Otherwise INTEGRATE must re-run, not re-summarize.
- Recommendation: resolve now (about 3 lines plus one test), or defer with an explicit INTEGRATE note.

### final-02 Medium (reproduced): the regenerated Shoply safe patches shift code under candidates stored in run6-final
- Location: benchmark/cases/sqli/case_04_safe.patch, case_07_safe.patch, case_11_safe.patch, read through benchmark/citation_export.py _read_lines and benchmark/judge_eval.py perturb_case and build_case_repo.
- Trigger: build the PR repo for sqli_04_safe from the old patch and from the new patch, then read app/routes/admin.py lines 47-53. Those are the lines the stored finding in run6-final/lgtm/sqli_04_safe.json cites.
- Expected: kev-judge-measurement consumes "the Shoply candidates in the stored lgtm run under benchmark/runs/run6-final/lgtm/". The exported unit code should be what the agent saw.
- Actual: the lines are shifted by one (the new constant line table = "audit_log" is inserted). The quoted cursor.execute call with the literal DELETE FROM audit_log text no longer exists in the PR file.
- Effect on kev-judge-measurement: units from sqli_04/07/11_safe in run6-final would export mismatched code. The perturbation twins of the vulnerable cases also change. This artificially creates the "quoted lines absent" condition that AC-S6-3 studies.
- Not a defect against this slice: AC-S4-7 and DEC-11 require the patch change.
- Recommendation: defer to kev-judge-measurement as a needs-replan item (below).

### Unresolved lens items (not re-raised)
- test-quality M1 and M3: still open. M1 is that error-row scope is untested. M3 is that rescore of an old no-sast sqli row is untested. I reproduced the M3 behavior manually and it is correct. Defer both, or fold M3 into the final-01 test.

## Plan check
- Contradiction: AC-S4-3 says the alerta and postgraas cases are reported "out". The CT says a pre-slice result "reads as in". For the tracked real-world runs these cannot both hold (final-01).
- Gap: "headline metrics" is undefined. Rows marked out still count in errors, error_rate, off_category_alarm_rate, evidence_grounding_rate, latency, tokens and case_labels. This is behavior L1 and is acceptable under the CT wording. The plan should say so.
- Gap: no plan text names the effect of regenerating the Shoply patches on stored runs or on the inputs of kev-judge-measurement (final-02).

### minor corrections (slices/benchmark-scope-trace.md)
1. Provides, CT-benchmark-scope-trace-1.
   - Before: Headline metrics in summary.json count only cases with scope "in". A result written before this slice has no scope key and reads as "in".
   - After: Headline metrics in summary.json (overall, per_category, per_split, and grounded_only) count only cases with scope "in". Other summary counts (errors, rates, latency, tokens) include all rows. A result written before this slice has no scope key and reads as "in". Rescoring and re-summarizing apply the per-case scope from benchmark/real_world/cases.json and the mode rule.
   - If final-01 is deferred, drop the last sentence and add the INTEGRATE note instead.
   - Reason: defines "headline" and removes the contradiction with AC-S4-3.
2. Decisions or External contracts: add this entry: summary.json adds out_of_scope_cases (list of ids) and off_category (case id to finding ids); real-world results carry case_scope copied from cases.json; real-world summary.json adds sql_cases_semgrep_warns_on.
   - Reason: these keys were built but are not in the CT.

### needs-replan (other slices)
- kev-judge-measurement (Consumes): the run6-final/lgtm candidates for sqli_04_safe, sqli_07_safe and sqli_11_safe were produced against the pre-slice patches.
  - Exact change: add to Consumes or Constraints: Candidates from these three cases are rebuilt from the patches at the pin commit of the run, or excluded from labels and accuracy. Perturbation twins for sqli_04/07/11_vulnerable use the current safe patches.
  - Slices touched: kev-judge-measurement, INTEGRATE.
- INTEGRATE: if final-01 is deferred, real-world headline numbers must come from a fresh run, or re-summarizing must fill case_scope. Re-summarizing the stored gpu-qwen3.8-27b runs as they are includes the out-of-scope cases.

## Coverage
- Axes inspected: correctness (scope rule across every mode and category, error paths, rescore, summarize-only, resume), contract keys, tests as evidence (relied on the test-quality mutation results), architecture (single scope helper in evaluate.py, dependency direction unchanged), security (no trust-boundary change), performance (scope_fields recomputed per row is negligible), dependencies (stdlib asdict only, no lockfile change).
- Runs: throwaway scripts on copies of the tracked stored runs (real-world lgtm, run6-final Shoply lgtm) and on case repos built from the old and new sqli_04_safe patches, all in the assigned tmp folder.
- Limits: the full pytest suite was not re-run (relied on checks.md plus repair-1-check). No real-world fetch (DEC-9).
- Not checked against external-research: the claim that Semgrep gives no in-diff warning on the alerta and postgraas_safe cases. These come from cases.json flags; the claim is unverified here.
- Cleanup: tmp/final removed, and the then-empty tmp/ parent was removed too. Worktree status is clean at efc8599.
