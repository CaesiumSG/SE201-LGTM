# Final review: kev-judge-measurement (efc85996..41560a09)

## Verdict
APPROVE (CLEAN). 0 Critical, 0 High, 3 Medium (new), 0 Low reported.

The slice check suite was run once at head 41560a0: 815 passed, 0 failed, worktree clean.

Acceptance criteria checked at Unit tier:
- AC-S5-1: met. kev_accuracy.supported and kev_accuracy.verdict are reported separately.
- AC-S5-2: met. kev_agreement.verdict_vs_supported and kev_agreement.verdict_vs_agent are reported.
- AC-S5-3: met. evaluate.finding_verdict maps not_real to safe. kev_verdict is written into benchmark rows (evaluate.py:290), so scoring sees it. Report stats and label exclude it. The authz_09_safe test is present.
- AC-S5-4: met. The CLI count excludes not_real. README.md and the CLI help state the rule. Edits stay within the approved README scope.
- AC-S6-1: Shoply part met. labels.n = 74 and source = "model". The real-world part belongs to INTEGRATE.
- AC-S6-2: logic met. Results are reported per kind and per origin. Real-world part belongs to INTEGRATE. See final-03 on the meaning of "accepted".
- AC-S6-3: logic met. On run6-final the list is empty because the cases are absent. This was already raised as lens B-3 and is recorded in log.md.
- AC-S6-4: met. Severity is reported as its own tally.
- AC-S6-5: met. docs/kev-labeling-criteria.md exists. benchmark/kev_model_labels.json records labeling_model claude-opus-5-5, which resolves B-2.
- DEC-13: met. sqli_04/07/11_safe are excluded from labels, accuracy and agreement, and listed in stale. Benchmark scoring keeps them.

## Findings

### final-01 (Medium, reproduced): the stored labels cannot be measured with the shipped entry point on run6-final
- Location: benchmark/judge_eval.py rejudge (the line that skips a record when record.get("mode") is not in evaluate.JUDGED_MODES). The line is unchanged, but this slice consumes it for its outcome.
- Trigger: every benchmark/runs/run6-final/lgtm/*.json record has no "mode" key. The stored findings have judged = null, so 0 judged outcomes. A throwaway run of rejudge(run6-final, export, cfg, stub_judge) gave 36 records, 0 judge calls and 0 judged findings. As a result, "python benchmark/judge_eval.py run6-final export kev_model_labels.json --live" reports n=0 for kev_accuracy, kev_agreement, supported_by_kind and safe_case_acceptance.
- Expected: the slice Outcome says the judge-eval report measures Kev on model-labeled candidates, and the slice consumes the run6-final candidates. evaluate.py:258 already defaults a missing mode to "lgtm" (row.get("mode", "lgtm")).
- Actual: the 74 labels can never be compared against a Kev answer through the CLI.
- Smallest correction: in rejudge, use record.get("mode", "lgtm"), matching evaluate.py:258, and add one test with a mode-less record.
- Recommendation: resolve. It is a one-line fix inside a Modifies file. Alternatively, defer with a known-issue entry for INTEGRATE, which judges fresh runs that carry mode.

### final-02 (Medium, inspected): the "undetermined" labels come from an exact-text lookup artifact and contradict the supported rule in the criteria
- Location: benchmark/kev_model_labels.json (8 undetermined units, all with placeholder supports: yes) and the docs/kev-labeling-criteria.md undetermined sentence.
- Trigger: sqli_01_vulnerable/2.0 is labeled undetermined because its "cited quote is not present in reviewed code". The quoted search_users body is in benchmark/cases/sqli/case_01_vulnerable.patch lines 20-27. The agent quote only drops the docstring line, so an exact substring match fails. The code is a plain f-string SQL injection on request.args. Seven of the eight units are sqli_*/2.0 and likely follow the same pattern.
- Expected: Kev reads code by file and lines, not by quote text. The criteria say supported = no when the code "does not contain what the claim quotes", so a quote that is truly absent can still be labeled.
- Actual: 8 of 74 labels (11%) are dropped from every accuracy, agreement and acceptance measure, including likely clear true positives. The criteria rule will carry into journey-4 labeling in INTEGRATE.
- Smallest correction: change the criteria to "the cited lines are absent from the reviewed code" (match by cited lines, ignoring whitespace and docstrings), then relabel the 8 units from the enclosing function.
- Recommendation: resolve the criteria sentence now so INTEGRATE inherits it. Relabeling the 8 units can be deferred to INTEGRATE.

### final-03 (Medium, inspected): safe_case_acceptance counts supported-but-not_real as "accepted"
- Location: benchmark/judge_eval.py safe_case_acceptance (bool(o["supported"])).
- Trigger: a judged unit on a safe case with supported=True and kev_verdict=not_real, which is the authz_09_safe pattern.
- Expected: DEC-7 and AC-S5-3 say the verdict decides and that such a candidate is not a vulnerability. log.md records the build choice "Kev accepted = supported True", but no decision covers its conflict with DEC-7.
- Actual: the candidate raises the safe-case acceptance share, so the report shows Kev as accepting it as a vulnerability.
- Smallest correction: count it as accepted only when o["supported"] and o.get("kev_verdict") != "not_real", or report both shares. Update the benchmark/README.md bullet to match.
- Recommendation: resolve, or record a decision that "accepted" means support only.

### Lens findings carried, not re-raised
- Test-quality findings 1-3 (Medium) look unaddressed at head and have no recorded deferral: quote_absence last-line boundary, the non-code skip and the report wiring; stats.not_real and suggested-fix absence are not asserted; there is no stale report row test. They should be resolved or deferred explicitly.
- B-3 (AC-S6-3 empty on run6-final) and SEC-1 (not_real suppresses the gate, approved by DEC-7) stand as reported.
- B-1 and B-2 are resolved by the blind Opus relabel (repair-1). Labels no longer track case status: authz_06_safe and sqli_03_safe include undetermined units, and some safe units have supports: yes.

## Plan check
- Contradiction: the Consumes entry assumes run6-final candidates can be measured, but the records lack mode, so the live rejudge skips them (final-01).
- Gap: the plan gave no labeling rule for quote-only units. This was resolved by the criteria edit, which introduced final-02.
- minor correction: slice file, Rules bullet. Before: "The labels and the judge-eval accuracy and agreement numbers leave them out". After: "The labels and the judge-eval accuracy, agreement and acceptance numbers leave them out, as well as units labeled undetermined". Reason: it matches the shipped undetermined exclusion in log.md.
- minor correction: slice Scope Modifies lists benchmark/citation_export.py, benchmark/kev_support/*, src/lgtm/validation/judge.py, tests/test_judge.py, tests/test_kev_support_bench.py and tests/test_e2e_judged_bench.py, all unchanged. No edit is needed; this note is for the INTEGRATE merge notes only.
- needs-replan: none.

## Coverage
- Axes inspected: correctness of the exit-code, report-label, scoring and judge-eval measures across every supported x kev_verdict combination; undetermined and stale exclusions; label file contents against the stored run and patch; README edits against the approved scope; consumers of supported and kev_verdict in benchmark/ and src/; security (temp dir and git use in report()); dependencies (none added, CON-2); CON-3 (additive keys, documented exit-code change).
- Checks run: the slice pytest command once (815 passed); one throwaway script computing all new measures on run6-final with the stored labels (all unit ids matched, 0 judged); one throwaway rejudge with a stub judge (0 calls).
- Limits: no live Kev; the other 7 undetermined units were not individually verified against their patches; CodeGraph was not used (stale index), so git and Read were used instead.
- Cleanup: tmp/final/ was removed; the worktree git status is clean; no other resources were created.
