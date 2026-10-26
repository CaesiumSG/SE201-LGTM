Build closed: INTEGRATE — blocked (environment)

Branch: build/issue-21-lgtm-flow/INTEGRATE
Head: acfb780225ebbdd1f59dc40d3e01f4a0cad3b3c2
Integration base: origin/main bad831d99fbf91dcbed703625ce4ef4e81cef791
State: unsquashed

## Summary
All four feature slices are merged onto current main, including the kev-validation line they were built on. The merge conflicts with main's section/graph pipeline were resolved keeping both sides. The full test suite passes. The live end-to-end journeys could not run because no model endpoint or Kev judge server was reachable, so criteria proved only by them remain unproven.

## Review and test evidence
- Full suite 2941 passed, 0 failed, 7 skipped (Windows host limits) at the last repair.
- Existing commands run (CON-3); no new dependencies (CON-2).
- Lens reviews: behavior, test-quality, common-sense, structure.
- Final review ACTION, two repair rounds, second re-review CLEAN.

## Needs replan
- AC-S1-2 (lgtm mode yields a finding about string-built SQL on alerta_sqli_vulnerable): Restate AC-S1-2 as "alerta_sqli_vulnerable is reviewed (deletion-dominated diff, sections not empty) and its outcome is reported as an out-of-scope measurement", or drop it. Touches INTEGRATE journey 2 only.
- stories.md S1 business rules, after "Removed lines are valid evidence for a finding about removed behavior": Add "and the judge is shown the removed code they cite". (rereview.md extends it: "...about removed behavior, and the judge and the judge-eval export are shown the removed code they cite".)
- slices/INTEGRATE.md Whole-feature checks: Add "README documents every changed exit code, including evaluate_real exit 4" (done by the repair).
- slices/INTEGRATE.md journey 4: Add: "citation_export reads null-snapshot citations by the same snapshot rule as the production judge read." (rereview-2.md: soften "same" to "the same content-at-cited-lines rule"; the export intentionally does not use production's whole-file fallback.)

## Outstanding
- Live E2E journeys 1-4 (slices/INTEGRATE.md): Run with a live model endpoint and Kev judge server; criteria AC-S1-1, AC-S1-2, AC-S2-4, AC-S3-2 (litellm), AC-S3-3, AC-S3-5, AC-S3-6, AC-S3-7, AC-S4-3, AC-S4-5, AC-S6-1, AC-S6-2, AC-S6-6 are unproven
- behavior-01 / final-02: Injection finding vs judged-mode exit code: cli.py now counts verdict vulnerable only outside lgtm/lgtm-no-sast; rereview.md found no residual
- common-sense-01: Dead EXCLUDED/UNCREDITED code in benchmark/evaluate.py and README rows (pre-existing on main)
- structure-02: Two judged-row predicates
- test-quality-05..07: Low items: adapted fixtures; score_case legacy branch judged flag and alarms_outside_target coverage; lock regenerated from current output (see final/review-test-quality.md)
- fill_record: getattr for a SimpleNamespace double
- rereview-2 open question: Off-by-N cited lines with surviving text read PR code; unmeasured, journey 4 labelling will surface it
- final.md Low/Medium items not repaired: None open: final-01 High, final-02 Medium, final-03 Medium repaired; final-04 Medium (meta.endpoints_reviewed kept as on main) recorded as a decision; final.md lists no Low items
- Stray temp repos lgtm-inj-*: Left in the user Temp folder by benchmark/injection/run_injection_bench.py

## Next
Start the model endpoint and Kev judge server, then resume INTEGRATE to run journeys 1-4 and squash.
