# Solution architect replan 1: R-1, R-2

## R-1 (kev-judge-measurement)
Smallest resolution: exclude the three stale stored candidates (sqli_04_safe, sqli_07_safe, sqli_11_safe) from labeling and scoring, list them as excluded in the judge-eval report, and leave run6-final and the regenerated patches untouched. Added a Rules section and a Consumes exception to `slices/kev-judge-measurement.md`; INTEGRATE journey 4 risk now says it labels those three from integrated output.
Class: minor (Consumes wording and a rule inside the existing Scope; no file added outside Scope, no criterion, outcome, constraint or CT key changes).
Rejected: re-anchoring run6-final writes outside Scope (major); regenerating needs a live model, which only INTEGRATE may run.
Resolved: D-1 is DEC-13.

## R-2 (INTEGRATE)
Smallest resolution: no code change. Journey 2 writes to an output directory with no earlier results and does not use --resume or --summarize-only on stored runs, so case_scope is written from cases.json. Old stored real-world runs keep reading "in" (CT-benchmark-scope-trace-1 unchanged) and are not used to prove AC-S4-3 or AC-S4-5. Edited `slices/INTEGRATE.md` (journey 2, one risk bullet).
Class: minor (command fix and clarification).
Rejected: applying cases.json scope on summarize-only/resume changes CT-benchmark-scope-trace-1 (major, and invalidates accepted benchmark-scope-trace).
Resolved: D-2 is DEC-14. INTEGRATE.md records the stored-run counting as a known issue.

## Open decisions
* D-1 (resolved, DEC-13) Handle stale Shoply candidates for sqli_04/07/11_safe | exclude and report (recommended); re-anchor run6-final (writes outside Scope, major); relabel from a fresh Shoply run (needs live model, INTEGRATE only) | exclude and report; INTEGRATE labels them in journey 4
* D-2 (resolved, DEC-14) Real-world scope for stored runs | fresh journey-2 output dir (recommended); make summarize-only/resume re-read cases.json (changes CT-benchmark-scope-trace-1) | fresh output dir

## Impact
* Accepted slices invalidated: none. benchmark-scope-trace, reviewer-reach, pr-scoped-review unchanged.
* Constraints touched: none (CON-1..3).
* plan/architecture.md: no row changes (rows hold no Scope or Provides detail). Not edited.
* Acceptance-criterion changes for the story-planner: none.
* plan/changes.md: minor changes after approval still need a line; the orchestrator should add one for R-1 and R-2.
* Slice files: no Packages file left the Scope; Packages, Checks unchanged (technical-planner may add a check that excluded candidates are listed).
* Related outstanding items (README duplication, case_scope duplicate, rescore no-sast row) not addressed; not in R-1/R-2.

Skipped: did not read code bodies or verify the three candidates' staleness beyond the intake facts. Risk: kev-judge-measurement lowers Shoply safe-candidate coverage until INTEGRATE journey 4.

## Fix notes (assessment findings)
* kev-judge-measurement.md: DEC-13 rule stated once in Rules (package judge-measurement, Unit), worded "stale with reason", bounded to labels and judge-eval numbers, benchmark scoring kept (ready-01, -04, -05; stories-02, -04). Consumes names src/lgtm/validation/evidence.py instead of symbols; FileDiff, validate signatures and grounded_in_pr clauses removed (ready-02, overlap-01). CT mis-citation removed (stories-03).
* INTEGRATE.md: journey 4 adds an lgtm run of sqli_04_safe and sqli_11_safe (eval split) and cites the Shoply parts of AC-S6-1 and AC-S6-2 and DEC-13; same in "Criteria proved here only" (stories-01, -03; overlap-02, -03). Risk added for evidence.py reconciliation (overlap-01). Known issue says journey 2 runs once without --resume (stories-04).
* Not fixed: ready-03 and ready-06 (Packages and Checks, technical-planner's); overlap-04, -05 (builder-chosen label path, Resources wording; no one-word fix); stories-05(b) (stories.md header, story-planner or changes.md). Resume after a crash inside the fresh directory (stories-05a) left unaddressed: DEC-14 is silent.
