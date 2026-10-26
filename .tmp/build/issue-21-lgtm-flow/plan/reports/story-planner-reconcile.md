# story-planner: reconcile stories with DEC-5..DEC-10

Written: `plan/stories.md` (7 stories, 39 criteria). Open decisions are resolved in place; the header and the rules name the DEC that answers each.

## Resolutions
- OD-1 -> DEC-5: S3 rule and AC-S3-1 state option (a).
- OD-3 -> DEC-6: limits are raised, not kept. S2 rules state raised budgets and enclosing function incl. deletions.
- OD-7 -> DEC-7: S5 rule states the verdict decides (option a); README documents the exit-code change.
- OD-8 -> DEC-8: S6 rule states Claude Opus 5.5 labels by the build agent against documented criteria (not human labels).
- OD-11 -> DEC-9: held-out rule at the top of stories.md, applied in S2, S3, S6.
- OD-2, OD-4, OD-5, OD-6, OD-9, OD-10 -> DEC-10 recommendations (pending user approval): OD-2 (a), OD-4 (a), OD-5 (a) real-world + (c) Shoply, OD-6 (a), OD-9 measure only, OD-10 (a).

## Criterion changes
Changed (ID kept, [OD-n] tags removed):
- AC-S1-2
- AC-S2-1 (also removed-only hunks), AC-S2-2, AC-S2-4 (check-only)
- AC-S3-1, AC-S3-5 (one check, not a tuning target)
- AC-S4-3 (now only `alerta_sqli` pair and `postgraas_sqli_safe`; the three Shoply safe cases moved to AC-S4-7), AC-S4-4
- AC-S5-3 (option wording removed), AC-S5-4 (README documents exit code)
- AC-S6-1 (states labels are model-generated), AC-S6-4
- AC-S7-2

Added: AC-S2-5, AC-S3-7, AC-S4-7, AC-S6-5, AC-S6-6.
Removed: none.
Unchanged: AC-S1-1, S1-3, S1-4, AC-S2-3, AC-S3-2..S3-4, S3-6, AC-S4-1, S4-2, S4-5, S4-6, AC-S5-1, S5-2, AC-S6-2, S6-3, AC-S7-1, S7-3.

## Questions and hand-offs
- DEC-8 consequence: accuracy is measured against model labels, not human truth; AC-S6-1 requires saying so. Documented labeling criteria may not exist at the base; AC-S6-5 makes writing them part of S6.
- AC-S4-7 assumes sqli_04/07/11_safe are the three Shoply safe cases; not verified in code. It changes fixtures: the build must confirm Semgrep warns on them.
- Tension: DEC-6 raises limits and DEC-9 forbids tuning on real-world. Budget values come from Shoply or reasoning; AC-S2-4 (aegra, real-world) is check-only, a failure is reported not tuned.
- DEC-10 is pending user approval; the criteria built on OD-2, OD-4, OD-5, OD-6, OD-9, OD-10 could change.
- S4 and S7 both touch benchmark/evaluate.py (unchanged from the earlier report).

Skipped: reading code (base budget values, fixture existence not checked). Risk: AC-S2-5 and AC-S4-7 rest on unverified base facts.
