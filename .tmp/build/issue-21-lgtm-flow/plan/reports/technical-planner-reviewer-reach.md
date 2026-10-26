# Technical planner report: reviewer-reach

Written: Packages (one package, `reach`), Checks. Setup omitted (default only).

## Scope contract corrections (hand-off to solution architect)
1. AC-S1-3 (removed-only evidence not downgraded/rejected). At 7f642e1 the grounding rule is in src/lgtm/validation/evidence.py (`_grounds_pr` requires the snippet in added text), and tests in tests/test_validation.py. Neither file is in reviewer-reach Scope; the slice's Out of scope assigns "grounding of removed-line evidence" to pr-scoped-review. AC-S1-3 is therefore assigned to package `reach` but cannot be delivered inside Scope. Options: (a) add evidence.py and tests/test_validation.py to reviewer-reach Modifies, which collides with pr-scoped-review (it also changes evidence.py, AC-S3-7), so pr-scoped-review would need reviewer-reach as prerequisite (already is) and the Out-of-scope line dropped; recommended. (b) move AC-S1-3 to pr-scoped-review. Consequence of doing nothing: the criterion is unbuildable.

## Open decisions
2. AC-S1-4 (deletion-only non-security PR yields no finding) is model behavior. Planned as Unit with a fake model (prompt/pipeline passes the no-finding answer through). A live proof needs the model endpoint on a Shoply dev case, which I could not confirm exists as a deletion-only non-security case. Recommend keeping Unit; add a Shoply dev case only if the architect wants live proof (consequence: new benchmark/cases file outside Scope).

## Notes
- AC-S1-1, AC-S1-2, AC-S2-4 excluded (INTEGRATE-only, DEC-9). AC-S2-3 belongs to benchmark-scope-trace.
- CT-reviewer-reach-1 (section run record) has no cited criterion; covered by the package's pipeline tests, no extra check.
- One package: the files share section building, tool limits, and the pipeline result, so they are not independent.
- Only `pytest` listed; no lint or type-check is documented in plan/repo.md.
- Not verified: file contents at the base beyond the evidence and config files.
