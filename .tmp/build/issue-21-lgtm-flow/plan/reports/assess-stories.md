# Assessment: stories (issue-21-lgtm-flow)

Result: ACTION. 0 Critical, 2 High, 5 Medium, 5 Low.
Inputs read: objective, stories, decisions, architecture, all slices, slice-rules. The intake report was not read (outside the allowed set), so the A/B/C/D item mapping is checked only through the objective group summaries.

## Checks
| Check | Result |
| --- | --- |
| Every objective outcome covered by a story | Met for the groups in the objective text (reach S1/S2, PR scope S3, scope S4, Kev S5/S6, measurement S7). D1-D5 and per-item IDs cannot be traced (stories-08). |
| No story or criterion beyond objective and decisions | Mostly met; see stories-09, stories-10. |
| No contradictions among stories, decisions, slices | Not met: stories-01, stories-05, stories-06. |
| Every criterion cited by exactly one slice or INTEGRATE | Not met: stories-02. Every criterion is cited at least once. |

## Findings

### stories-01 High: Definition of Done conflicts with the held-out rule
objective.md DoD: every acceptance criterion passes. DEC-9, AC-S2-4 (a failure is reported, not tuned), AC-S3-5, AC-S3-7 and the INTEGRATE risks say live-model real-world results (AC-S1-1, AC-S1-2, AC-S2-4, AC-S3-2 litellm part, AC-S3-5, real-world parts of AC-S4-3/S4-5) may fail with no permitted remedy. A pass/fail criterion that cannot be fixed by tuning is either unattainable or not a criterion.
Recommend: state that the real-world-named criteria are measurements that must be run and reported in the INTEGRATE result, not pass gates. Needs user confirmation (changes DoD meaning).

### stories-02 High: Criteria cited by slices without a package, and cited more than once
- reviewer-reach, pr-scoped-review and kev-judge-measurement list AC-S1-1, AC-S1-2, AC-S2-4, AC-S3-5, AC-S3-7, AC-S6-6 in Criteria but in no package and with no tier. slice-rules (Build-ready): every criterion a slice cites maps to exactly one package and tier.
- Many criteria are also cited by INTEGRATE.md journeys: AC-S4-1/S4-2 (benchmark docs package and INTEGRATE review), AC-S2-5, AC-S3-3, AC-S3-6, AC-S4-6, AC-S4-7, AC-S7-1, AC-S7-2, AC-S2-3 (journey 3, each already Unit/Integration in a slice), AC-S5-1/S5-2/S6-1/S6-2/S6-5 (journey 4), AC-S5-4 (journey 1, Unit in kev). The check requires exactly one citation; E2E use also requires that no lower tier can prove it, which journeys 3 and 4 do not claim for these.
Recommend: remove the INTEGRATE-only criteria from the three slices' Criteria lines (keep the pending-integration Checks lines) and cite them only in INTEGRATE. Remove from journeys 1, 3, 4 the criteria a slice already proves at a lower tier, or mark them as observations, not citations.

### stories-03 Medium: DEC-10 content lives outside the plan
DEC-10 points to plan/reports/story-planner-stories.md for OD-2, OD-4, OD-5, OD-6, OD-9, OD-10. No story or slice states them, yet every slice cites DEC-10 and must be self-contained. It is also pending user approval, so slices depend on an unapproved decision.
Recommend: state each adopted OD in one line in decisions.md, or drop the DEC-10 citation from slices whose criteria it does not change. Approval can wait; the missing inline text blocks self-containment.

### stories-04 Medium: AC-S1-3 and AC-S3-4 are near-duplicates - merge (recommendation)
Observed: both are in package removed-line-grounding (pr-scoped-review), tier Unit, same files (evidence.py, git_diff.py) and tests. AC-S3-4 states the mechanism (removed-line evidence can be marked grounded); AC-S1-3 states the consequence (removed-only evidence is not downgraded or rejected). The slice Owns row already joins them in one sentence, and neither can pass without the other. Keeping both forces the cross-story exceptions in architecture (S1 except AC-S1-3) and in the reviewer-reach Out-of-scope row.
Recommend: merge into one criterion under S3, for example "Evidence consisting only of removed lines can be marked grounded in the PR and is not downgraded or rejected for lacking added-line evidence". Keep the S1 business rule "Removed lines are valid evidence". Delete AC-S1-3 and the S1-3 exceptions in architecture and slice text. Whether current code downgrades such evidence was not checked. If the plan is already approved this is a Major change (criterion) and needs re-approval.

### stories-05 Medium: model_input_lock ownership count disagrees
architecture.md and INTEGRATE.md say tests/model_input_lock/expected.json is touched by four slices; only three append it (reviewer-reach, pr-scoped-review, kev-judge-measurement). benchmark-scope-trace does not list it.
Recommend: correct the count to three, or add the file to the slice that changes it.

### stories-06 Medium: AC-S4-3/S4-4 wording versus CT-benchmark-scope-trace-1
Stories accept "excluded from, or labeled out-of-scope"; the contract fixes scope "out" with headline counting only "in". "0 UNCREDITED" is undefined in the plan.
Recommend: reword AC-S4-3/S4-4 to the contract (case reported with scope out, not counted in headline metrics) and replace UNCREDITED with a plain description.

### stories-07 Medium: AC-S2-2 and the S1 "every lgtm mode" rule are not testable as written
AC-S2-2 "whole function of typical size" has no bound. The S1 rule says every lgtm mode, but criteria cover only lgtm mode (AC-S1-1/S1-2).
Recommend: define the AC-S2-2 size from the Shoply dev cases or a line count; narrow the S1 rule to lgtm mode or add a mode-agnostic Unit criterion.

### stories-08 Low: no traceability from stories to intake items
The objective lists A1-A4, A5-A8, B1-B4, C1-C7, D1-D5; stories carry no item IDs. D1-D5 are covered by S6/S7 only by inference; not verifiable here.
Recommend: add an item-ID line per story so the coverage check is mechanical.

### stories-09 Low: AC-S4-7 has no objective or decision basis
Changing the three Shoply safe SQL cases so Semgrep warns on them is in no objective line or DEC; the story justifies it by "as the README states". It also changes the baseline AC-S3-6 compares against while the two slices run concurrently.
Recommend: confirm with the user or cite the intake item; fix the AC-S3-6 baseline as the base-commit run.

### stories-10 Low: documentation reach beyond the objective
The objective names the README; AC-S4-1 also requires docs/project-proposal.md, and benchmark-scope-trace modifies benchmark/real_world/README.md with no criterion.
Recommend: keep project-proposal if the issue asks for it; drop real_world/README.md or tie it to AC-S4-2.

### stories-11 Low: authz_09_safe asserted twice
AC-S3-3 (pr-scoped-review) and AC-S5-3 (kev) both require authz_09_safe not to be a false positive/alarm, by different mechanisms. Not a contradiction.
Recommend: no action.

### stories-12 Low: sample values in criteria
AC-S4-5 "(2 of 6 today)" and case line counts in AC-S1-1/S1-2 are sample values; INTEGRATE already flags them unverified.
Recommend: drop "(2 of 6 today)" from the criterion.

## Not checked
Intake report and external files; code at 7f642e1 (no CodeGraph query). Claims about current downgrade behavior, case names and counts are unverified.
