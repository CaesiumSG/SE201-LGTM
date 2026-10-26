# Story planner: assess fixes (issue-21-lgtm-flow)

Written: plan/stories.md, this report.

## Changed in stories.md
- stories-04: AC-S1-3 deleted (no renumbering). AC-S3-4 now reads: removed-line-only evidence can be marked grounded and is not downgraded or rejected for lacking added-line evidence. S1 rule "Removed lines are valid evidence" kept.
- stories-06: AC-S4-3, AC-S4-4 reworded to "reported with scope out, not counted in headline metrics"; UNCREDITED removed.
- stories-07: AC-S2-2 bound set to 150 lines (assumption, not verified against Shoply dev cases). S1 rule narrowed to `lgtm` mode.
- stories-08: group-level "Intake items" line added per story. Per-item IDs not added; intake report was not in the allowed reads.
- stories-09: AC-S3-6 baseline fixed to the `lgtm` run at base commit 7f642e1.
- stories-12: "(2 of 6 today)" dropped from AC-S4-5.
- Unchanged criteria IDs: all others. Removed: AC-S1-3.

## Not fixed here (hand-offs)
- stories-03: state OD-2/4/5/6/9/10 inline in decisions.md (DEC-10), or drop DEC-10 from slices. Outside stories.md.
- stories-05: architecture.md and INTEGRATE.md say four slices touch model_input_lock expected.json; should be three.
- stories-04 follow-on: delete the AC-S1-3 exceptions in architecture.md, slice Owns rows and the reviewer-reach Out-of-scope row; remove AC-S1-3 from slice Criteria. Merge is a Major criterion change if the plan was approved.
- stories-02 and stories-01: skipped as instructed.
- stories-10: benchmark/real_world/README.md edit has no criterion; drop it or tie to AC-S4-2 (slice fix).
- stories-11: no action.

## Open decisions
- stories-09: confirm with the user that AC-S4-7 (Semgrep warns on three Shoply safe SQL cases) is wanted; no objective/DEC basis found.
- stories-10: confirm docs/project-proposal.md in AC-S4-1 is requested by the issue; kept for now.
- AC-S2-2: confirm 150 lines.
