# solution-architect: slice cut for issue-21-lgtm-flow

Written: plan/architecture.md, slices/reviewer-reach.md, slices/pr-scoped-review.md, slices/benchmark-scope-trace.md, slices/kev-judge-measurement.md, slices/INTEGRATE.md.

## Cut
reviewer-reach (S1, S2) -> pr-scoped-review (S3); reviewer-reach -> benchmark-scope-trace (S4, S7, AC-S2-3); both -> kev-judge-measurement (S5, S6). pr-scoped-review and benchmark-scope-trace are the only concurrent pair; they touch disjoint trees (src/ vs benchmark/ and docs).

## S4/S7 hand-off
benchmark/evaluate.py and benchmark/real_world/evaluate_real.py are changed by S4, S7 and the AC-S2-3 statement, so they share one slice. S5-3 also changes evaluate.py scoring, so kev-judge-measurement is chained after it. CT-reviewer-reach-1 carries section tool calls, raw answer, and limit hit from the pipeline to the per-case result. The story-planner open item (does call_log reach the result) is unverified; the contract makes reviewer-reach responsible for exposing it.

## Open decisions and the cut
No answer to OD-1, OD-3, OD-7, OD-8 changes the cut. OD-11 (c) (new held-out set) would add a benchmark slice; (a) and (b) do not. OD-8 (a) or (c) needs human labeling and can stall kev-judge-measurement. OD-5 (c) makes benchmark-scope-trace regenerate Shoply cases (already in its Modifies).

## Judgement calls to confirm
- AC-S2-3 is assigned to benchmark-scope-trace, not reviewer-reach, because the per-case result is written there.
- kev-judge-measurement depends on pr-scoped-review only to avoid overlap in src/lgtm/pipeline.py, prompts.toml, report_builder.py and the model-input lock; file overlap was not verified in code. If none exists, drop that prerequisite so the two run concurrently.
- Real-world case criteria (AC-S1-2, S3-2, S3-5, S4-5) are run only by INTEGRATE under OD-11 (a). If OD-11 is answered (b) or (c), move them into slice checks.
- Exact files for deletion handling, enclosing-definition context, and the labeled-candidate file were not read; Scope uses directories.

## Dropped as not needed
Separate documentation slice; separate S5 and S6 slices; a slice for the model-input lock.

Skipped: reading code bodies; existence checked only through the base-commit tree. Risk: src/lgtm/validation/evidence.py and src/lgtm/review/provenance.py as S3 files are inferred from names.
