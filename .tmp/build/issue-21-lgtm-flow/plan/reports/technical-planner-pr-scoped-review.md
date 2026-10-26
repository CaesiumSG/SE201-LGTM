# technical-planner: pr-scoped-review

Written: Packages, Checks in slices/pr-scoped-review.md. No Setup (default suffices).

## Open decisions
None.

## Notes
- Two packages: reviewer scope rule (authz_reviewer, prompts.toml) and removed-line grounding (evidence, git_diff). Files disjoint; neither needs the other's code.
- AC-S3-3 and AC-S3-6 need the live model; tiered Integration, proven by the Shoply dev benchmark run. AC-S3-6 is a before/after comparison against the current lgtm dev run.
- AC-S3-5, AC-S3-7 and the litellm part of AC-S3-2 are INTEGRATE-only (DEC-9).

## Scope corrections
None. tests/model_input_lock/expected.json is in Appends; scenarios.py is not touched.
