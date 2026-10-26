Source: LGT-167 https://linear.app/se201-lgtm/issue/LGT-167/pr-scoped-review-findings-are-limited-to-problems-the-pr-introduces-or
Retrieved: 2026-10-26 (time of day not captured)

# pr-scoped-review: Findings are limited to problems the PR introduces or exposes

Outcome: A vulnerability finding appears only when it cites a changed or removed line or explains how the PR newly exposes the code, and removed-line evidence can be marked grounded.
Prerequisites: reviewer-reach
Criteria: AC-S3-1, AC-S3-2, AC-S3-4   Constraints: CON-1, CON-2, CON-3   Decisions: DEC-3, DEC-5, DEC-9, DEC-10   External: none

## Scope

| Field | Entries |
| -- | -- |
| Owns | PR-scoping rule for reported vulnerabilities; grounding of evidence on removed lines, including that removed-only evidence is not downgraded or rejected; policy-mode behavior relative to no-policy |
| Modifies | src/lgtm/validation/evidence.py, src/lgtm/diff/git_diff.py, src/lgtm/agents/authz_reviewer.py, src/lgtm/agents/prompts.toml; tests/test_validation.py, tests/test_graph_evidence.py, tests/test_agents.py, tests/test_graph_prompts.py, tests/test_diff.py |
| Regenerated | tests/model_input_lock/expected.json |
| Consumes | The reviewer changes delivered by reviewer-reach; the grounded_in_pr field on EvidenceItem and its rendering in src/lgtm/reporting/report_builder.py, both unchanged |
| Resources | Live-model and real-world runs are INTEGRATE only (defer); tests use fake models |
| Out of scope | Deletion-only reach, limits and context (reviewer-reach); the Shoply dev criteria on safe cases and TP retention, the policy-mode comparison, and the no-tuning rule (INTEGRATE); any change to report_builder.py, to the EvidenceValidator validate and validate_all signatures, or to FileDiff fields beyond additive removed-text access, all of which stay as at base for kev-judge-measurement; handling of supported-but-not_real candidates and judge criteria (kev-judge-measurement); benchmark scoring and scope labels (benchmark-scope-trace) |

## Packages

| Package | Criteria (tier) | Production files | Test files |
| -- | -- | -- | -- |
| scope-rule | AC-S3-1 (Unit: rule present in every authz system prompt, policy and no-policy; model adherence INTEGRATE via AC-S3-3), AC-S3-2 (Unit: same; litellm part INTEGRATE) | src/lgtm/agents/authz_reviewer.py, src/lgtm/agents/prompts.toml | tests/test_agents.py, tests/test_graph_prompts.py, tests/model_input_lock/expected.json |
| removed-line-grounding | AC-S3-4 (Unit) | src/lgtm/validation/evidence.py, src/lgtm/diff/git_diff.py | tests/test_validation.py, tests/test_graph_evidence.py, tests/test_diff.py |

INTEGRATE-only, in no package: AC-S3-3, AC-S3-5, AC-S3-6, AC-S3-7, and the litellm part of AC-S3-2.

## Checks

* `pytest`: unit and fake-model suites of both packages, including the model input lock.
