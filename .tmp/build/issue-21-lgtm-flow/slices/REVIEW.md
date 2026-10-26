Source: LGT-171 (https://linear.app/se201-lgtm/issue/LGT-171/review-pull-request-review)
Retrieved: 2026-10-26 (date only)

# REVIEW: Pull-request review

## Outcome

The squashed integration branch, from the integration base to its head, is reviewed as one pull request against the plan and the project specs, with no Critical or High finding left open.

## Prerequisites

INTEGRATE

## Spec documents

* README.md: documented commands, exit code, outputs, and scope statement (AC-S4-1, CON-3).
* benchmark/README.md: out-of-scope cases and modes, benchmark commands, per-case results (AC-S4-2, AC-S4-6).
* docs/project-proposal.md: scope statement of the two jobs (AC-S4-1).
* docs/real-world-eval.md: real-world evaluation method, held-out rule, and Semgrep SQL injection count (AC-S4-5, AC-S6-6).
* benchmark/security-policy.md: Shoply access-control policy the dev-set authz verdicts are judged against (AC-S3-3, AC-S3-6).
* benchmark/real_world/policies/aegra.md, benchmark/real_world/policies/litellm.md: policies for the aegra and litellm cases (AC-S1-1, AC-S3-2).

## Review focus

* Prompt interaction: deletion-evidence and PR-scope rules in src/lgtm/agents/prompts.toml, src/lgtm/agents/authz_reviewer.py, and src/lgtm/diff/git_diff.py do not contradict each other (AC-S1-1, AC-S3-3).
* tests/model_input_lock/expected.json matches one regeneration after the final merge, not merged text.
* The supported-but-not_real rule in benchmark/evaluate.py keeps scope exclusions and off-category handling (AC-S6-1, AC-S6-2).
* Surfaces kept as at base: grounded_in_pr rendering in src/lgtm/reporting/report_builder.py, EvidenceValidator validate and validate_all signatures, FileDiff fields.
* CT-reviewer-reach-1 and CT-benchmark-scope-trace-1: persisted keys match consumed keys.
* README.md and benchmark/README.md keep both slices' edits and state only what is true.
* DEC-9: no real-world result feeds back into prompts, budgets, or judge criteria.
* CON-2: no new dependency in pyproject.toml or requirements.txt. CON-3: existing commands and benchmark entry points still run.
