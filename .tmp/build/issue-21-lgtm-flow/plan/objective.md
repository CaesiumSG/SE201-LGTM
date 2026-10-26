Source: LGT-165 https://linear.app/se201-lgtm/issue/LGT-165/issue-21-address-lgtm-flow-problems-reviewer-reach-pr-scope-benchmark
Retrieved: 2026-10-26 (time of day not captured)

# Objective

Address the lgtm flow problems raised in GitHub issue #21 (https://github.com/CaesiumSG/SE201-LGTM/issues/21) so that the reviewer reaches the bugs a PR introduces, reports only problems grounded in the PR's changes, and the benchmark and Kev judge measure that behavior honestly against a documented scope. Problem inventory: `plan/reports/intake-issue-21.md` (items A1–A8, B1–B4, C1–C7, D1–D5).

## In scope

* Reviewer reach (A1–A4): deletion-only bugs are found; the investigation budget and context window let the reviewer reach the code a change affects.
* PR-scoped review (A5–A8): findings are limited to problems the PR introduces or exposes; pre-existing issues and over-strict policy readings are not reported as PR findings.
* Benchmark and documented scope (B1–B4): LGTM's scope is stated in the README; benchmark cases and modes outside it are excluded or labeled.
* Kev judge (C1–C7): support and verdict are scored separately against labels, and judge agreement with the agent is measurable.
* Measurement gaps (D1–D5) as listed in the intake.

## Out of scope

* Run-to-run variance at temperature 0 (A9) (DEC-2).
* New review capabilities, languages, or models beyond what the issue raises.

## Constraints

* CON-1: Work starts from the head of PR #20 (DEC-3); slices never rebase onto or require changes to `main` beyond it.
* CON-2: No new third-party dependencies.
* CON-3: Existing CLI commands and benchmark entry points keep working; changed outputs are additive or documented in the README.

## Feature-wide criteria

* The full test suite passes (commands in `plan/repo.md`).

## Design references

None (issue has no images or design links).

## Definition of Done

Every acceptance criterion in `plan/stories.md` passes at its tier, except criteria measured on real-world cases (DEC-9): `INTEGRATE` runs and reports them, and a shortfall is recorded, never tuned against. `INTEGRATE` checks pass on the integrated branch.
