Source: LGT-165 https://linear.app/se201-lgtm/issue/LGT-165/issue-21-address-lgtm-flow-problems-reviewer-reach-pr-scope-benchmark
Retrieved: 2026-10-26 (time of day not captured)

# Stories

Source: `plan/reports/intake-issue-21.md` (items A1-D5), DEC-1..DEC-12, CON-1..CON-3. Former open decisions OD-1, OD-3, OD-7, OD-8, OD-11 are answered by DEC-5..DEC-9; OD-2, OD-4, OD-5, OD-6, OD-9, OD-10 take the recommendations of `plan/reports/story-planner-stories.md` (DEC-10, pending user approval).

Held-out rule (DEC-9): the real-world benchmark cases (including `aegra_*`, `alerta_*`, `litellm_*`, `postgraas_*`) are never used to tune prompts, budgets, or judge criteria. They are used only to measure. Criteria that name a real-world case are checks, not tuning targets; tuning uses the Shoply cases.

## S1: Deletion-only changes are reviewed

Intake items: A1-A4 (group level).

As a maintainer, I want the reviewer to examine what a PR removes, so a bug caused by deleting a check is reported.

Business rules

* A deletion-only or deletion-dominated change is reviewable in `lgtm` mode.
* Removed lines are valid evidence for a finding about removed behavior.
* `alerta_sqli_vulnerable` is a behavior check for S1 but is outside the headline metrics (see S4).

Acceptance criteria

* AC-S1-1: Reviewing the PR of `aegra_authz_vulnerable` (19 lines deleted, none added) in `lgtm` mode yields a finding about the removed thread-ownership check.
* AC-S1-2: Reviewing the PR of `alerta_sqli_vulnerable` (114 deleted, 7 added) in `lgtm` mode yields a finding about the string-built SQL that replaced the parameterized query.
* AC-S1-4: A deletion-only PR that removes non-security code produces no vulnerability finding.

## S2: The reviewer reaches the code a change affects

Intake items: A1-A4 (group level).

As a maintainer, I want the reviewer to start with enough code and have room to follow behavior, so it does not spend its tool calls locating the changed function.

Business rules

* A section review that ends because a tool or step limit was reached is visible in the results, not silent.
* The investigator tool-call budget, the investigator step budget, and the `read_file` line cap are raised above their values at 7f642e1. The new values are for the build to choose within the existing config (DEC-6).
* The enclosing function of every change is part of the initial reviewer input; deletions are included (DEC-6).

Acceptance criteria

* AC-S2-1: The initial reviewer input for a section includes the enclosing function or definition of every changed line, including removed lines (a hunk spanning several functions contributes each of them), not only the changed lines and three lines around them.
* AC-S2-2: A single file read returns, without truncation, a whole function that is longer than the `read_file` line cap at 7f642e1.
* AC-S2-3: When a section review or the investigator ends because a limit was reached, the per-case result states which limit and which section.
* AC-S2-4: On `aegra_authz_vulnerable`, no section review ends with an empty list after exhausting its tool calls. Check only: a failure is reported, not tuned against (held-out rule).
* AC-S2-5: The investigator tool-call budget, the investigator step budget, and the `read_file` line cap each exceed their values at 7f642e1, and the chosen values are recorded in the config.

## S3: Findings are limited to problems the PR introduces or exposes

Intake items: A5-A8 (group level).

As a reviewer of a PR, I want only PR-caused problems reported, so pre-existing weaknesses and over-strict policy readings are not false alarms.

Business rules

* A finding is about the PR only if it cites a line the PR changed or removed, or explains how the PR newly exposes existing code. Other findings are not reported as PR findings (DEC-5).
* Supplying the project security policy does not lower results relative to running without it.
* The held-out rule applies to every S1-S3 criterion that names a real-world case.

Acceptance criteria

* AC-S3-1: A finding is reported as a vulnerability only if it cites a changed or removed line, or states how the change newly exposes the cited code.
* AC-S3-2: A weakness that already existed on the base branch and is unchanged by the PR is not reported as a vulnerability; `litellm_authz_safe` is not a false positive.
* AC-S3-3: `authz_06_safe` (API-key-scoped report endpoint) and `authz_09_safe` (filter hiding cancelled orders on an owner-scoped query) are not false positives.
* AC-S3-4: Evidence consisting only of removed lines can be marked grounded in the PR and is not downgraded or rejected for lacking added-line evidence.
* AC-S3-5: With a project policy supplied, `aegra_authz_safe` is not a false positive and `lgtm-policy` real-world F1 is not below `lgtm` real-world F1. This is one check run on the real-world set, not a tuning target.
* AC-S3-6: No Shoply vulnerable case that is a TP in the `lgtm` run at the base commit (7f642e1) becomes a FN.
* AC-S3-7: No prompt, budget, or judge criterion is changed in response to real-world case results; the real-world set is run as a measurement after Shoply-based changes are final.

## S4: The scope of LGTM is documented and the benchmark respects it

Intake items: B1-B4 (group level).

As a reader of the README or benchmark, I want the two jobs and the exclusions stated, and out-of-scope cases and modes kept out of the headline numbers.

Business rules

* In scope: triage of Semgrep SQL injection warnings; authz bugs Semgrep cannot see. Everything else is out of scope.
* Out of scope among real-world cases: SQL injection cases with no in-diff Semgrep warning on either side.
* The three Shoply safe SQL injection cases are changed so Semgrep warns on them, as the README states, and stay in the headline metrics.
* In `lgtm-no-sast`, SQL injection rows are out of scope; authz rows are kept.

Acceptance criteria

* AC-S4-1: The scope statement (the two jobs, and that other vulnerability classes are out of scope) appears in both `README.md` and `docs/project-proposal.md` (DEC-12).
* AC-S4-2: `benchmark/README.md` lists the out-of-scope cases and modes and why.
* AC-S4-3: `alerta_sqli` (pair) and `postgraas_sqli_safe` are reported with scope "out" and are not counted in the headline metrics.
* AC-S4-4: `lgtm-no-sast` SQL injection rows are reported with scope "out" and are not counted in the headline metrics; the mode still runs.
* AC-S4-5: The real-world summary reports how many SQL injection cases Semgrep warns on.
* AC-S4-6: Existing benchmark commands run unchanged and still write per-case results and `summary.json`.
* AC-S4-7: Semgrep reports an in-diff warning on `sqli_04_safe`, `sqli_07_safe`, and `sqli_11_safe`, and these cases stay in the headline metrics, because the benchmark measures LGTM's value over SAST on safe code that SAST flags (DEC-11).

## S5: Verdict and support of Kev are scored separately

Intake items: C1-C7 (group level).

As a maintainer, I want the "supported" and "verdict" answers of Kev each measured and used, so a `not_real` verdict is not counted as a false alarm.

Business rules

* Supported and verdict are separate questions with separate accuracy numbers.
* A candidate Kev rates supported but with verdict `not_real` is not a vulnerability: the verdict decides the score and the `lgtm review` exit code (DEC-7). The exit-code change is documented in the README (CON-3).

Acceptance criteria

* AC-S5-1: Benchmark output reports verdict accuracy and supported accuracy as two numbers, against labels.
* AC-S5-2: Benchmark output reports how often the verdict and supported answers of Kev disagree, and how often the verdict of Kev equals the verdict of the agent.
* AC-S5-3: A candidate judged supported but `not_real` is not counted as a reported vulnerability or a false alarm; `authz_09_safe` is not a false alarm.
* AC-S5-4: The `lgtm review` exit code follows the same rule as AC-S5-3, and `README.md` documents it.

## S6: Kev is measured on real LGTM output

Intake items: C1-C7, D1-D5 (group level).

As a maintainer, I want labeled real candidates, so the accuracy of Kev rests on actual LGTM findings rather than 0 examples.

Business rules

* Labels come from Claude Opus 5.5, run by the build agent against documented criteria, not from human labeling. Labels are stored with the benchmark (DEC-8).
* Accuracy numbers are measured against these model labels and are reported as such.
* Severity is measured only, not stabilized (DEC-10).

Acceptance criteria

* AC-S6-1: The judge-eval report states the number of labeled examples, greater than 0, covering candidates from the Shoply and real-world lgtm runs, and that the labels are model-generated.
* AC-S6-2: The report breaks supported accuracy down by candidate kind including `live_shaped`, and reports the share of candidates on safe cases that Kev accepted, for Shoply and real-world separately.
* AC-S6-3: For `authz_10_vulnerable` and `authz_12_vulnerable`, the report states whether the quoted lines are absent from the PR version of the file and whether the cause is the agent quote or a repository mismatch.
* AC-S6-4: Severity accuracy is reported as its own number, apart from supported and verdict.
* AC-S6-5: The labeling criteria are written in the repository, and the stored labels sit with the benchmark and record the labeling model.
* AC-S6-6: Real-world candidates are used only to measure Kev, never to change judge prompts or criteria (held-out rule).

## S7: Results keep what is needed to explain them

Intake items: D1-D5 (group level).

As a maintainer, I want per-case results to keep the work of the reviewer and to show off-category bugs, so misses like A2 can be explained from the results.

Acceptance criteria

* AC-S7-1: Each lgtm-mode per-case result contains, per section, the tool calls of the reviewer (name and arguments) and its raw final answer.
* AC-S7-2: A finding of a category different from the case category is listed in the case result and summary as off-category and does not change TP/FP/FN/TN.
* AC-S7-3: `--rescore` still works on results written before this change.
