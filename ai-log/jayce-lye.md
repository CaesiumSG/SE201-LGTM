# AI Use Log: Jayce Lye

## 2026-10-10 · Initial LGTM implementation
- **Tool (model):** Claude Code (Claude Fable 5)
- **Files:** src/lgtm/ (config, diff parser, Semgrep runner, RAG indexer and retriever, agents, evidence validator, report builder, pipeline, CLI), benchmark/ (Shoply app, policy docs, case generator, evaluator), tests/, README.md
- **Outcome:** Changed

### What I asked for
A first working version of LGTM built from the prompt in
docs/claude-prompt.md: the full pipeline from git diff to report, the
Shoply benchmark app with generated PR cases, and a test suite.

### How I checked it
Ran the test suite and a full benchmark run, and checked the architecture
against the proposal. Reviewing the first runs showed that Semgrep was
scanning the working tree instead of the PR's file contents, and that the
agents sometimes returned JSON with unescaped quotes and newlines that
failed to parse.

### What I kept or changed
Kept the overall structure. Changed the SAST step to scan the PR-ref file
contents and added repair of malformed agent JSON. Later review (13 Oct
entry) found further problems in the evaluator and the LLM-only baseline.


## 2026-10-10 · Proposal feedback: code search tool and dev/eval split
- **Tool (model):** Claude Code (Claude Fable 5)
- **Files:** src/lgtm/ (search_code tool), benchmark/evaluate.py, benchmark/tools/generate_cases.py, benchmark/labels.json, tests/test_benchmark_cases.py, README.md, benchmark/README.md
- **Outcome:** Kept

### What I asked for
Changes to address the proposal feedback: a `search_code` tool for code
RAG, a dev/eval split of the benchmark, and six OWASP-derived SQL
injection case pairs to expand the benchmark to 36 cases.

### How I checked it
The new patches are produced by generate_cases.py, not written by hand,
and tests/test_benchmark_cases.py checks them. Re-ran the benchmark on
all 36 cases and updated the docs from the run output.

### What I kept or changed
Kept as generated.


## 2026-10-13 · Evaluation and pipeline bug fixes; rebuilt LLM-only baseline
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** benchmark/evaluate.py, src/lgtm/agents/, src/lgtm/analysis/facts.py, src/lgtm/pipeline.py, src/lgtm/sast/, src/lgtm/validation/evidence.py, tests/test_baselines.py, tests/test_facts.py, tests/test_validation.py, tests/test_semgrep.py
- **Outcome:** Changed

### What I asked for
A root-cause analysis of the benchmark failures from round 1, and fixes.

### How I checked it
Read pipeline.py against section 5 of the proposal line by line. This
showed that the AI-written "llm-only" baseline from 10 Oct was not LLM-only:
it had the same RAG and tools as LGTM, so the comparison could not show what
those add. Unit tests had not caught it because they encoded the same
assumption. Also found that the scorer credited the wrong agent when a case
had no finding in its own category, and re-validated the 13 "ungrounded"
findings by hand, which showed the validator was rejecting correct
citations. Each bug got a regression test, and the benchmark was re-run.
Every number in the evaluation log was copied from summary.json files in
benchmark/runs/.

### What I kept or changed
Rejected the original baseline and rebuilt it to match the proposal.
Removed the scorer's fallback, fixed the validator's matching, and added
grounded metrics. A PR review then led to further changes to validator
speed and rescore provenance.


## 2026-10-13 – 2026-10-18 · Documentation and checkpoint report
- **Tool (model):** Claude Code (Claude Opus 5.5, Claude Fable 5.1)
- **Files:** README.md, docs/evaluation-log.md, docs/checkpoint.md, docs/checkpoint.pdf, docs/ai-use-log.md, docs/team-tasks.md
- **Outcome:** Changed

### What I asked for
Drafts of the evaluation log, the checkpoint report, the team AI use log
and the team task plan for the checkpoint sprint.

### How I checked it
The team reviewed the drafts. Traced every figure in the report to a
committed run file, and checked the report against the checkpoint
requirements in the project spec.

### What I kept or changed
Rewrote and condensed sections over several passes, including turning the
"Challenges and what we learned" section into a challenge / action /
going-forward table and trimming the AI-use note.


## 2026-10-18 · Architecture figure
- **Tool (model):** Claude Code (Claude Fable 5.1)
- **Files:** docs/architecture.svg, docs/checkpoint.md
- **Outcome:** Changed

### What I asked for
An architecture diagram for Figure 1 of the checkpoint report.

### How I checked it
Compared the diagram against the code as built and against the proposal's
original diagram.

### What I kept or changed
Tried swapping in the proposal's diagram, then went back to the as-built
diagram, adding a guardrails panel.


## 2026-10-18 · Cap LLM output tokens
- **Tool (model):** Claude Code (Claude Fable 5.1)
- **Files:** src/lgtm/agents/base.py, src/lgtm/config.py, tests/test_agents.py
- **Outcome:** Kept

### What I asked for
A cap on the number of output tokens per LLM call, alongside the existing
request timeout, so a runaway generation cannot stall a review.

### How I checked it
Added tests in tests/test_agents.py and ran the full suite. Merged through
a reviewed pull request (fix/llm-timeout).

### What I kept or changed
Kept as generated.


## 2026-10-23 · Field trial on ordinary merged PRs
- **Tool (model):** Claude Code (Claude Fable 5.1)
- **Files:** benchmark/field_trial/ (cases.json, run_field_trial.py), benchmark/runs/field_trial/, docs/field-trial.md, tests/test_field_trial.py, README.md, benchmark/runs/README.md
- **Outcome:** Kept

*Written 31 Oct from the commits and the description of PR #18.*

### What I asked for
The field trial planned for the checkpoint sprint (task 2 in
docs/team-tasks.md) that never happened: a harness that runs LGTM on 12
ordinary merged PRs from mealie, alerta and redash, and a run in all three
modes.

### How I checked it
The merge commits in cases.json are pinned SHAs, and the harness fetches
them from the upstream projects. Read every finding in the run by hand and
wrote down what each one says in docs/field-trial.md. Added tests for the
case list and the harness helpers.

### What I kept or changed
Kept the harness. The run showed that 10 of 12 PRs never reached an agent,
which became the main finding instead of the false-alarm rate. Merged
myself (PR #18) without a second reviewer.


## 2026-10-23 · Per-member AI-use log folder
- **Tool (model):** Claude Code (Claude Fable 5.1)
- **Files:** ai-log/ (README.md, a stub per member), docs/project-overview/, docs/ai-use-log.md
- **Outcome:** Kept

*Written 31 Oct from the commits and the description of PR #16.*

### What I asked for
Commit the ai-log/ folder, which existed only on my machine, with an
empty stub for every other member and links from the team log.

### How I checked it
Checked the stub format against the course AI-use policy template in
docs/project-overview/.

### What I kept or changed
Kept. The stubs are templates only: each member writes their own entries.


## 2026-10-23 · Prompt-injection mitigations on by default
- **Tool (model):** Claude Code (Claude Fable 5.1)
- **Files:** src/lgtm/config.py, src/lgtm/pipeline.py, src/lgtm/cli.py, benchmark/evaluate.py, benchmark/injection/run_injection_bench.py, tests/test_mitigation_defaults.py, tests/test_baselines.py, README.md, docs/prompt-injection.md, docs/evaluation-log.md
- **Outcome:** Kept

*Written 31 Oct from the commits and the description of PR #17.*

### What I asked for
Turn Brian's comment stripping and injection detection on by default, so
the shipped tool is the mitigated one, with flags to turn them off.

### How I checked it
New tests pin the defaults, the modes they apply to and the CLI switches;
full suite green. Re-ran the injection suite (attack success 0 of 6 with
the defaults on) and the Shoply dev split with the mitigations on and off
from the same frozen tree (same outcome on all 18 cases). Runs committed
under benchmark/injection/results/ and benchmark/runs/run7-mitigation-defaults/.

### What I kept or changed
Kept. I decided the llm-only baseline keeps the raw diff, as the proposal
defines it, so its numbers stay comparable. Merged myself (PR #17) without
a second reviewer.


## 2026-10-24 · Integrating the section/graph pipeline stack
- **Tool (model):** Claude Code (Claude Fable 5.1)
- **Files:** src/lgtm/ (config, pipeline, cli, agents/base and tools, review/), benchmark/evaluate.py, benchmark/injection/, README.md, benchmark/README.md, docs/ (checkpoint, evaluation log, GPU and real-world results notes), tests/
- **Outcome:** Changed

*Written 31 Oct from the commits and the description of PR #19.*

### What I asked for
A merge-readiness review of Jin Rae's stacked PRs (#10, #12, #14, #15)
and an integration branch that fixes what blocks the merge.

### How I checked it
The review found blockers: the old pipeline was deleted rather than kept
behind a flag, verdicts depended on whether CodeGraph was installed, the
scorer had changed, and docs quoted runs that no longer matched the code.
Full suite green after the fixes (2169 passed on macOS), plus a smoke run
with and without CodeGraph. A reduced local re-run from the frozen tree
showed that the lgtm run had gone out without CodeGraph, so I recorded it
on the PR instead of quoting it.

### What I kept or changed
Kept the stack. Added flags for the old behaviour, restored the round-2
scoring rule, and marked every results table "pending re-measurement".
Merged myself (PR #19) without a second reviewer.


## 2026-10-26 · Final-stretch plan, CI workflow and field-trial runner
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** .github/workflows/tests.yml, tests/test_graph_runtime.py (PR #22); benchmark/field_trial/run_field_trial.py, tests/test_field_trial.py (PR #23); the final-stretch plan (outside the repo)
- **Outcome:** Changed

### What I asked for
A review of my plan to get from where we were to the final submission,
then help with my own tasks: a CI workflow, a check of the unmerged
issue-21 branch before the freeze decision, and changes the field-trial
re-run would need.

### How I checked it
Checked the plan's claims against the repository. The AI's first estimate
of cluster time (about 35 hours) used local latency; the committed cluster
numbers in docs/gpu-model-eval.md put a full pass at about 3 hours, so it
corrected the plan. The first CI run failed one test on Linux; it was a
test assumption (the fake CodeGraph's shell exports PWD), not a leak, and
the second run passed (2180 tests). Ran the issue-21 branch's tests on
macOS and in a Linux container, which showed its 52 extra macOS failures
are all bash 3.2 problems in the cluster scripts. Wrote tests first for the
runner change.

### What I kept or changed
Changed the plan's compute estimate and the order of what to cut. Kept the
workflow after the test fix. PRs #22 and #23 were opened for review by Jin
Rae; they were not merged before the v1.0-eval tag.


## 2026-10-27 · Interactive C4 architecture map
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** docs/architecture-c4.html
- **Outcome:** Kept

*Written 31 Oct from the commit and the description of PR #25.*

### What I asked for
A clickable C4 map of LGTM, from the system context down to functions, for
onboarding, the report and the presentation.

### How I checked it
Context, container and component descriptions were written from the
README, docs/ and the code at bad831d. The code-level views were generated
from the source with Python's ast. Checked that all 28 diagrams render at
laptop and phone width.

### What I kept or changed
Kept. The generator script for the code views is not committed, so they
will go stale as src/lgtm changes. Merged myself (PR #25) without a second
reviewer.


*The entries below, 28 Oct – 5 Nov, were drafted on 5 Nov by Claude from
the session records and the PRs, for me to check before merging.*

## 2026-10-28 · Freeze decision and the v1.0-eval tag
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** none in the code; annotated tag v1.0-eval (a5b22d2, code identical to bad831d)
- **Outcome:** Changed

### What I asked for
A check of Jin Rae's unmerged Kev-judge branch (later PR #24) so that he
and I could decide whether to merge it before freezing, or to freeze the
code already on main.

### How I checked it
Confirmed each problem the review reported against the branch itself:
the judge verdict was excluded from report.json, the label file held 74
Shoply-only labels rather than the 114 claimed, and its macOS test
failures were bash 3.2 problems in the cluster scripts. Jin Rae and I made
the decision together.

### What I kept or changed
We froze on main as v1.0-eval and treated the Kev pipeline as a separately
labelled variant. This was superseded on 4 Nov, when the Kev pipeline
merged (#24, #26) and became the base for the final version.


## 2026-10-31 · Deploy scripts on the bash that ships with macOS
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** model/deploy/lib.sh (branch fix/deploy-env-bash32)
- **Outcome:** Kept

### What I asked for
A fix for the GPU deploy scripts dying on a Mac with "ORIGAMI_USER:
unbound variable".

### How I checked it
On 5 Nov, reproduced the bug before opening the PR. With /bin/bash 3.2,
`source <(...)` loads no variables from model/.env; `eval` of the same
CR-stripped text loads them, on bash 3.2 and 5.x and with a CRLF file. The
deploy tests under bash 3.2 go from 52 failures to 17. The remaining 17
are a copy of the old lib.sh embedded in the test and the judged-bench
wrapper, both out of scope. All 83 deploy tests pass on bash 5.

### What I kept or changed
Kept as written; opened as a PR for Jin Rae. The scripts worked on my
machine only because Homebrew's bash 5 comes first on my PATH.


## 2026-11-01 – 2026-11-03 · Field-trial re-run at v1.0-eval
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** benchmark/field_trial/run_field_trial.py (fix pushed to PR #23); run outputs on a local branch that is not pushed
- **Outcome:** Changed

### What I asked for
The field trial (12 ordinary merged PRs) re-run at the frozen tag.

### How I checked it
Ran locally on qwen3.8:27b with CodeGraph installed. LGTM reviewed 12/12
PRs with no false alarms; the plain LLM's one CWE-89 flag was read by
hand. The run exposed a harness bug (the baseline modes crashed on
`endpoints_reviewed`), fixed test-first and pushed to #23. A smoke run
surfaced a possible flaw in one upstream project. Its details are kept out
of this public repository until I decide whether to report it privately.

### What I kept or changed
I kept the harness fix. I did not push the outputs: the v2 pipeline
superseded them, and they contain the withheld case.


## 2026-11-04 · Benchmark of real PRs that introduced published vulnerabilities
- **Tool (model):** Claude Code (Claude Opus 5.5), with research subagents
- **Files:** benchmark/real_prs/cases.json, benchmark/real_prs/run_real_prs.py, benchmark/field_trial/run_field_trial.py, tests/test_real_prs.py, .gitignore (PR #27)
- **Outcome:** Changed

### What I asked for
Tests on real repositories with real vulnerabilities, not synthetic
reverts: the pull request that introduced a published advisory, and the
commit that fixed it.

### How I checked it
Checked each advisory's introducing and fix commits against the GHSA text
and the git history, and pinned them by SHA. Ran all four modes on the
SCIS GPU (Qwen 3.8 27B with the Kev-4B judge). lgtm-no-sast first scored
zero because the scorer only judges benchmark modes; I fixed this in the
harness and re-scored from the stored findings instead of re-running.
Results:
- Semgrep caught 0/13.
- The plain LLM caught 7/13.
- LGTM caught 9/13, with 2 false alarms.
- Of the 4 SQL injections, LGTM caught none as SQL injection.

### What I kept or changed
I kept the benchmark; Jin Rae approved it. The SQL injection gap became
the next task.


## 2026-11-04 · Offline report viewer
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** viewer/build_viewer.py, viewer/template.html, viewer/runs.json, viewer/README.md, tests/test_viewer.py (PR #28)
- **Outcome:** Changed

### What I asked for
A front end for browsing benchmark results: per case, the diff, the
findings with their cited lines, the judge's verdict and the agent trace.

### How I checked it
Built it from the stored runs and compared case pages with the result
JSON in a browser. Advisory links render for https URLs only. Added tests
for the builder.

### What I kept or changed
I added advisory links and an "is the flag in the advisory's file" fact
after the first version. Jin Rae approved it.


## 2026-11-04 – 2026-11-05 · SQL injection reviewer, held-out set, Bedrock backend, live hunt
- **Tool (model):** Claude Code (Claude Opus 5.5), with subagents for the advisory search and for checking leads. For the live hunt, Claude Sonnet 4.6 on Amazon Bedrock was the reviewer model inside LGTM.
- **Files:** src/lgtm/agents/sqli_reviewer.py, authz_reviewer.py, bedrock_llm.py, base.py, prompts.toml, pipeline.py, config.py, cli.py; benchmark/real_prs/heldout.json, benchmark/live_hunt/; docs/real-prs-eval.md, docs/agents.md; tests (PR #29)
- **Outcome:** Changed

### What I asked for
Fix the SQL injection blind spot on a separate branch. Test the fix on
advisories it had not been tuned on. Use part of a $100 Bedrock budget to
hunt for real issues in recently merged PRs.

### How I checked it
- **Held-out set:** 17 advisories were chosen after the reviewer was
  written and scored once. The new version caught 15/17 (14 in the right
  file with the right CWE), against 12/17 for v2.0 and 7/17 for the plain
  LLM. Authorization results were identical between the two versions.
- **Interrupted run:** a VPN drop killed the GPU tunnels mid-run. The
  records written after the drop were set aside and re-run on a new job.
- **Independent review:** before the PR, an independent AI review of the
  branch checked every number in docs/real-prs-eval.md against the result
  files. It found 4 problems, all fixed:
  - failures in the SQL injection pass were invisible;
  - the budget stop was retried and swallowed;
  - one claim in the doc was wrong;
  - two case notes hinted at a withheld lead.

  The full suite then passed (3283).
- **Live hunt:** 55 leads from 20 PRs, each checked against the source by
  separate agents. 2 were real, and both have since been published as
  advisories by others (wagtail). 2 more are withheld pending a disclosure
  decision. A ledger tracked Bedrock spend: $16.73 so far.

### What I kept or changed
- Pinned the Bedrock SDK below version 2, because the Claude 4.x models
  rejected the newer API version.
- Corrected the doc's Semgrep claim.
- Left the plain-LLM control file unchanged, as the control-integrity
  test requires.
- Open for Jin Rae's review. Merging it means the final tag becomes v2.1.


## 2026-11-05 · GitHub App and dashboard for the demo
- **Tool (model):** Claude Code (Claude Opus 5.5), in a separate session
- **Files:** demo/ (PR #30); the repositories cyberjj999/shoply-demo and a private replay repository
- **Outcome:** Changed

### What I asked for
At first, three front-end styles to choose from. I rejected the first
result, three review-page designs, because it was not a product. I asked
again for a real one: Sign in with GitHub, a GitHub App installed on real
repositories, reviews triggered by pull requests, and an organisation
dashboard. Past benchmark runs could appear in its history.

### How I checked it
A recorded run on 5 Nov:
- shoply-demo #1–#3: an authorization bug blocked and then passed after
  the fix, a SQL injection blocked, an IDOR blocked.
- A replay of taiga's real 2016 SQL injection PR: caught at the advisory's
  location, then merged as upstream did.

Check runs and review comments appeared on github.com. The dashboard was
checked at four widths in three styles. The App's secrets, the database
and the clones stayed out of the commit, which was scanned before the
push. The replay repository is private and not a fork, and nothing links
to or mentions the upstream project.

### What I kept or changed
I created and installed the GitHub App myself; the AI did not grant any
access. Open for Jin Rae's review.
