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
