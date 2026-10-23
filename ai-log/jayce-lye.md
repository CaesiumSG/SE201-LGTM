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
