# AI Use Log: Lee Jin Rae

These entries retrospectively cover my work merged into `main` from
13 October to 6 November 2026. Dates and file scopes were reconstructed
from commits; tool use and checking are based on my recollection.

My main development assistant was Pi with GPT-6.1-sol. I also used Claude
Code and a local Qwen3.6 27B model connected through Pi, but cannot reliably
assign all of that use to individual tasks. Specific attribution is given
where known below. These development assistants are separate from the
Qwen reviewer and Kev judge evaluated as part of LGTM.

Across this work, I read code and diffs, ran automated checks and real
evaluations, and had agents produce results for me to review. For benchmark
work, I commonly had AI run the benchmark, read the results myself, and
used AI to make further fixes. The entries do not imply that I personally
executed every test or performed a manual audit of every result.

## 2026-10-13 – 2026-10-18 · GPU model deployment and serving reliability
- **Tool (model):** GitHub Copilot (model not recorded), followed by other development assistants described above
- **Files:** model/deploy/, model/jobs/, model/src/ollama_server.py, model/.env.example, model/README.md, model/GPU_CLUSTER_CONTEXT.md
- **Outcome:** Changed

### What I asked for
Deployment scripts and Slurm jobs to serve the model on the GPU cluster,
with local access to the endpoint and configuration for the available GPUs.

### How I checked it
Reviewed generated code and real-run output as part of the deployment and
evaluation work. The initial deployment commit credits Copilot. I cannot
reconstruct the exact assistant handover or every individual deployment
check.

### What I kept or changed
Kept the deployment structure and iterated on readiness checks, CPU-thread
allocation, GPU requests and fallback submission, and 32k-context setup.

## 2026-10-18 · GPU-model configuration, resumable evaluation and LLM error handling
- **Tool (model):** Pi (primarily GPT-6.1-sol)
- **Files:** src/lgtm/config.py, src/lgtm/cli.py, src/lgtm/agents/base.py, src/lgtm/agents/plain_reviewer.py, benchmark/evaluate.py, benchmark/real_world/evaluate_real.py, tests/test_gpu_model.py, tests/test_agents.py, tests/test_baselines.py
- **Outcome:** Changed

### What I asked for
GPU-model selection, resumable benchmark runs and explicit error accounting,
plus more robust handling of failed calls, invalid tool inputs and malformed
JSON answers.

### How I checked it
Read benchmark results and used AI to investigate failures and revise the
implementation. Reviewed code changes and automated-check output. The
recorded GPU run did not exercise the retry path, so it was not evidence
that live retries worked.

### What I kept or changed
Kept the configuration and resume support, with iterative changes to retry,
input-validation and answer-repair handling rather than accepting the first
implementation unchanged.

## 2026-10-18 · GPU benchmark runs and checkpoint results
- **Tool (model):** Pi (primarily GPT-6.1-sol)
- **Files:** benchmark/runs/archive/gpu-qwen3.8-27b/, benchmark/runs/archive/gpu-shared/, docs/gpu-model-eval.md, docs/evaluation-log.md, docs/checkpoint.md, src/lgtm/config.py, model/jobs/serve.sbatch
- **Outcome:** Changed

### What I asked for
Run the Shoply and real-world benchmarks on the GPU model, summarise the
results, and update the deployment defaults and checkpoint material.

### How I checked it
Had AI run the benchmarks and read through the results myself before asking
for fixes and report revisions. Later benchmark work exposed contamination
from indexed case descriptions; the early Shoply results were withdrawn
rather than treated as valid performance evidence.

### What I kept or changed
Kept the run records and deployment setup. Revised timing, error,
category/split and grounding summaries, and the baseline-context caveat.
Changed the defaults to the selected GPU reviewer configuration.

## 2026-10-19 – 2026-10-20 · Policy-only retrieval and immutable CodeGraph evidence
- **Tool (model):** Pi (GPT-6.1-sol)
- **Files:** src/lgtm/rag/, src/lgtm/graph/, src/lgtm/agents/tools.py, src/lgtm/pipeline.py, src/lgtm/validation/evidence.py, src/lgtm/reporting/report_builder.py, tests/test_graph_export.py, tests/test_graph_runtime.py, tests/test_graph_tools.py, tests/test_graph_evidence.py
- **Outcome:** Changed

### What I asked for
Replace source-code RAG with CodeGraph exploration and exact Git reads,
while retaining policy retrieval. Keep base and PR evidence tied to frozen
snapshots and expose that provenance in findings and benchmark records.

### How I checked it
Used code/diff review and automated-check results during the iterations.
The committed tests cover export safety, process cleanup, snapshot-labelled
tools and evidence validation; I do not claim to have manually exercised
every platform-specific case.

### What I kept or changed
Kept the graph-and-Git approach. Iterated on path safety, private-root
redaction, cleanup, tool-call charging, graph health and citation handling.

## 2026-10-20 – 2026-10-21 · Investigator-led section review and authorization cases
- **Tool (model):** Pi (GPT-6.1-sol)
- **Files:** src/lgtm/agents/investigator.py, src/lgtm/agents/authz_reviewer.py, src/lgtm/review/, src/lgtm/pipeline.py, benchmark/tools/generate_cases.py, benchmark/cases/authz/, benchmark/labels.json, tests/test_sections.py, tests/test_investigator.py, tests/test_benchmark_cases.py
- **Outcome:** Changed

### What I asked for
Have an investigator propose review sections over the PR diff rather than
relying only on detected endpoints. Add coverage records and authorization
cases for changes such as deleted checks, helpers, moved routes and large
diffs.

### How I checked it
Reviewed generated changes and automated-check output, and used benchmark
results to guide further changes. Tests cover section planning, coverage,
deduplication, investigator responses and generated cases.

### What I kept or changed
Kept section-based review and broader cases. Iterated on splitting and
fallback behaviour, prompt fencing, malformed findings and integration with
the rest of the pipeline.

## 2026-10-21 – 2026-10-22 · Benchmark coverage, resume handling and contamination fixes
- **Tool (model):** Pi (primarily GPT-6.1-sol)
- **Files:** benchmark/evaluate.py, benchmark/real_world/evaluate_real.py, benchmark/real_world/fetch.py, benchmark/tools/generate_cases.py, benchmark/cases/, src/lgtm/review/dedup.py, src/lgtm/review/provenance.py, tests/test_baselines.py, tests/test_evaluate_real.py, tests/test_real_world_cases.py
- **Outcome:** Changed

### What I asked for
Investigate benchmark problems and correct evaluation coverage, resume and
error handling. Remove information that could reveal benchmark answers to
the reviewer and repair affected cases.

### How I checked it
Had AI run benchmarks, read their results and used AI to fix the problems.
The contamination issue made me more cautious about later evaluation and
label review. I do not attribute the original discovery to myself alone.

### What I kept or changed
Restricted copied policy documents so the benchmark README's case
descriptions were not indexed. Also changed revealing docstrings, case
construction, run pinning and failure/resume handling. Superseded results
were not retained as valid evidence.

## 2026-10-22 · Central prompt registry and model-input regression checks
- **Tool (model):** Pi (primarily GPT-6.1-sol)
- **Files:** src/lgtm/agents/prompts.toml, src/lgtm/agents/registry.py, src/lgtm/agents/, src/lgtm/rag/retriever.py, tests/model_input_lock/, tests/test_registry.py, docs/agents.md
- **Outcome:** Changed

### What I asked for
Move model-visible prompts and tool descriptions into a central TOML
registry, with regression checks to preserve the rendered model input.

### How I checked it
Reviewed changes and automated-check output. The model-input fixtures and
registry tests provide checks against unintended prompt changes during the
extraction.

### What I kept or changed
Kept the central registry and regression fixtures, with iterative revisions
to the extraction and its integration with agents, tools and documentation.

## 2026-10-23 – 2026-10-24 · Kev deployment, judging and judge-quality evaluation
- **Tool (model):** Pi (primarily GPT-6.1-sol); Claude Code (Opus 5.5) for benchmark-label generation
- **Files:** model/deploy/, model/jobs/kev-serve.sbatch, model/jobs/judged-serve.sbatch, src/lgtm/validation/judge.py, src/lgtm/validation/cwe_criteria.py, src/lgtm/validation/judge_examples.py, benchmark/citation_export.py, benchmark/judge_eval.py, benchmark/kev_support/, benchmark/runs/kev-support-20261023/, tests/test_judge.py
- **Outcome:** Changed

### What I asked for
Integrate a separately deployed Kev judge, report its decisions separately
from reviewer candidates, and build benchmarks to compare request formats
and measure whether cited evidence supports the findings.

### How I checked it
Reviewed benchmark and automated-check results. I also manually read
AI-generated labels during the Kev evaluation work. The earlier benchmark
contamination issue was a reason to be more careful about these labels;
label generation by Opus 5.5 was not treated as independent human ground
truth. I cannot assign that manual review to every individual run here.

### What I kept or changed
Kept separate reviewer and judge stages. Iterated on candidate contracts,
citation handling, request formats, verdict/support reporting, confidence
metrics, cluster serving and failure handling.

## 2026-10-27 · PR-scoped findings, review reach and actual-output judge labels
- **Tool (model):** Pi (primarily GPT-6.1-sol); Claude Code (Opus 5.5) for benchmark-label generation
- **Files:** src/lgtm/agents/authz_reviewer.py, src/lgtm/agents/base.py, src/lgtm/review/endpoints.py, src/lgtm/pipeline.py, src/lgtm/validation/evidence.py, benchmark/judge_eval.py, benchmark/kev_model_labels.json, docs/kev-labeling-criteria.md, tests/test_removed_line_citation.py, tests/test_tool_loop_context.py
- **Outcome:** Changed

### What I asked for
Improve review context and PR-scoped findings, including changed-line and
base-side evidence, and measure the judge using actual reviewer output.

### How I checked it
Reviewed generated changes, benchmark output and tests. Manually checked
AI-generated labels rather than relying only on the generating model, with
particular care after the contamination problem.

### What I kept or changed
Kept the added review context, provenance and judge measurement, with
iterative corrections. This was also an integration commit containing
teammates' work; I do not claim all files in it as my own AI-generated work.

## 2026-10-29 · Two-condition benchmarks, traces, development batches and held-out guard
- **Tool (model):** Pi (primarily GPT-6.1-sol); Claude Code (Opus 5.5) for benchmark-label generation
- **Files:** benchmark/evaluate.py, benchmark/real_world/evaluate_real.py, benchmark/real_world/batch.py, benchmark/guard.py, benchmark/kev_model_labels.json, benchmark/runs/shoply-20261029/lgtm/, src/lgtm/agents/base.py, src/lgtm/validation/evidence.py, tests/test_case_record.py, tests/test_batch_run.py, tests/test_guard.py, tests/test_fix_rules.py
- **Outcome:** Changed

### What I asked for
Focus reported comparisons on LGTM and LLM-only, retain useful run traces,
and support resumable development batches with stored controls and a
held-out regression guard.

### How I checked it
Reviewed benchmark results and automated-check output and directed further
fixes. Manually reviewed generated labels during this evaluation work.
The committed tests check batch completion, control validity, trace
recording and guard behaviour; their presence alone does not establish a
successful live guard run.

### What I kept or changed
Kept the two-condition comparison and trace/batch/guard tooling. Iterated on
unsupported evidence, error records, control reuse and preventing held-out
per-case console output from leaking through the guard. Removed Kev
reasoning from stored traces.

## 2026-10-29 – 2026-11-01 · Context-budget failures and bounded investigator answers
- **Tool (model):** Pi (primarily GPT-6.1-sol)
- **Files:** src/lgtm/agents/base.py, src/lgtm/agents/investigator.py, src/lgtm/agents/tools.py, src/lgtm/agents/authz_reviewer.py, src/lgtm/config.py, benchmark/real_world/batch.py, benchmark/guard.py, benchmark/field_trial/run_field_trial.py, benchmark/injection/run_injection_bench.py, tests/test_investigator_final_answer.py, tests/test_investigator_evidence.py, tests/test_tool_loop_context.py, tests/test_tool_loop_window.py
- **Outcome:** Changed

### What I asked for
Fix failures visible in benchmark output, especially incomplete investigator
answers and requests that exceeded the context window. Bound tool results
and preserve room for closing and re-ask requests.

### How I checked it
Used benchmark output and tests to assess the fixes. Read the results and
requested further AI revisions rather than treating a first passing test
as the end of the investigation.

### What I kept or changed
Kept bounded evidence and explicit final-answer handling. Iterated on
output allowances, context headroom, repeated reads, per-call reserves,
paired tool history and preserving tool-call markup. Also revised harness
GPU selection and failure accounting as problems appeared.

## 2026-11-06 · Elided citation quotes and unreadable-source judgments
- **Tool (model):** Pi (primarily GPT-6.1-sol)
- **Files:** src/lgtm/validation/evidence.py, src/lgtm/validation/judge.py, tests/test_validation.py, tests/test_judge.py, tests/test_e2e_review_judge.py
- **Outcome:** Changed

### What I asked for
Fix citation validation for quotes containing standalone ellipsis lines,
and avoid sending a finding to Kev when no readable cited source could
reach the judge.

### How I checked it
Reviewed benchmark output and tests while iterating on the fix. Regression
cases cover elided quotes and findings without readable cited source.

### What I kept or changed
Kept support for elided citation excerpts and explicit unsupported outcomes
without a Kev call when the source is unreadable. The matching checks the
parts around an ellipsis independently; it does not establish their order
in the source.

## Reflection

### What I learned
I learned to break work into smaller tasks, but also to trust the tools more
for routine work. When an agent runs a benchmark, I am now comfortable
trusting it to calculate F1 and read the results without double-checking
every file it opens in chat. I put more attention into checking its judgments:
when I ask about a change, it can give one answer, then change its mind after
I push back a little. I need to understand the reasons, not just accept a
confident answer.

### Strengths and weaknesses
The tools were fast at implementation and working through results. Given
the right context, I think a model like Opus could probably design a better
system than me. The weakness is that it does not automatically have the
context we have as builders. For example, my section-based review changes
replaced the old review path, but we later restored it behind a flag so we
could reproduce earlier benchmark runs. Building the new design was not
enough; we also needed to preserve our evaluation history. That is project
context I need to make explicit, rather than expect the model to know.

### What went wrong and what I would do differently
Sometimes I was too specific: AI followed my design without questioning its
gaps. One example was increasing the investigator's final-answer allowance
without also reserving enough space for it in the context window. That
needed a separate fix. During this project, I started discussing my ideas
and asking AI to poke holes in them before building. Next time, I
would do that earlier, rather than only checking whether AI built what I asked for.
