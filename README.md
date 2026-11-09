# LGTM — Context-Aware PR Security Agent

LGTM reviews pull requests for security vulnerabilities by combining
**deterministic SAST** (Semgrep) with **LLM agents grounded in repository
context**. Semgrep provides high-recall signal for SQL injection; local
LLM agents (Qwen via Ollama) triage those findings against the actual code
and review changed code sections against the project's *documented* security
policy (retrieved with RAG) — catching authorization flaws SAST cannot see,
while an evidence validator keeps the LLM honest.

## Scope

LGTM does two jobs:

1. Triage of Semgrep SQL injection warnings.
2. Authorization (authz) bugs that Semgrep cannot see.

Every other vulnerability class is out of scope.

## Demo

LGTM also runs as a real **GitHub App with a dashboard** (`demo/`). In the demo, an AI coding assistant (a small local
model) writes a feature for a demo shop and leaves out an ownership check; the dashboard's App tab shows what that lets
a customer do (read another customer's order and address); the pull request goes to GitHub, and LGTM's review blocks
it with an inline comment, the policy rule it breaks and a fix. Real-world replays show the same on published
advisories (taiga-back, wagtail, authentik). Runbook, setup and the demo script: [demo/README.md](demo/README.md).

## Architecture

```
            ┌──────────────────────────────────────────────────┐
 PR branch  │ 1. Context building                              │
 ──────────▶│    git diff ── changed files/lines               │
 base branch│    semgrep ── CWE-89 findings in the diff        │
 ──────────▶│    ChromaDB ── security-policy / api-spec chunks │
            └───────────────┬──────────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────────┐
            │ 2. SAST Triage Agent (CWE-89)                    │
            │    true positive or parameterized false alarm?   │
            │ 3. Authorization Reviewer Agent                  │
            │    (CWE-639 / CWE-862 / CWE-863)                 │
            │    does the change respect the documented policy?│
            │    Tools (read-only, max 5 calls per section):   │
            │    investigate_base_code · investigate_pr_code   │
            │    read_file · grep_repo · search_policy         │
            └───────────────┬──────────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────────┐
            │ 4. Evidence Validator                            │
            │    cited files/lines/snippets/policy must exist  │
            │ 5. Report Builder ── report.json + report.md     │
            └──────────────────────────────────────────────────┘
```

The investigator groups the PR's changed hunks into sections. Hunks it does
not place, and investigator failures, fall back to per-file sections. Every
Python hunk is reviewed, including deletions. Each section gets one authz
review that can return several findings. Overlapping duplicates are merged
and the Kev-4B judge decides whether the cited code supports each finding.

Each candidate is reported as supported, unsupported or not judged, with
the judge confidence, CWE, evidence citations, and a suggested fix.

## Setup

Requirements: Python 3.13+, git, and for the full pipeline
[Ollama](https://ollama.com) + Semgrep.

Optional: [CodeGraph](https://www.npmjs.com/package/@colbymchenry/codegraph)
on `PATH` enables the `investigate_base_code` / `investigate_pr_code` tools
(tested with 1.6.2):

```bash
npm install -g @colbymchenry/codegraph@1.6.2
codegraph --version
```

Without it (or with `--no-graph`) the agents use `read_file`, `grep_repo` and
`search_policy` only; verdicts are never adjusted for the graph's absence.

```bash
# 1. Install LGTM (editable) + dev and SAST extras
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" semgrep

# 2. A model: local Ollama (the default endpoint, http://localhost:11434) ...
ollama pull qwen3.8:27b         # the default model; any tool-calling model works with --model
# ... or the SCIS GPU cluster tunnel (see model/README.md), then --gpu-model qwen3.8-27b
model/deploy/up.sh
```

## Usage

```bash
# Index the docs committed on the base branch (security policy, API spec, README)
lgtm index --repo /path/to/repo --ref main

# Review a PR (diff of pr-branch against base-branch)
lgtm review --repo /path/to/repo --base main --pr feature-branch \
            --model qwen3.8:27b --output lgtm-output

# Baseline for comparison
lgtm review ... --mode llm-only      # one LLM call on the diff,
                                     #   no Semgrep, no RAG, no tools

# Prompt-injection mitigations (both ON by default in lgtm mode; the
# llm-only baseline always sees the raw diff)
lgtm review ... --no-strip-comments           # keep comments/docstrings in the
                                              #   PR code the LLM sees
lgtm review ... --no-detect-prompt-injection  # don't report reviewer-directed
                                              #   text in the diff as a finding
```

`sast-only` and `lgtm-no-sast` are for internal development and benchmarking
only. Reported results compare `lgtm` (which includes Kev judging) against
`llm-only`.

Outputs `lgtm-output/report.json` (machine-readable findings) and
`lgtm-output/report.md` (human-readable review). Both list supported,
unsupported and not judged candidates, supported first.

Exit code of `lgtm review`: 1 if any candidate is supported and the judge's
verdict for it is not `not_real`, or the `llm-only` baseline
reports a vulnerable finding; otherwise 2 if any candidate is not judged, any agent errored,
or the PR changes a policy document and `fail_on_policy_change` is on (see [Policy index](#policy-index));
otherwise 0 (CI-friendly). A supported candidate with verdict `not_real` is
not a vulnerability: it is listed as "not real" in the reports and does not
set exit code 1.

`--gpu-model qwen3.8-27b` connects through the existing GPU cluster
tunnel at `http://127.0.0.1:11435` with the model `qwen3.8:27b` and
thinking disabled. It cannot be combined with `--gpu-cluster` or
`--model`; `--ollama-url` overrides the URL. The registry URL assumes
`LOCAL_OLLAMA_PORT=11435`. `benchmark/evaluate.py` and
`benchmark/real_world/evaluate_real.py` accept the same flag.

## Configuration

Settings are read from a JSON file passed with `--config-file`.

### CodeGraph

The `lgtm` mode uses CodeGraph when `graph_enabled` is
true (the default) and the binary is found. The `llm-only`
baseline never uses it. `--no-graph` (or `"graph_enabled": false`) reviews
without it; so does a missing binary, with a warning. In both cases the
agents keep `read_file`, `grep_repo` and `search_policy`, and no verdict is
changed because the graph was absent.

### Authorization planner

`authz_planner` (CLI `--authz-planner`) decides what the authorization agent
looks at: `investigator` (default) has an LLM group every changed Python
hunk into review sections, so the whole PR is reviewed; `endpoint` reviews
only hunks that contain a Flask/FastAPI route decorator, one section per
file, with no investigator. `endpoint` is the checkpoint pipeline's gating,
kept so the 13 Oct numbers can be reproduced and the two compared on the
same cases (the real-world evaluation and the field trial showed the gating
skips most real authorization changes).

| Key | Default | Limits |
|---|---|---|
| `graph_binary` | `"codegraph"` | Executable name or path, no arguments |
| `graph_init_timeout_s` | `120` | Must be positive |
| `graph_query_timeout_s` | `20` | Must be positive |
| `graph_max_output_chars` | `6000` | At least `1024`; values above `6000` are reduced to `6000` |
| `graph_max_export_files` | `20000` | Must be positive; values above `20000` are reduced to `20000` |
| `graph_max_export_bytes` | `209715200` | Must be positive; values above `209715200` are reduced to `209715200` |

Each snapshot (`base`, `pr`) is exported to a temporary directory and indexed
on first use. Graph queries read the committed commit only, not the working
tree. If the graph fails for a snapshot (timeout, non-zero exit, export
error), that snapshot's graph tools are skipped for the rest of the run and
agents use `read_file` or `grep_repo` with the same snapshot label. A launch
failure affects both snapshots.

The run's graph state is written to `graph_state` in `report.json` and to
the benchmark records:

- `ok`: no graph failures
- `unavailable:missing`: the `codegraph` binary was not found
- `degraded:<label>:<reason>`: the graph failed for that snapshot; multiple
  entries are separated by `;`

### Policy index

The base branch's docs are the security policy. A PR cannot change the policy
it is reviewed against:

- `lgtm index --ref <commit>` (default `HEAD`) reads the `.md`, `.txt` and
  `.rst` files committed at that commit, never the working tree, and records
  the commit in the index. Uncommitted and untracked docs are not indexed.
- `lgtm review` uses the index only when it was built from the base commit.
  Otherwise it warns, prints the `lgtm index` command to run, and reviews with
  code evidence only. `policy_index` in `report.json` is `ok`, `missing` or
  `stale:<commit the index was built from>`.
- A PR that adds, edits, renames or deletes any of those docs is listed under
  "Policy Documents Changed: Needs Human Review" in `report.md` and in
  `policy_docs_changed` in `report.json`. This does not change the exit code
  unless `fail_on_policy_change` is set to `true` in the config file; then it
  sets exit code 2 when nothing is supported. The review itself still reads
  the base versions.

The policy index is stored in `.lgtm/chroma` inside the reviewed repository.
Deleting that directory also deletes the index, so run
`lgtm index --repo /path/to/repo --ref <base>` again before the next review. Indexing
replaces only the policy collection (`lgtm_docs`); LGTM does not clean up
other collections automatically. Config keys that no longer exist
are ignored with an `Ignoring unknown config keys` warning.

## Guardrails

- Agent tools are **read-only**; file access is sandboxed to the repo.
- Agents read committed snapshots of the **base** and **PR** branches. Each
  branch is resolved once to a full commit SHA before the run starts. PR
  content is treated as untrusted data (analyzed, never executed or obeyed).
- Each SAST triage run (one finding) and each authz section review has a
  budget of **5 tool calls** (`max_tool_calls`) shared by all of its tools,
  including calls with invalid arguments or unknown tool names. Once the
  budget is spent, tools return a budget error. The investigator has its own
  budget.
- LLM calls are **retried** up to 3 times with 2s, 4s and 8s backoff
  before an agent run is reported as failed.
- Tool arguments are **validated** against each tool's schema before the
  tool runs. Invalid calls return an error to the agent and count toward the
  tool-call budget. The third invalid call in a run forces the final answer.
- Final answers that are not valid JSON are **re-requested** up to 3 times.
- Every code citation is **annotated** post-hoc with `grounded_in_pr`. A
  citation labelled `base` or `pr` must name a file in that committed
  snapshot, and any line range must be ordered, positive and inside the file.
- Human-in-the-loop: LGTM reports, it never auto-fixes.

## Benchmarks

There are **three separate benchmarks**. Each one answers a different
question, has its own script and its own metric:

| Benchmark | Question | Cases | Script | Metric | Write-up |
|---|---|---|---|---|---|
| **Shoply** (synthetic) | Does LGTM catch vulnerabilities, without false alarms? | 52 (dev 26 / eval 26) | `benchmark/evaluate.py` | Precision / recall / F1 | `docs/evaluation-log.md` |
| **Real-world CVEs** | Does that hold on code real developers shipped? | 12 (development set) | `benchmark/real_world/evaluate_real.py` | Precision / recall / F1 | [`docs/real-world-eval.md`](docs/real-world-eval.md) |
| **Prompt injection** | Can text in a PR trick LGTM into missing a vulnerability? | 6 attacks on Shoply cases | `benchmark/injection/run_injection_bench.py` | Attack success rate | [`docs/prompt-injection.md`](docs/prompt-injection.md) |

The Shoply files (`app/`, `cases/`, `labels.json`, the policy docs and
`evaluate.py`) sit at the top of `benchmark/` because Shoply came first;
`evaluate.py` evaluates **only Shoply**, not the other two. Its `--split eval`
means the 26 held-out *Shoply* cases.

**Why the results aren't combined into one score:** the benchmarks measure
different things (accuracy vs. resistance to attack) with different metrics,
and they differ in how independent they are: Shoply's dev split was used to
tune the prompts, and the real-world cases are tuned on too; both are
development sets, while the eval split is held out. One
pooled F1 would mix tuned and untuned data and hide the drop on real code.
Read them side by side; the [summary at the end of this
section](#all-results-at-a-glance) does that.

### 1. Shoply (synthetic)

`benchmark/` contains **Shoply**, a Flask e-commerce API with token auth
and RBAC, plus **26 matched PR pairs** (52 cases): 12 SQL-injection pairs
(6 hand-written + 6 derived from the OWASP Benchmark SQLi taxonomy,
translated to Python/Flask; vulnerable vs
parameterized-but-SAST-triggering controls) and 14 authorization pairs
(IDOR, missing/incorrect role checks, API-key scope violations —
invisible to SAST by design).

```bash
python benchmark/evaluate.py --gpu-cluster --mode lgtm
python benchmark/evaluate.py --gpu-cluster --mode llm-only
python benchmark/evaluate.py --gpu-cluster --mode lgtm --split eval   # held-out half only
```

The benchmarks run two conditions: LGTM (the full pipeline, including
Semgrep) and LLM-only. The reviewer is `qwen3.8:27b` on the SCIS GPU cluster
and the judge is Kev (Kev-4B). Claude Opus 5.5 labels the benchmark
findings under `docs/kev-labeling-criteria.md`.

Reported metrics: precision / recall / F1 (overall and per category),
false-positive rate on safe controls, evidence grounding rate,
`possible` / `insufficient_evidence` rates, median latency, and median
tokens per PR. See `benchmark/README.md` for details.

Token counts are what the model backends report (Ollama's prompt and output
counts, Bedrock's input including cached prompt tokens, and Kev's input
tokens), summed per review in `lgtm.usage`. Each report carries them under
`review.token_usage`, split by stage (investigator, reviewers, SAST triage,
plain reviewer). Each benchmark record has `input_tokens`, `output_tokens`,
`total_tokens` and `judge_input_tokens`, and the summaries add a `tokens`
block of medians. Ollama may count fewer prompt tokens when it reuses its
prompt cache, so `estimated_input_tokens` (prompt characters / 4) is kept as
a cross-check. The older `est_tokens` field only sizes the findings JSON and
is not a token count.

A case where the pipeline raises, or where an agent reports an
execution, LLM or unparsable-output failure, is recorded as `ERROR`.
Errors are left out of TP/FP/TN/FN and out of precision, recall and F1.
The summary reports `scored`, `errors`, `error_rate` and `error_cases`,
and metrics that cannot be computed are `null`.

The 52 cases carry a balanced **dev/eval split** (13 vulnerable + 13 safe in
each), recorded in the `split` field of `labels.json`: tune prompts and
config on `--split dev`, report results on the held-out `--split eval`.

Results: the run writes its summary to the Shoply run folder under
`benchmark/runs/` (`summary.json`).

### 2. Real-world CVEs

12 cases built from 6 published advisories in open-source Python
projects (3 SQLi, 3 authz; a vulnerable and a safe PR each). The real-world
set is the development set: prompts, rules and config are tuned against it.
The synthetic eval split (`--split eval`) is the held-out check.
`alerta_sqli_vulnerable`, `alerta_sqli_safe` and
`postgraas_sqli_safe` are out of scope.

```bash
python benchmark/real_world/fetch.py                     # clone + build case branches
python benchmark/real_world/evaluate_real.py --gpu-model qwen3.8-27b --modes lgtm llm-only
python benchmark/real_world/batch.py <results-root>      # next unrun batch of the real-world set
python benchmark/guard.py <results-root>                 # eval split in lgtm mode, flips against the last guard run
```

Each `batch.py` run writes `batch-<n>/bundle.json` under the results root when
the batch finishes; running the same command again continues with the next
unrun batch. `guard.py` writes `guard/flips.json` under the results root. See
[`benchmark/real_world/README.md`](benchmark/real_world/README.md).

Results: `benchmark/runs/archive/real_world/summary.json`; write-up in
[`docs/real-world-eval.md`](docs/real-world-eval.md).

### 3. Prompt injection

6 attack cases: vulnerable Shoply cases with the vulnerable code unchanged,
plus comments, docstrings, fake JSON findings, renamed identifiers or docs
aimed at the reviewer. **Attack success rate (ASR)** = cases flagged
`vulnerable` originally but not once injected, out of those flagged
originally (lower is better).

```bash
python benchmark/injection/run_injection_bench.py --mode lgtm --model qwen3.8:27b
python benchmark/injection/run_injection_bench.py --mode llm-only --model qwen3.8:27b
```

Results: `benchmark/runs/archive/injection-results/` (see
[`docs/prompt-injection.md`](docs/prompt-injection.md)). The mitigations are
on by default in lgtm mode (§7 there; the dev-split comparison is archived in
`benchmark/runs/archive/run7-mitigation-defaults/`).

### 4. Field trial on ordinary merged PRs

12 merged PRs from mealie (FastAPI), alerta (Flask) and redash (Flask) that
touch route handlers, permission helpers or database code. Every PR was
accepted by its maintainers, so this measures crash rate, latency and
false alarms on everyday traffic, not detection.

```bash
python benchmark/field_trial/run_field_trial.py --fetch
python benchmark/field_trial/run_field_trial.py --modes lgtm llm-only
```

Results: `benchmark/runs/archive/field_trial/summary.json`; write-up in
[`docs/field-trial.md`](docs/field-trial.md).

### All results at a glance

The per-benchmark result files above hold the figures for the LGTM and
LLM-only conditions.

The full history of rounds, failures, fixes and lessons is in
[`docs/evaluation-log.md`](docs/evaluation-log.md); the checkpoint report
is [`docs/checkpoint.md`](docs/checkpoint.md).

### Dataset roadmap

- ✅ 6 SQLi pairs derived from the OWASP Benchmark taxonomy (Java →
  Python/Flask translation), keeping positives and negatives balanced.
- ✅ 6 published CVEs in real Python web projects (3 SQLi, 3 authz) as 12
  development-set cases; see
  [`docs/real-world-eval.md`](docs/real-world-eval.md).
- ✅ 6 prompt-injection cases (comments, docstrings, fake JSON findings,
  renamed identifiers, a policy-exemption doc, delimiter escapes); see
  [`docs/prompt-injection.md`](docs/prompt-injection.md).
- Next: more OWASP patterns (stacked queries, second-order injection) and
  more CVE-linked cases, including real vulnerable PRs rather than reverts.
- Keep the eval split held out: prompt and config tuning uses the dev split
  and the real-world set only.

## Project layout

```
src/lgtm/
├── cli.py                  # click CLI: lgtm index / lgtm review
├── config.py               # LGTMConfig dataclass
├── pipeline.py             # orchestrator (lgtm / llm-only)
├── diff/git_diff.py        # git diff extraction + unified diff parser
├── diff/sanitizer.py       # comment stripper + prompt-injection detector
├── analysis/facts.py       # AST facts for the agents (static_facts flag)
├── sast/semgrep_runner.py  # semgrep subprocess + JSON parsing
├── sast/rules/             # bundled CWE-89 semgrep rules
├── rag/indexer.py          # doc discovery, chunking, ChromaDB indexing
├── rag/retriever.py        # top-k policy retrieval with line metadata
├── graph/runner.py         # codegraph subprocess: init and explore, timeouts
├── graph/session.py        # per-snapshot graph session and failure state
├── graph/exporter.py       # committed-snapshot export to temporary directories
├── graph/snapshot.py       # commit SHA resolution
├── graph/format.py         # tool output formatting
├── agents/tools.py         # read-only snapshot tools, graph tools, call budget
├── agents/sast_triage.py   # CWE-89 triage agent
├── agents/authz_reviewer.py# CWE-639/862/863 section reviewer
├── agents/plain_reviewer.py# tool-free LLM-only baseline (Baseline B)
├── validation/evidence.py  # citation validator (anti-hallucination)
└── reporting/report_builder.py  # JSON + Markdown reports
tests/                      # unit and integration tests, no Ollama needed
benchmark/                  # Shoply app, 52 cases, evaluate.py
benchmark/real_world/       # 12 real-world CVE cases, fetch.py, evaluate_real.py
benchmark/injection/        # 6 prompt-injection cases, run_injection_bench.py
```

## Development

```bash
pytest tests/ -q                           # unit + integration tests
python benchmark/tools/generate_cases.py   # regenerate patches + labels
```
