# LGTM — Context-Aware PR Security Agent

LGTM reviews pull requests for security vulnerabilities by combining
**deterministic SAST** (Semgrep) with **LLM agents grounded in repository
context**. Semgrep provides high-recall signal for SQL injection; local
LLM agents (Qwen via Ollama) triage those findings against the actual code
and review changed code sections against the project's *documented* security
policy (retrieved with RAG) — catching authorization flaws SAST cannot see,
while an evidence validator keeps the LLM honest.

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
review that can return several findings. Findings with the `safe` verdict are
dropped, overlapping duplicates are merged, and the evidence is validated.

Verdicts per finding: `vulnerable` · `safe` · `possible` ·
`insufficient_evidence`, each with confidence, CWE, evidence citations, and
a suggested fix.

## Setup

Requirements: Python 3.10+, git, and for the full pipeline
[Ollama](https://ollama.com) + Semgrep.

Optional: Node.js and the `codegraph` CLI on `PATH` enable the
`investigate_base_code` and `investigate_pr_code` tools. Without it, only
`read_file`, `grep_repo` and `search_policy` are offered.

```bash
# 1. Install LGTM (editable) + dev and SAST extras
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" semgrep

# 2. Open the GPU cluster tunnel (default endpoint http://127.0.0.1:11435)
model/deploy/up.sh              # see model/README.md
```

A local Ollama works with `--ollama-url http://localhost:11434` after
`ollama pull qwen3.8:27b`; any tool-calling model works with `--model`.

## Usage

```bash
# Index the target repo's documentation (security policy, API spec, README)
lgtm index --repo /path/to/repo

# Review a PR (diff of pr-branch against base-branch)
lgtm review --repo /path/to/repo --base main --pr feature-branch \
            --model qwen3.8:27b --output lgtm-output

# Baselines for comparison
lgtm review ... --mode sast-only     # Baseline A: Semgrep only, no LLM
lgtm review ... --mode llm-only      # Baseline B: one LLM call on the diff,
                                     #   no Semgrep, no RAG, no tools
lgtm review ... --mode lgtm-no-sast  # Ablation: LGTM agents + RAG + tools,
                                     #   regex SQL detector instead of Semgrep

# Prompt-injection mitigations (both off by default)
lgtm review ... --strip-comments           # remove comments/docstrings from
                                           #   PR code before the LLM sees it
lgtm review ... --detect-prompt-injection  # flag reviewer-directed text in
                                           #   the diff as its own finding
```

Outputs `lgtm-output/report.json` (machine-readable findings) and
`lgtm-output/report.md` (human-readable review). Exit code 1 signals
confirmed `vulnerable` findings (CI-friendly).

`--gpu-model qwen3.8-27b` connects through the existing GPU cluster
tunnel at `http://127.0.0.1:11435` with the model `qwen3.8:27b` and
thinking disabled. It cannot be combined with `--gpu-cluster` or
`--model`; `--ollama-url` overrides the URL. The registry URL assumes
`LOCAL_OLLAMA_PORT=11435`. `benchmark/evaluate.py` and
`benchmark/real_world/evaluate_real.py` accept the same flag.

## Configuration

Settings are read from a JSON file passed with `--config-file`.

### CodeGraph

The `lgtm` and `lgtm-no-sast` modes use CodeGraph when the binary is found.
The `sast-only` and `llm-only` baselines never use it. There is no setting
or CLI flag that turns the graph off.

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

The policy index is stored in `.lgtm/chroma` inside the reviewed repository.
Deleting that directory also deletes the index, so run
`lgtm index --repo /path/to/repo` again before the next review. Indexing
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
- Every citation is **validated** post-hoc; ungrounded findings are flagged
  with `evidence_valid: false`. A citation labelled `base` or `pr` must name a
  file in that committed snapshot, and any line range must be ordered,
  positive and inside the file. The snippet must appear in that file.
- A `vulnerable` verdict is **downgraded to `possible`** when the PR graph was
  unavailable for the finding and no valid code citation validated against the
  PR snapshot or the PR diff. Any one such citation is enough to keep the
  verdict.
- Human-in-the-loop: LGTM reports, it never auto-fixes.

## Benchmarks

There are **three separate benchmarks**. Each one answers a different
question, has its own script and its own metric:

| Benchmark | Question | Cases | Script | Metric | Write-up |
|---|---|---|---|---|---|
| **Shoply** (synthetic) | Does LGTM catch vulnerabilities, without false alarms? | 36 (dev 18 / eval 18) | `benchmark/evaluate.py` | Precision / recall / F1 | `docs/evaluation-log.md` |
| **Real-world CVEs** | Does that hold on code real developers shipped? | 12 (held out) | `benchmark/real_world/evaluate_real.py` | Precision / recall / F1 | [`docs/real-world-eval.md`](docs/real-world-eval.md) |
| **Prompt injection** | Can text in a PR trick LGTM into missing a vulnerability? | 6 attacks on Shoply cases | `benchmark/injection/run_injection_bench.py` | Attack success rate | [`docs/prompt-injection.md`](docs/prompt-injection.md) |

The Shoply files (`app/`, `cases/`, `labels.json`, the policy docs and
`evaluate.py`) sit at the top of `benchmark/` because Shoply came first;
`evaluate.py` evaluates **only Shoply**, not the other two. Its `--split eval`
means the 18 held-out *Shoply* cases.

**Why the results aren't combined into one score:** the benchmarks measure
different things (accuracy vs. resistance to attack) with different metrics,
and they differ in how independent they are: Shoply's dev split was used to
tune the prompts, the eval split and the real-world cases never were. One
pooled F1 would mix tuned and untuned data and hide the drop on real code.
Read them side by side; the [summary at the end of this
section](#all-results-at-a-glance) does that.

### 1. Shoply (synthetic)

`benchmark/` contains **Shoply**, a Flask e-commerce API with token auth
and RBAC, plus **18 matched PR pairs** (36 cases): 12 SQL-injection pairs
(6 hand-written + 6 derived from the OWASP Benchmark SQLi taxonomy,
translated to Python/Flask; vulnerable vs
parameterized-but-SAST-triggering controls) and 6 authorization pairs
(IDOR, missing/incorrect role checks, API-key scope violations —
invisible to SAST by design).

> Results measured at an earlier commit; not re-measured for the current code.

```bash
python benchmark/evaluate.py --mode lgtm
python benchmark/evaluate.py --mode sast-only
python benchmark/evaluate.py --mode llm-only
python benchmark/evaluate.py --mode lgtm --split eval   # held-out half only
```

Reported metrics: precision / recall / F1 (overall and per category),
false-positive rate on safe controls, evidence grounding rate,
`possible` / `insufficient_evidence` rates, median latency and estimated
tokens per PR. See `benchmark/README.md` for details.

A case where the pipeline raises, or where an agent reports an
execution, LLM or unparsable-output failure, is recorded as `ERROR`.
Errors are left out of TP/FP/TN/FN and out of precision, recall and F1.
The summary reports `scored`, `errors`, `error_rate` and `error_cases`,
and metrics that cannot be computed are `null`.

The 36 cases carry a balanced **dev/eval split** (9 vulnerable + 9 safe in
each), recorded in the `split` field of `labels.json`: tune prompts and
config on `--split dev`, report results on the held-out `--split eval`.

Reference results (13 Oct 2026, all 36 cases, `qwen2.5-coder:7b` local;
baselines from `benchmark/runs/run3-bugfixes/`, LGTM from the final clean
run in `benchmark/runs/run6-final/`):

| Mode | Precision | Recall | F1 | SQLi F1 | Authz F1 | FP rate (safe) | Grounding | Median latency |
|---|---|---|---|---|---|---|---|---|
| A: sast-only | 0.57 | 0.67 | 0.62 | 0.73 | 0.00 | 0.50 (SQLi 0.75) | 1.00 | 1.8s |
| B: llm-only | 0.86 | 0.67 | 0.75 | 0.92 | 0.00 | 0.11 | 0.78 | 11.9s |
| ablation: lgtm-no-sast | 0.90 | 0.94 | 0.92 | 0.92 | 0.92 | 0.11 | 0.90 | 20.5s |
| **C: lgtm** | **0.94** | **0.94** | **0.94** | **0.96** | **0.92** | **0.06** | 0.93 | 21.3s |

Held-out eval split only (n=18): sast-only F1 0.63 · llm-only 0.75 ·
lgtm-no-sast 0.89 · **lgtm 0.89**. Counting only detections whose evidence
validated, lgtm's eval F1 is 0.82.

What the numbers say:

- **Policy retrieval is what makes authorization review possible.** The
  bare LLM (Baseline B) catches 0 of 6 authz flaws. Without the policy it
  can only say `possible`, and it says that about safe PRs too.
- **SAST + triage removes SAST's false positives.** Semgrep false-alarms
  on 75% of the safe parameterized SQL; LGTM on 0%. It catches 11 of 12
  SQLi flaws; the miss (`sqli_04`) is a triage error that flips between
  runs.
- **LGTM vs its no-SAST ablation is within one case** (0.94 vs 0.92). Most
  of the gain over the baselines comes from the policy-grounded LLM, not
  from Semgrep.
- **Known weaknesses** (details in `docs/evaluation-log.md`):
  - The authz agent raises *off-category* ownership warnings on 22 of the
    24 SQLi cases (92%), on endpoints that already have the right role
    check. Case-level F1 doesn't count these.
  - The 7B model almost never uses its tools unless forced.
  - Verdicts can flip on irrelevant prompt changes. With 18 eval cases, one
    flip is ±0.05 F1.

### 2. Real-world CVEs

12 held-out cases built from 6 published advisories in open-source Python
projects (3 SQLi, 3 authz; a vulnerable and a safe PR each). Nothing was
tuned on them. The authz cases also run with a short policy written from
each project's docs (the `policy` variant).

> Results measured at an earlier commit; not re-measured for the current code.

```bash
python benchmark/real_world/fetch.py --policies          # clone + build case branches
python benchmark/real_world/evaluate_real.py --modes sast-only lgtm
```

Results (12 cases, the projects' own docs; from
[`docs/real-world-eval.md`](docs/real-world-eval.md)):

| Mode | Precision | Recall | F1 | SQLi F1 | Authz F1 | FP rate (safe) | Median latency |
|---|---|---|---|---|---|---|---|
| A: sast-only | 0.67 | 0.33 | 0.44 | 0.67 | 0.00 | 0.17 | 12.1s |
| **B: llm-only** | **1.00** | **0.67** | **0.80** | **0.80** | **0.80** | **0.00** | 68.7s |
| ablation: lgtm-no-sast | 0.67 | 0.33 | 0.44 | 0.80 | 0.00 | 0.17 | 39.6s |
| C: lgtm | 0.67 | 0.33 | 0.44 | 0.80 | 0.00 | 0.17 | 16.6s |

With the project policy, lgtm's authz F1 rises from 0.00 to 0.40 (6 authz
cases). **LGTM did not reproduce its Shoply result:** SQLi triage carried
over, but in 4 of 6 authz cases the endpoint detector never sent the code to
the agent. With 12 cases, one flipped verdict moves recall by up to 0.17.

### 3. Prompt injection

6 attack cases: vulnerable Shoply cases with the vulnerable code unchanged,
plus comments, docstrings, fake JSON findings, renamed identifiers or docs
aimed at the reviewer. **Attack success rate (ASR)** = cases flagged
`vulnerable` originally but not once injected, out of those flagged
originally (lower is better).

> Results measured at an earlier commit; not re-measured for the current code.

```bash
python benchmark/injection/run_injection_bench.py --mode sast-only
python benchmark/injection/run_injection_bench.py --mode lgtm \
       --strip-comments --detect-injection
```

| Mode | ASR | What happened |
|---|---|---|
| A: sast-only | 0% (0/3) | Semgrep ignores comments and docstrings |
| B: llm-only | 0% (0/3) | Still flagged all 3 SQLi cases |
| **C: lgtm, no mitigation** | **100% (3/3)** | Triage agent downgraded all 3 SQLi detections (2 to `possible`, 1 to `safe`) |
| C: lgtm + `--strip-comments` + `--detect-prompt-injection` | 0% (0/3) | Reported in [`docs/prompt-injection.md`](docs/prompt-injection.md) |

Only the 3 SQLi attacks are counted: none of the modes flagged the 3 authz
originals as `vulnerable` in this harness, so no authz attack could succeed.
The committed run files in `benchmark/injection/results/` cover the three
unmitigated rows.

### All results at a glance

| Mode | Shoply F1, all 36 (eval 18) | Real-world F1 (12) | Injection ASR (lower is better) |
|---|---|---|---|
| A: sast-only | 0.62 (0.63) | 0.44 | 0% |
| B: llm-only | 0.75 (0.75) | **0.80** | 0% |
| ablation: lgtm-no-sast | 0.92 (0.89) | 0.44 | not run |
| C: lgtm | **0.94** (**0.89**) | 0.44 | 100% unmitigated, 0% mitigated |

LGTM is best on the benchmark it was tuned for, falls to the SAST baseline
on real code, and needs the injection mitigations to hold up against a
malicious PR.

The full history of rounds, failures, fixes and lessons is in
[`docs/evaluation-log.md`](docs/evaluation-log.md); the checkpoint report
is [`docs/checkpoint.md`](docs/checkpoint.md).

### Dataset roadmap

- ✅ 6 SQLi pairs derived from the OWASP Benchmark taxonomy (Java →
  Python/Flask translation), keeping positives and negatives balanced.
- ✅ 6 published CVEs in real Python web projects (3 SQLi, 3 authz) as 12
  held-out cases, with a project-policy variant for the authz cases. LGTM did
  not reproduce its Shoply results there; see
  [`docs/real-world-eval.md`](docs/real-world-eval.md).
- ✅ 6 prompt-injection cases (comments, docstrings, fake JSON findings,
  renamed identifiers, a policy-exemption doc, delimiter escapes); see
  [`docs/prompt-injection.md`](docs/prompt-injection.md).
- Next: more OWASP patterns (stacked queries, second-order injection) and
  more CVE-linked cases, including real vulnerable PRs rather than reverts.
- Keep the dev/eval separation strict: all prompt and config tuning on the
  dev split only.

## Project layout

```
src/lgtm/
├── cli.py                  # click CLI: lgtm index / lgtm review
├── config.py               # LGTMConfig dataclass
├── pipeline.py             # orchestrator (lgtm / sast-only / llm-only / lgtm-no-sast)
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
benchmark/                  # Shoply app, 36 cases, evaluate.py
benchmark/real_world/       # 12 real-world CVE cases, fetch.py, evaluate_real.py
benchmark/injection/        # 6 prompt-injection cases, run_injection_bench.py
```

## Development

```bash
pytest tests/ -q                           # unit + integration tests
python benchmark/tools/generate_cases.py   # regenerate patches + labels
```
