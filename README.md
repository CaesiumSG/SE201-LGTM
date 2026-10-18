# LGTM — Context-Aware PR Security Agent

LGTM reviews pull requests for security vulnerabilities by combining
**deterministic SAST** (Semgrep) with **LLM agents grounded in repository
context**. Semgrep provides high-recall signal for SQL injection; local
LLM agents (Qwen via Ollama) triage those findings against the actual code
and review changed endpoints against the project's *documented* security
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
            │    Tools (read-only, base branch, max 5 calls):  │
            │    read_file · grep_repo · search_policy         │
            │    search_code (semantic RAG over source)        │
            └───────────────┬──────────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────────┐
            │ 4. Evidence Validator                            │
            │    cited files/lines/snippets/policy must exist  │
            │ 5. Report Builder ── report.json + report.md     │
            └──────────────────────────────────────────────────┘
```

Verdicts per finding: `vulnerable` · `safe` · `possible` ·
`insufficient_evidence`, each with confidence, CWE, evidence citations, and
a suggested fix.

## Setup

Requirements: Python 3.10+, git, and for the full pipeline
[Ollama](https://ollama.com) + Semgrep.

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

## Guardrails

- Agent tools are **read-only**; file access is sandboxed to the repo.
- Code and docs are read from the **base branch only** — PR changes are
  treated as untrusted data (analyzed, never executed or obeyed).
- Tool calls are **capped** (default 5 per agent invocation).
- LLM calls are **retried** up to 3 times with 2s, 4s and 8s backoff
  before an agent run is reported as failed.
- Tool arguments are **validated** against each tool's schema before the
  tool runs. Invalid calls return an error to the agent without using the
  tool-call budget, and the third invalid call in a run forces the final
  answer.
- Final answers that are not valid JSON are **re-requested** up to 3 times.
- Every citation is **validated** post-hoc; ungrounded findings are flagged
  with `evidence_valid: false`.
- Human-in-the-loop: LGTM reports, it never auto-fixes.

## Benchmark

`benchmark/` contains **Shoply**, a Flask e-commerce API with token auth
and RBAC, plus **18 matched PR pairs** (36 cases): 12 SQL-injection pairs
(6 hand-written + 6 derived from the OWASP Benchmark SQLi taxonomy,
translated to Python/Flask; vulnerable vs
parameterized-but-SAST-triggering controls) and 6 authorization pairs
(IDOR, missing/incorrect role checks, API-key scope violations —
invisible to SAST by design).

```bash
python benchmark/evaluate.py --mode lgtm
python benchmark/evaluate.py --mode sast-only
python benchmark/evaluate.py --mode llm-only
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
each): tune prompts and config on `--split dev`, report results on the
held-out `--split eval`.

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
├── sast/semgrep_runner.py  # semgrep subprocess + JSON parsing
├── sast/rules/             # bundled CWE-89 semgrep rules (offline-safe)
├── rag/indexer.py          # doc discovery, chunking, ChromaDB indexing
├── rag/retriever.py        # top-k policy retrieval with line metadata
├── agents/tools.py         # read-only tools + call budget + sandboxing
├── agents/sast_triage.py   # CWE-89 triage agent
├── agents/authz_reviewer.py# CWE-639/862/863 reviewer + endpoint extraction
├── agents/plain_reviewer.py# tool-free LLM-only baseline (Baseline B)
├── validation/evidence.py  # citation validator (anti-hallucination)
└── reporting/report_builder.py  # JSON + Markdown reports
tests/                      # 158 tests, no Ollama needed
benchmark/                  # Shoply app, 36 cases, evaluate.py
```

## Development

```bash
pytest tests/ -q                           # unit + integration tests
python benchmark/tools/generate_cases.py   # regenerate patches + labels
```
