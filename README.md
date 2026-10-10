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

# 2. Install Ollama and pull the model
ollama pull qwen2.5:7b          # default; any tool-calling model works
ollama serve                    # if not already running
```

## Usage

```bash
# Index the target repo's documentation (security policy, API spec, README)
lgtm index --repo /path/to/repo

# Review a PR (diff of pr-branch against base-branch)
lgtm review --repo /path/to/repo --base main --pr feature-branch \
            --model qwen2.5:7b --output lgtm-output

# Baselines for comparison
lgtm review ... --mode sast-only   # Semgrep only, no LLM
lgtm review ... --mode llm-only    # LLM agents without Semgrep seeding
```

Outputs `lgtm-output/report.json` (machine-readable findings) and
`lgtm-output/report.md` (human-readable review). Exit code 1 signals
confirmed `vulnerable` findings (CI-friendly).

## Guardrails

- Agent tools are **read-only**; file access is sandboxed to the repo.
- Code and docs are read from the **base branch only** — PR changes are
  treated as untrusted data (analyzed, never executed or obeyed).
- Tool calls are **capped** (default 5 per agent invocation).
- Every citation is **validated** post-hoc; ungrounded findings are flagged
  with `evidence_valid: false`.
- Human-in-the-loop: LGTM reports, it never auto-fixes.

## Benchmark

`benchmark/` contains **Shoply**, a Flask e-commerce API with token auth
and RBAC, plus **12 matched PR pairs** (24 cases): 6 SQL-injection pairs
(vulnerable vs parameterized-but-SAST-triggering controls) and 6
authorization pairs (IDOR, missing/incorrect role checks, API-key scope
violations — invisible to SAST by design).

```bash
python benchmark/evaluate.py --mode lgtm
python benchmark/evaluate.py --mode sast-only
python benchmark/evaluate.py --mode llm-only
```

Reported metrics: precision / recall / F1 (overall and per category),
false-positive rate on safe controls, evidence grounding rate,
`possible` / `insufficient_evidence` rates, median latency and estimated
tokens per PR. See `benchmark/README.md` for details.

Reference run (sast-only baseline, local semgrep + bundled CWE-89 rules):
SQLi recall 1.0 but 83% FP rate on the safe SQLi controls, and 0 recall on
authorization cases — precisely the gap the LLM stages close.

## Project layout

```
src/lgtm/
├── cli.py                  # click CLI: lgtm index / lgtm review
├── config.py               # LGTMConfig dataclass
├── pipeline.py             # orchestrator (lgtm / sast-only / llm-only)
├── diff/git_diff.py        # git diff extraction + unified diff parser
├── sast/semgrep_runner.py  # semgrep subprocess + JSON parsing
├── sast/rules/             # bundled CWE-89 semgrep rules (offline-safe)
├── rag/indexer.py          # doc discovery, chunking, ChromaDB indexing
├── rag/retriever.py        # top-k policy retrieval with line metadata
├── agents/tools.py         # read-only tools + call budget + sandboxing
├── agents/sast_triage.py   # CWE-89 triage agent
├── agents/authz_reviewer.py# CWE-639/862/863 reviewer + endpoint extraction
├── validation/evidence.py  # citation validator (anti-hallucination)
└── reporting/report_builder.py  # JSON + Markdown reports
tests/                      # 105 tests, no Ollama/Semgrep needed
benchmark/                  # Shoply app, 24 cases, evaluate.py
```

## Development

```bash
pytest tests/ -q                           # unit + integration tests
python benchmark/tools/generate_cases.py   # regenerate patches + labels
```
