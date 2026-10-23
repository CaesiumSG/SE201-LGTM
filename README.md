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

# 2. Install Ollama and pull the model
ollama pull qwen2.5-coder:7b    # default; any tool-calling model works
ollama serve                    # if not already running
```

## Usage

```bash
# Index the target repo's documentation (security policy, API spec, README)
lgtm index --repo /path/to/repo

# Review a PR (diff of pr-branch against base-branch)
lgtm review --repo /path/to/repo --base main --pr feature-branch \
            --model qwen2.5-coder:7b --output lgtm-output

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

## Guardrails

- Agent tools are **read-only**; file access is sandboxed to the repo.
- Code and docs are read from the **base branch only** — PR changes are
  treated as untrusted data (analyzed, never executed or obeyed).
- Tool calls are **capped** (default 5 per agent invocation).
- Every citation is **validated** post-hoc; ungrounded findings are flagged
  with `evidence_valid: false`.
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

### 4. Field trial on ordinary merged PRs

12 merged PRs from mealie (FastAPI), alerta (Flask) and redash (Flask) that
touch route handlers, permission helpers or database code. Every PR was
accepted by its maintainers, so this measures crash rate, latency and
false alarms on everyday traffic, not detection.

```bash
python benchmark/field_trial/run_field_trial.py --fetch
python benchmark/field_trial/run_field_trial.py --modes sast-only lgtm llm-only
```

| Mode | Crashes | PRs flagged `vulnerable` | Findings | Median review latency |
|---|---|---|---|---|
| A: sast-only | 0 / 12 | 0 | 0 | 4.8 s |
| B: llm-only | 0 / 12 | 0 | 23 (1 `possible`) | 14.1 s |
| **C: lgtm** | **0 / 12** | **0** | 14 (all `safe`) | 2.5 s (144 s on the 11-endpoint PR) |

No false alarms, but **10 of 12 PRs reached no LLM agent**: Semgrep found
nothing and only 2 PRs had a route decorator inside a changed hunk. On the
PR that was reviewed, the agent cited Mealie's own permission docs and
judged 11 endpoints correctly. Write-up: [`docs/field-trial.md`](docs/field-trial.md).

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
├── sast/rules/             # bundled CWE-89 semgrep rules (offline-safe)
├── rag/indexer.py          # doc discovery, chunking, ChromaDB indexing
├── rag/retriever.py        # top-k policy retrieval with line metadata
├── agents/tools.py         # read-only tools + call budget + sandboxing
├── agents/sast_triage.py   # CWE-89 triage agent
├── agents/authz_reviewer.py# CWE-639/862/863 reviewer + endpoint extraction
├── agents/plain_reviewer.py# tool-free LLM-only baseline (Baseline B)
├── validation/evidence.py  # citation validator (anti-hallucination)
└── reporting/report_builder.py  # JSON + Markdown reports
tests/                      # 231 tests, no Ollama needed
benchmark/                  # Shoply app, 36 cases, evaluate.py
benchmark/real_world/       # 12 real-world CVE cases, fetch.py, evaluate_real.py
benchmark/injection/        # 6 prompt-injection cases, run_injection_bench.py
```

## Development

```bash
pytest tests/ -q                           # unit + integration tests
python benchmark/tools/generate_cases.py   # regenerate patches + labels
```
