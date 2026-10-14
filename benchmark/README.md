# LGTM Benchmark — Shoply

A deliberately reviewable Flask e-commerce API plus **18 matched PR pairs**
(36 cases) used to evaluate the LGTM PR security agent.

## Layout

- `app/` — the Shoply application (Flask + SQLAlchemy, token auth, RBAC).
- `security-policy.md`, `api-spec.md` — project documents indexed by LGTM's
  RAG system; the authorization agent judges PRs against these.
- `cases/sqli/` — 12 SQL-injection pairs (CWE-89): 6 hand-written pairs
  plus 6 pairs derived from the **OWASP Benchmark** SQLi taxonomy
  (source × propagation × sink, translated from Java/servlet to
  Python/Flask idioms — header/cookie/JSON-body sources, propagation
  through variable chains and clause builders, DB-API / SQLAlchemy sinks;
  labels carry `origin: owasp-derived`). Each `*_vulnerable.patch`
  interpolates request data into SQL; the matching `*_safe.patch`
  implements the same feature with bound parameters or an allowlist. The
  safe versions still look SQL-ish enough to trigger SAST, which is the
  false-positive test.
- `cases/authz/` — 6 authorization pairs (CWE-639 / CWE-862 / CWE-863).
  These are invisible to SAST by design; only policy-aware review can catch
  them.
- `labels.json` — ground truth for all 36 cases (with dev/eval split).
- `evaluate.py` — runs LGTM on every case and reports metrics.
- `tools/generate_cases.py` — regenerates all patches and `labels.json`
  from the case definitions (patches are produced by real `git diff`, so
  they always apply cleanly).

## Running the evaluation

```bash
# From the repository root (install LGTM first: pip install -e .)
python benchmark/evaluate.py --mode lgtm            # full pipeline
python benchmark/evaluate.py --mode sast-only       # Semgrep baseline
python benchmark/evaluate.py --mode llm-only        # LLM-only baseline (no SAST/RAG/tools)
python benchmark/evaluate.py --mode lgtm-no-sast    # ablation: LGTM minus Semgrep
python benchmark/evaluate.py --mode lgtm --rescore  # re-score a saved run, no LLM calls
python benchmark/evaluate.py --split dev            # development set only
python benchmark/evaluate.py --split eval           # held-out evaluation set
python benchmark/evaluate.py --cases sqli_01_vulnerable authz_02_safe  # subset
```

Use `--gpu-cluster` to connect through the existing tunnel at
`http://127.0.0.1:11435` with `qwen2.5:7b`. Server and tunnel startup stay
separate; see [`model/README.md`](../model/README.md). Explicit `--model`
and `--ollama-url` options override the cluster defaults.

**Dev/eval protocol:** pairs alternate between splits in blocks of three
(pairs 1–3 and 7–9 → dev; pairs 4–6 and 10–12 → eval), so each split holds
9 vulnerable + 9 safe cases. Tune prompts, rules, and config against
`--split dev` only; quote final numbers from `--split eval`. To scale
further, extract more cases from public corpora (more OWASP Benchmark
patterns, CVE-derived PRs) while keeping the positive/negative balance.

For each case the harness:

1. copies `app/` + the policy docs into a temp git repo and commits it as
   the base branch;
2. applies the case's patch on a `pr` branch and commits;
3. runs `lgtm index` + the review pipeline;
4. scores the predicted verdict against `labels.json`.

Results (per-case JSON + a metrics summary) are written to
`benchmark/results/<mode>/` (git-ignored scratch space). Runs we report on
are copied into `benchmark/runs/` and committed; see `benchmark/runs/README.md`
and `docs/evaluation-log.md`.

## Metrics reported

- Precision / recall / F1 — overall, per category (sqli, authz), and per
  dev/eval split.
- "Grounded" variants of the above: a detection only counts if the evidence
  validator accepted its citations.
- Off-category alarm rate: cases where an agent flags the category the case
  does *not* test (e.g. an ownership warning on a SQLi case).
- False-positive rate on the safe controls.
- Evidence grounding rate (findings whose citations all check out).
- `insufficient_evidence` rate and `possible` rate.
- Median latency per case and estimated tokens per PR.

## Regenerating cases

```bash
python benchmark/tools/generate_cases.py
```

Edit the case definitions in that script, re-run it, and commit the
refreshed patches + `labels.json`.
