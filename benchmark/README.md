# LGTM Benchmark — Shoply

A deliberately reviewable Flask e-commerce API plus **12 matched PR pairs**
(24 cases) used to evaluate the LGTM PR security agent.

## Layout

- `app/` — the Shoply application (Flask + SQLAlchemy, token auth, RBAC).
- `security-policy.md`, `api-spec.md` — project documents indexed by LGTM's
  RAG system; the authorization agent judges PRs against these.
- `cases/sqli/` — 6 SQL-injection pairs (CWE-89). Each `*_vulnerable.patch`
  interpolates request data into SQL; the matching `*_safe.patch` implements
  the same feature with bound parameters or an allowlist. The safe versions
  still look SQL-ish enough to trigger SAST, which is the false-positive
  test.
- `cases/authz/` — 6 authorization pairs (CWE-639 / CWE-862 / CWE-863).
  These are invisible to SAST by design; only policy-aware review can catch
  them.
- `labels.json` — ground truth for all 24 cases.
- `evaluate.py` — runs LGTM on every case and reports metrics.
- `tools/generate_cases.py` — regenerates all patches and `labels.json`
  from the case definitions (patches are produced by real `git diff`, so
  they always apply cleanly).

## Running the evaluation

```bash
# From the repository root (install LGTM first: pip install -e .)
python benchmark/evaluate.py --mode lgtm            # full pipeline
python benchmark/evaluate.py --mode sast-only       # Semgrep baseline
python benchmark/evaluate.py --mode llm-only        # LLM-only baseline
python benchmark/evaluate.py --split dev            # development set only
python benchmark/evaluate.py --split eval           # held-out evaluation set
python benchmark/evaluate.py --cases sqli_01_vulnerable authz_02_safe  # subset
```

**Dev/eval protocol:** pairs 1–3 of each category are the development set,
pairs 4–6 the held-out evaluation set (each split: 6 vulnerable + 6 safe).
Tune prompts, rules, and config against `--split dev` only; quote final
numbers from `--split eval`. To scale the dataset, extract additional
SQL-injection cases from public corpora such as the OWASP Benchmark
(Java — translate to Python/Flask idioms) while keeping the
positive/negative balance.

For each case the harness:

1. copies `app/` + the policy docs into a temp git repo and commits it as
   the base branch;
2. applies the case's patch on a `pr` branch and commits;
3. runs `lgtm index` + the review pipeline;
4. scores the predicted verdict against `labels.json`.

Results (per-case JSON + a metrics summary) are written to
`benchmark/results/<mode>/`.

## Metrics reported

- Precision / recall / F1 — overall and per category (sqli, authz).
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
