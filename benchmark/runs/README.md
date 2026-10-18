# Benchmark runs (committed evidence)

Each directory is one evaluation round. Each mode subdirectory holds:

- one JSON file per case, with every finding, verdict, evidence item,
  validation result and latency;
- a `summary.json` with all metrics, the list of case outcomes, and the run
  metadata.

`benchmark/results/` is the scratch output directory and is git-ignored;
runs worth keeping are copied here. The narrative for each round (what
failed, why, what changed) is in
[`docs/evaluation-log.md`](../../docs/evaluation-log.md).

| Directory | Date | Code state | Modes | Notes |
|---|---|---|---|---|
| `run1-original/` | 2026-10-10 | commit `3071740` | sast-only, lgtm, lgtm-no-sast | The first full run. `lgtm-no-sast` was called `llm-only` at the time. `summary.original.json` holds the numbers as first reported; `summary.json` re-scores the same findings with the fixed scorer (the evidence verdicts are the original validator's) |
| `run2-llm-only-baseline/` | 2026-10-13 | round-1 code + new `plain_reviewer.py` | llm-only | The first *correct* Baseline B: no SAST, no RAG, no tools |
| `run3-bugfixes/` | 2026-10-13 | round-3 bug fixes (tool-call parsing, validator, Semgrep rule) | all four | Flags off; the main comparison |
| `run4-dev-experiments/` | 2026-10-13 | + `analysis/facts.py`, experiment flags, path-free rule IDs | lgtm (dev split): `control`, `facts`, `tools` | Tuning experiments, dev split only |
| `run5-dev-role-guidance/` | 2026-10-13 | + facts v2, `authz_role_guidance` | lgtm (dev split) | Rejected on dev (authz recall 3/3 → 0/3) |
| `run6-final/` | 2026-10-13 | shipped config (all flags off) | lgtm | The clean final numbers quoted in the README |
| `real_world/` | 2026-10-15 | `683e2a2` → `fef5a75`; summaries rebuilt at `0f8f527` | sast-only, llm-only, lgtm, lgtm-no-sast on 12 real-world CVE cases; `*-policy` = the two lgtm modes on the 6 authz cases with a project policy | `qwen2.5-coder:7b`, local Ollama endpoint, `0f8f527`. Held-out: no tuning. Per-case JSON also holds diff size, detected endpoints, index time and `index_skipped`. Which commit produced which case is in [`docs/real-world-eval.md`](../../docs/real-world-eval.md). `git_commit` is a real SHA here (frozen git worktree) |
| `gpu-qwen3.8-27b/` | 2026-10-18 | commit `a9b380b` | lgtm, lgtm-no-sast, llm-only on 36 Shoply and 12 real-world cases; `*-policy` = the two lgtm modes on the 6 authz cases with a project policy | `qwen3.8:27b` (Q4_K_M) on one RTX 3090 via Ollama 0.34.2. Subdirectories `shoply/` and `real_world/`. Setup and results in [`docs/gpu-model-eval.md`](../../docs/gpu-model-eval.md) |
| `gpu-shared/` | 2026-10-18 | commit `a9b380b` | sast-only on Shoply and real-world | Semgrep only, no model. Shared by the `gpu-*` runs |

Re-score any run with the current scoring rules (no model calls):

```bash
python benchmark/evaluate.py --mode lgtm --rescore --output benchmark/runs/run3-bugfixes/lgtm
```

Runs were produced from a frozen copy of the working tree, so
`git_commit` in the summaries reads `unknown` for rounds 2–6. Local absolute paths that Semgrep had embedded in rule IDs before the fix were stripped from all committed files. The code
state is the one described in the evaluation log for that round.
