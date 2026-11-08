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

Current runs use the reviewer `qwen3.8:27b` (served on the SCIS GPU cluster)
and the judge Kev (Kev-4B), in two conditions: lgtm (the full pipeline,
including Semgrep) and llm-only.

| Directory | Modes | Notes |
|---|---|---|
| Shoply run folder | lgtm, llm-only on the 36 committed Shoply cases | Written by `benchmark/evaluate.py --gpu-cluster` |
| `archive/real_world/` | lgtm, llm-only on 12 real-world CVE cases | Held-out: no tuning. Per-case JSON also holds diff size, detected endpoints, index time and `index_skipped`. Which commit produced which case is in [`docs/real-world-eval.md`](../../docs/real-world-eval.md) |
| `archive/field_trial/` | lgtm, llm-only on 12 ordinary merged PRs (mealie, alerta, redash) | Crash / latency / false-alarm trial; nothing tuned. Write-up in [`docs/field-trial.md`](../../docs/field-trial.md) |

Prompt-injection results are in `benchmark/runs/archive/injection-results/`. The findings
of the `shoply-20261029/lgtm` run are labelled by Claude Opus 5.5 in
`benchmark/kev_model_labels.json`.

Earlier runs are in `benchmark/runs/archive/`. They use earlier models and
conditions (sast-only, lgtm-no-sast, policy variants, lgtm-mitigated) and are
archived history, not current results:

| Directory | Date | Code state | Modes | Notes |
|---|---|---|---|---|
| `archive/run1-original/` | 2026-10-10 | commit `3071740` | sast-only, lgtm, lgtm-no-sast | The first full run. `summary.original.json` and `summary.json` hold two scorings of the same findings |
| `archive/run2-llm-only-baseline/` | 2026-10-13 | round-1 code + new `plain_reviewer.py` | llm-only | Baseline B: no SAST, no RAG, no tools |
| `archive/run3-bugfixes/` | 2026-10-13 | round-3 bug fixes (tool-call parsing, validator, Semgrep rule) | all four | Flags off |
| `archive/run4-dev-experiments/` | 2026-10-13 | + `analysis/facts.py`, experiment flags, path-free rule IDs | lgtm (dev split): `control`, `facts`, `tools` | Tuning experiments, dev split only |
| `archive/run5-dev-role-guidance/` | 2026-10-13 | + facts v2, `authz_role_guidance` | lgtm (dev split) | Dev split only |
| `archive/run6-final/` | 2026-10-13 | shipped config (all flags off) | lgtm | Checkpoint pipeline |
| `archive/run7-mitigation-defaults/` | 2026-10-23 | `4fc0999` (mitigations on by default) | lgtm (dev split): `control` (off), `mitigated` (on) | Dev split only |
| `archive/injection-results/` | 2026-10-17 to 2026-10-23 | | sast-only, llm-only, lgtm, lgtm-mitigated on 6 injection cases | Prompt-injection run |
| `archive/field_trial/` | 2026-10-23 | `ff110c3` + the field-trial harness | sast-only, llm-only, lgtm on 12 ordinary merged PRs | Field trial |
| `archive/real_world/` | 2026-10-15 | `683e2a2` → `fef5a75`; summaries rebuilt at `0f8f527` | sast-only, llm-only, lgtm, lgtm-no-sast on 12 real-world CVE cases; `*-policy` = the two lgtm modes on the 6 authz cases with a project policy | Real-world run. `git_commit` is a real SHA here (frozen git worktree) |
| `archive/gpu-qwen3.8-27b/`  | 2026-10-18 | commit `a9b380b` | lgtm, lgtm-no-sast, llm-only on 36 Shoply and 12 real-world cases; `*-policy` = the two lgtm modes on the 6 authz cases with a project policy | `qwen3.8:27b` (Q4_K_M) on one RTX 3090 via Ollama 0.34.2. Subdirectories `shoply/` and `real_world/`. Setup and results in [`docs/gpu-model-eval.md`](../../docs/gpu-model-eval.md) |
| `archive/gpu-shared/` | 2026-10-18 | commit `a9b380b` | sast-only on Shoply and real-world | Semgrep only, no model. Shared by the `gpu-*` runs |

`archive/kev_model_labels.json` holds the earlier Kev labels.

Runs under `benchmark/runs/archive/` predate coverage recording and score
UNKNOWN if rescored; their committed summaries are the reported numbers.

Runs were produced from a frozen copy of the working tree, so
`git_commit` in the summaries reads `unknown` for rounds 2–6. Local absolute paths that Semgrep had embedded in rule IDs before the fix were stripped from all committed files. The code
state is the one described in the evaluation log for that round.
