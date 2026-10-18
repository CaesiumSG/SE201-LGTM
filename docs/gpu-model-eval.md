# qwen3.8:27b evaluation

The same pipeline and both benchmark suites, run with `qwen3.8:27b` on one
GPU. Comparisons with the committed `qwen2.5-coder:7b` runs are in section D.

## Summary

- **Shoply (36 cases):** lgtm and lgtm-no-sast classified all 36 cases
  correctly (F1 1.000). llm-only scored F1 0.944. sast-only scored F1 0.615.
- **Real-world (12 cases):** lgtm and lgtm-no-sast scored F1 0.667 (recall
  0.500). llm-only scored F1 1.000. sast-only scored F1 0.444.
- **Real-world misses in the LGTM modes:** `aegra_authz_vulnerable`,
  `alerta_sqli_vulnerable` and `litellm_authz_vulnerable`. The aegra case was
  skipped before any agent ran.
- **Errors:** 0 in every mode. Every case that hit the iteration cap was
  scored.
- **Latency (qwen3.8:27b only):** lgtm mean latency was 44.91 s per Shoply
  case, and 16.82 s per real-world case.

## A. Setup

Source: `benchmark/runs/gpu-qwen3.8-27b/deployment.json`, unless noted.

| | |
|---|---|
| Model | `qwen3.8:27b`, Q4_K_M, digest `aaee06c3…9097813` |
| Runtime | Ollama 0.34.2 |
| GPU | one NVIDIA RTX 3090, 24 GB |
| Placement | fully on GPU (size = size_vram = 17399734598 bytes) |
| Context | 32768 tokens |
| Flash attention | off |
| KV cache | f16 |
| Reasoning (thinking) | off |
| Load time | 12.0 s |
| Decode speed | 28.47 tok/s on a short probe |
| Code state | `a9b380b` |
| Selection | `--gpu-model qwen3.8-27b` |
| GPU time held | 5063 s (1.41 h) for all LLM runs |

Suites:

- **Shoply:** 36 cases (18 dev, 18 eval; 18 vulnerable, 18 safe).
- **Real-world:** 12 cases (6 SQLi, 6 authz), plus the authz policy variant
  (6 cases).

Modes: lgtm, lgtm-no-sast and llm-only. sast-only does not call the model.
Its results are in `benchmark/runs/gpu-shared/`.

Agent limits (`src/lgtm/config.py`): `max_agent_iterations` 8, and
`max_tool_calls` 5 for each agent invocation. There is one invocation for
each finding.

## B. Shoply results

Source: `benchmark/runs/gpu-qwen3.8-27b/shoply/<mode>/summary.json`.
sast-only: `benchmark/runs/gpu-shared/shoply/sast-only/summary.json`.

| Mode | TP/FP/FN/TN | Precision | Recall | F1 | FPR on safe | Scored | Errors |
|---|---|---|---|---|---|---|---|
| lgtm | 18/0/0/18 | 1.000 | 1.000 | 1.000 | 0.000 | 36 | 0 |
| lgtm-no-sast | 18/0/0/18 | 1.000 | 1.000 | 1.000 | 0.000 | 36 | 0 |
| llm-only | 17/1/1/17 | 0.944 | 0.944 | 0.944 | 0.056 | 36 | 0 |
| sast-only | 12/9/6/9 | 0.571 | 0.667 | 0.615 | 0.500 | 36 | 0 |

F1 by category and split:

| Mode | Authz | SQLi | Dev | Eval |
|---|---|---|---|---|
| lgtm | 1.000 | 1.000 | 1.000 | 1.000 |
| lgtm-no-sast | 1.000 | 1.000 | 1.000 | 1.000 |
| llm-only | 0.833 | 1.000 | 1.000 | 0.889 |
| sast-only | 0.000 | 0.727 | 0.600 | 0.632 |

llm-only misses: `authz_06_safe` (FP) and `authz_06_vulnerable` (FN).

Errors are counted apart from verdicts. All modes had 0 errors.

## C. Real-world results

Source: `benchmark/runs/gpu-qwen3.8-27b/real_world/<mode>/summary.json`.
sast-only: `benchmark/runs/gpu-shared/real_world/sast-only/summary.json`.
All summaries are complete.

| Mode | TP/FP/FN/TN | Precision | Recall | F1 | FPR on safe | Scored | Errors |
|---|---|---|---|---|---|---|---|
| lgtm | 3/0/3/6 | 1.000 | 0.500 | 0.667 | 0.000 | 12 | 0 |
| lgtm-no-sast | 3/0/3/6 | 1.000 | 0.500 | 0.667 | 0.000 | 12 | 0 |
| llm-only | 6/0/0/6 | 1.000 | 1.000 | 1.000 | 0.000 | 12 | 0 |
| lgtm-policy (6 authz) | 1/0/2/3 | 1.000 | 0.333 | 0.500 | 0.000 | 6 | 0 |
| lgtm-no-sast-policy (6 authz) | 1/0/2/3 | 1.000 | 0.333 | 0.500 | 0.000 | 6 | 0 |
| sast-only | 2/1/4/5 | 0.667 | 0.333 | 0.444 | 0.167 | 12 | 0 |

F1 by category (12-case modes): lgtm authz 0.500, SQLi 0.800;
lgtm-no-sast the same. llm-only authz 1.000, SQLi 1.000.

Misses:

- lgtm and lgtm-no-sast miss `aegra_authz_vulnerable`,
  `alerta_sqli_vulnerable` and `litellm_authz_vulnerable`.
- The policy modes miss `aegra_authz_vulnerable` and
  `litellm_authz_vulnerable`.
- `aegra_authz_vulnerable` is skipped before any agent runs: 0 endpoints
  detected and 0 Semgrep findings in the diff. No model sees this case in the
  LGTM modes.

## D. Comparison with qwen2.5-coder:7b

The qwen2.5-coder:7b baselines ran on older code. The Shoply baselines record
git_commit `unknown`. The real-world baselines record `0f8f527`. Since then the
code gained UTF-8 diff decoding (`4bf1cb6`), error accounting (`886305d`), and
LLM retries, tool-input validation and re-asks of non-JSON answers
(`efe14ca`). The agent text sent to the model is unchanged. Model and code
changes are therefore not separated in this comparison.

Quality only. Latency is not compared here (see section E).

| Comparison | Baseline source | TP/FP/FN/TN (baseline → qwen3.8:27b) | F1 (baseline → qwen3.8:27b) | Other | Changed cases |
|---|---|---|---|---|---|
| Shoply lgtm | `benchmark/runs/run6-final/lgtm` | 17/1/1/17 → 18/0/0/18 | 0.944 → 1.000 | FPR 0.056 → 0.000; grounding 0.925 → 0.97 | `authz_06_safe` FP → TN; `sqli_04_vulnerable` FN → TP |
| Shoply lgtm-no-sast | `benchmark/runs/run3-bugfixes/lgtm-no-sast` | 17/2/1/16 → 18/0/0/18 | 0.919 → 1.000 | FPR 0.111 → 0.000 | `authz_06_safe` FP → TN; `sqli_03_safe` FP → TN; `sqli_04_vulnerable` FN → TP |
| Shoply llm-only | `benchmark/runs/run3-bugfixes/llm-only` | 12/2/6/16 → 17/1/1/17 | 0.750 → 0.944 | Authz F1 0.000 → 0.833 | `authz_01` to `authz_05_vulnerable` FN → TP; `sqli_03_safe` and `sqli_06_safe` FP → TN; `authz_06_safe` TN → FP |
| Real-world lgtm and lgtm-no-sast | `benchmark/runs/real_world/lgtm`, `benchmark/runs/real_world/lgtm-no-sast` | 2/1/4/5 → 3/0/3/6 | 0.444 → 0.667 | Grounding lgtm 0.833 → 0.5; lgtm-no-sast 0.75 → 0.667 | `langflow_authz_safe` FP → TN; `langflow_authz_vulnerable` FN → TP |
| Real-world policy modes | `benchmark/runs/real_world/lgtm-policy`, `benchmark/runs/real_world/lgtm-no-sast-policy` | 1/1/2/2 → 1/0/2/3 | 0.400 → 0.500 | n/a | `langflow_authz_safe` FP → TN |
| Real-world llm-only | `benchmark/runs/real_world/llm-only` | 4/0/2/6 → 6/0/0/6 | 0.800 → 1.000 | n/a | `alerta_sqli_vulnerable` and `litellm_authz_vulnerable` FN → TP |
| sast-only | `benchmark/runs/gpu-shared/` | identical in both suites | identical in both suites | n/a | n/a |

## E. Time and tool use

Latency and wall time are reported for qwen3.8:27b only. The
qwen2.5-coder:7b baselines ran on different hardware, so they are not
compared with these figures.

Source: `benchmark/runs/gpu-qwen3.8-27b/run-stats.json`.

- **Wall time** is the whole run, including the temp-repo build and indexing.
- **Latency** is per case. Shoply latency includes the repo build and
  indexing. Real-world latency is the pipeline only; index time is reported
  separately.
- **Tool calls** for a case are the sum of `tool_calls_used` over its
  findings. The sum includes calls refused after the 5-call budget.

Shoply:

| Mode | Wall (s) | Latency mean / median / p90 / max (s) | Tool calls total / mean / median / max, by case | Findings | Tool calls / finding |
|---|---|---|---|---|---|
| lgtm | 1618 | 44.91 / 41.88 / 72.83 / 86.56 | 441 / 12.25 / 11.5 / 27 | 67 | 6.58 |
| lgtm-no-sast | 1388 | 38.53 / 39.95 / 57.2 / 59.96 | 399 / 11.08 / 11.0 / 18 | 60 | 6.65 |
| llm-only | 325 | 8.97 / 8.71 / 10.59 / 13.72 | n/a (no tools) | n/a | n/a |
| sast-only | 37 | n/a | n/a | n/a | n/a |

Estimated tokens, median by case: lgtm 1132.5.

Real-world: all LLM modes together took 1552 s of wall time (48 units).
sast-only took 30 s.

| Mode | Latency mean / median / p90 (s) | Agent ran / skipped | Tool calls total / mean by case | Tool calls / finding | Index time, sum (s) |
|---|---|---|---|---|---|
| lgtm | 16.82 / 2.54 / 44.6 | 5 / 7 | 52 / 4.33 | 8.67 | 303.59 |
| lgtm-no-sast | 21.96 / 21.48 / 50.87 | 7 / 5 | 81 / 6.75 | 6.75 | 332.28 |
| lgtm-policy | 11.92 / 2.6 / 30.96 | 2 / 4 | 15 / 2.5 | 7.5 | 359.57 |
| lgtm-no-sast-policy | 21.57 / 8.97 / 55.7 | 3 / 3 | 33 / 5.5 | 5.5 | 382.99 |
| llm-only | 9.95 / 9.93 / 12.09 | no agent | n/a (no tools) | n/a | n/a |

Skipped units take about 2.5 s, which lowers the medians.

The field has been recorded since commit `72103be`. The committed
qwen2.5-coder:7b runs record 0 tool calls on every finding.

## F. Agent limits and resilience counters

Source: the run logs. These counters are not in `summary.json`.

| Mode | Iteration-cap forced finals | Cases that hit the cap | Tool-budget refusals |
|---|---|---|---|
| Shoply lgtm | 34 | 25 | 151 |
| Shoply lgtm-no-sast | 32 | 26 | 139 |
| Shoply llm-only | 0 | 0 | n/a |
| Real-world lgtm | 5 | 4 | 22 |
| Real-world lgtm-no-sast | 4 | 4 | 24 |
| Real-world lgtm-policy | 1 | 1 | 5 |
| Real-world lgtm-no-sast-policy | 1 | 1 | 6 |
| Real-world llm-only | 0 | 0 | n/a |

- Forced finals in Shoply: lgtm had 24 authz reviewer and 10 SAST triage
  finals. lgtm-no-sast had 25 authz and 7 triage finals.
- The iteration-cap case in each policy mode is `langflow_authz_safe`.
- A forced final is a tool-less LLM call that still yields a scored verdict.
- Every case that hit the cap was scored correctly.
- LLM retries, invalid tool inputs, invalid-input-cap finals and re-asks were
  0 in every log. The retry path was not exercised.
- A scan of all outputs found no thinking text.

## G. Known limitations

- A JSON final answer without a `verdict` field is scored
  `insufficient_evidence`. It is not re-asked and not counted as an error, so
  error counts can understate unusable answers.
- Each mode was run once. There are no repeat runs, so variance is not
  measured.
- Real-world n = 12 (6 per category). The policy variant n = 6.
- The baselines differ in code state and hardware (sections D and E).
