# Component benchmark results, 2026-11-05 and 2026-11-06

Each pipeline component scored on its own, against draft labels written by Claude Opus 5.5. No label has been reviewed yet; every figure below is provisional. Benchmark design and label formats: [`component-bench.md`](component-bench.md).

Models: reviewer `qwen3.8:27b` (Ollama), judge Kev-4B, both on the Origami cluster.

| Run | Commit | Components | Cases | Directory |
| --- | --- | --- | --- | --- |
| 2026-11-05 full run | `4815d3a` | all six | 12 real-world | `benchmark/runs/component-bench-2026-11-05/` |
| Kev rerun 1 | `0fccd5c` | kev-judge | 12 real-world | `benchmark/runs/component-bench-kev-2026-11-05/` |
| Kev rerun 2 | `eeb6a82` | kev-judge | 12 real-world | `benchmark/runs/component-bench-kev-2026-11-05-r2/` |
| 2026-11-06 full run | `521cb4b` | all seven | 12 real-world, 13 real-PR development | `benchmark/runs/component-bench-2026-11-06/` |
| 2026-11-06 tools run | `968e9990` | all seven | 12 real-world, 13 real-PR development | `benchmark/runs/component-bench-2026-11-06-tools/` |

## 2026-11-06 tools run

All seven components over 25 cases: the 12 real-world cases and the 13 real-PR development cases. Held-out cases are excluded. Single run; no repeats, so no variance is reported.

The first pass ran at `525a091f`. The `--resume` pass, which re-ran the errored units, ran at `968e9990`, the commit `summary.json` records (not dirty). The two commits differ only in test files; no production code differs.

What the run used:

- Production toolboxes for every model-backed component, with a live `GraphSession` per unit. Each unit records its `graph_state`.
- Two-stage SAST SQLi triage: a triage stage followed by a judge stage.
- Reviewer `qwen3.8:27b`, judge Kev-4B.

### Tool use

| Component | CodeGraph calls | `search_policy` calls | `read_file` | `grep_repo` |
| --- | --- | --- | --- | --- |
| Investigator | 48 | 8 | 276 | 94 |
| Authz reviewer | 14 | 12 | 36 | 23 |
| SAST SQLi triage | 0 | 8 | 54 | 42 |
| SQLi reviewer | 2 | 0 | 22 | 21 |

SAST SQLi triage is not offered the graph tools. The SQLi reviewer never called `search_policy`.

### Side by side

Scored / not scored / errored units, with headline scores. Scores are means over scored units.

| Component | Units | Headline |
| --- | --- | --- |
| Policy retrieval | 0 / 25 / 0 | not scored |
| Investigator | 24 / 0 / 1 | no scalar scores; none rated |
| Authz reviewer | 13 / 0 / 2 | TP 0.62, FN 0.15, FP 0.08, TN 0.23, verdict correct 0.85 |
| SAST SQLi triage | 20 / 0 / 0 | triage correct 0.40, judge correct 0.70 |
| Evidence validator | 50 / 0 / 0 | TP 0.50, FN 0, FP 0.04, TN 0.46 |
| Kev judge | 28 / 1 / 0 | verdict 0.89, real 0.91, not-real 0.80, severity 0.55 |
| SQLi reviewer | 9 / 1 / 0 | TP 0.67, FN 0, FP 0, TN 0.33, SAST also 0.44, reviewer only 0.22 |

### Aggregate counts

| Component | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Authz reviewer | 8 | 1 | 2 | 3 | 0.89 | 0.80 | 0.84 |
| Evidence validator | 25 | 2 | 0 | 23 | 0.93 | 1.00 | 0.96 |

| SAST SQLi stage | Precision | Recall | F1 |
| --- | --- | --- | --- |
| Triage | 0.40 | 1.00 | 0.57 |
| Judge | 0.58 | 0.88 | 0.70 |

SQLi reviewer: runs on the gold section of each of the 10 sqli cases; 9 are scored. Hits 6, false positives 0, precision 1.00, recall 1.00, F1 1.00. SAST triage also found 4 of the 6 hits; the reviewer alone found 2.

### Errored units

Three units errored with a degraded `graph_state`, the CodeGraph index timing out. The guard stays a failure.

- **Investigator, 1** (`airflow-partitioned-dagruns-authz`): `degraded:base:timeout`.
- **Authz reviewer, 2** (`airflow-partitioned-dagruns-authz`, `airflow-hitl-execution-api-authz`): `degraded:pr:timeout`.

### Not scored

- **Policy retrieval, 25**: no real-index gold labels exist yet.
- **Kev judge, 1**: `kj-litellm-authz-safe-1`, gold `undetermined`.
- **SQLi reviewer, 1** (`alerta_sqli_vulnerable`): the gold section has no SQL signal, so the pipeline would not route it to the SQLi reviewer.

Kev judge units carry a `verdict` and the Kev output under `detail.kev`, but no `explanation` field.

## 2026-11-06 run without tools

All seven components over 25 cases: the 12 real-world cases and the 13 real-PR development cases. Held-out cases are excluded. Every model-backed result file carries the setting `qwen3.8:27b@http://127.0.0.1:11435+jaredpalmer/kev-4b@http://127.0.0.1:8008`. No unit errored. Single run; no repeats, so no variance is reported.

### Side by side

Scored / not scored / errored units, with headline scores. The 2026-11-05 column is the full run; for kev-judge it is the full run, not the reruns. Scores are means over scored units. The two columns cover different case sets, so the figures are not like-for-like.

| Component | 2026-11-05 units | 2026-11-06 units | 2026-11-05 headline | 2026-11-06 headline |
| --- | --- | --- | --- | --- |
| Policy retrieval | 6 / 6 / 0 | 6 / 19 / 0 | hit 1.00, recall 1.00, MRR 0.83 | hit 1.00, recall 1.00, MRR 0.83 |
| Investigator | 2 / 0 / 10 | 24 / 1 / 0 | rated 2 of 12 | no scalar scores; none rated |
| Authz reviewer | 6 / 0 / 0 | 15 / 0 / 0 | TP 0.50, FN 0, FP 0.33, TN 0.17, verdict correct 0.67 | TP 0.73, FN 0.07, FP 0.20, TN 0.07, verdict correct 0.80 |
| SAST SQLi triage | 12 / 0 / 0 | 20 / 0 / 0 | TP 0.25, FP 0, FN 0.08, TN 0.67, correct 0.92 | TP 0.20, FP 0.05, FN 0.20, TN 0.55, correct 0.75 |
| Evidence validator | 24 / 0 / 0 | 50 / 0 / 0 | TP 0.50, FN 0, FP 0, TN 0.50 | TP 0.50, FN 0, FP 0.04, TN 0.46 |
| Kev judge | 16 / 1 / 0 | 28 / 1 / 0 | verdict 0.50, real 0.45, not-real 0.60, severity 0.36 | verdict 0.89, real 0.91, not-real 0.80, severity 0.55 |
| SQLi reviewer | not run | 9 / 1 / 0 | | TP 0.67, FN 0, FP 0, TN 0.33, SAST also 0.67, reviewer only 0 |

### Scoring rules since 2026-11-05

| Component | Status |
| --- | --- |
| Policy retrieval | Unchanged |
| Investigator | Unchanged |
| Evidence validator | Unchanged |
| Authz reviewer | Same-function hit rule, described in [`component-bench.md`](component-bench.md) |
| SQLi reviewer | Same-function hit rule, described in [`component-bench.md`](component-bench.md) |
| SAST SQLi triage | Unchanged; unparsable answers are read from the agent error kind |
| Kev judge | Changed by earlier commits: labels accept defensible verdicts and severities; severity wording is reach-based; each cited item is sent with its enclosing function. Scores are not directly comparable with 2026-11-05. The case count also grew |

### Fixes in the harness

- Authz and SAST SQLi triage decide `not_scored` from the `kind` of the agent's error record (`unparsable` or `failed`) instead of matching the explanation text.
- Each real-PR development case is checked for its local clone and ref before it runs; a missing clone is recorded as `error` with the fetch command.

### Aggregate counts

| Component | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Authz reviewer | 11 | 3 | 1 | 1 | 0.79 | 0.92 | 0.85 |
| SAST SQLi triage | 4 | 1 | 4 | 11 | 0.80 | 0.50 | 0.62 |
| Evidence validator | 25 | 2 | 0 | 23 | 0.93 | 1.00 | 0.96 |

### SQLi reviewer

Runs on the gold section of each of the 10 sqli cases; 9 are scored. Hits 6, false positives 0, precision 1.00, recall 1.00, F1 1.00. All 6 hits were also found by SAST triage; the reviewer found none that SAST missed.

### Not scored

- **Policy retrieval, 19**: policy retrieval does not apply to the non-policy cases.
- **Investigator, 1** (`weblate-memory-api-authz`): the final answer was not a JSON object with a `sections` list.
- **Kev judge, 1**: `kj-litellm-authz-safe-1`, gold `undetermined`.
- **SQLi reviewer, 1** (`alerta_sqli_vulnerable`): the gold section has no SQL signal, so the pipeline would not route it to the SQLi reviewer.

## 2026-11-05 summary

Over the 12 real-world cases.

| Component | Units scored | Headline | Reading |
| --- | --- | --- | --- |
| Policy retrieval | 6 | hit@k 1.00, recall@k 1.00, MRR 0.83 | Every gold passage retrieved at the default `rag_top_k` |
| Investigator | 2 of 12 | mean rating 0.90 | 10 units lost to a tunnel outage |
| Authz reviewer | 6 | precision 0.60, recall 1.00, F1 0.75 | Finds every vulnerability; flags 2 of 3 fixed versions |
| SAST SQLi triage | 12 | precision 1.00, recall 0.75, F1 0.86 | Drops one true alerta hit |
| Evidence validator | 24 | precision 1.00, recall 1.00, F1 1.00 | Every citation and distractor classified correctly |
| Kev judge (rerun 2) | 15 | verdict 0.87, severity 0.86 | See below |

## Policy retrieval

| hit@k | recall@k | MRR |
| --- | --- | --- |
| 1.00 | 1.00 | 0.83 |

All 6 authz cases retrieve a gold passage in the top k; in one third of them the first gold passage is not ranked first. The 6 sqli cases are not applicable.

## Investigator

| Case | Rating |
| --- | --- |
| `pyload_sqli_vulnerable` | 0.95 |
| `litellm_authz_safe` | 0.85 |

The other 10 cases errored with `connection refused` when both SSH tunnels to the cluster were reset by the remote side for about two minutes. They have no result and are not rated. Ratings and reasons are in `investigator/ratings/`; the rubric is `investigator/investigator_rubric.md`.

## Authz reviewer

| | Gold vulnerable | Gold safe |
| --- | --- | --- |
| Flagged | 3 (TP) | 2 (FP) |
| Not flagged | 0 (FN) | 1 (TN) |

False positives: `aegra_authz_safe` and `litellm_authz_safe`, both on the fixed code.

## SAST SQLi triage

| TP | FP | FN | TN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| 3 | 0 | 1 | 8 | 1.00 | 0.75 | 0.86 |

False negative: `alerta_sqli_vulnerable-gold-1`.

## Evidence validator

| TP | FP | FN | TN |
| --- | --- | --- | --- |
| 12 | 0 | 0 | 12 |

## Kev judge

| Metric | Full run | Rerun 1 | Rerun 2 |
| --- | --- | --- | --- |
| Verdict correct | 0.50 | 0.87 | **0.87** |
| Real verdict correct | 0.45 | 0.90 | **0.90** |
| Not-real verdict correct | 0.60 | 0.80 | **0.80** |
| Severity correct | 0.36 | 0.57 | **0.86** |
| Units scored / not scored | 16 / 1 | 15 / 1 | 15 / 1 |

Changes between runs:

- **Rerun 1** (labels): labels accept every defensible verdict and severity (`gold.acceptable`); `kj-alerta-sqli-vuln-1` cites the pre-fix `SearchTerm.__repr__` f-string; `kj-alerta-sqli-safe-2` accepts `not_real`; the duplicate `kj-alerta-sqli-safe-3` is removed. Rescoring the full run's verdicts under these labels gives 0.69.
- **Rerun 2** (judge input): severity levels are graded on who can reach the flaw, with medium and high worked examples; each cited item is sent with its enclosing function and decorators instead of the quoted lines alone; Kev's raw answers are recorded per unit. Both changes landed together, so their separate effects are not measured.

Kev's answers in rerun 2:

| Label | Gold | Accepted | Kev verdict | Kev severity | Kev supported | Result |
| --- | --- | --- | --- | --- | --- | --- |
| `kj-pyload-sqli-vuln-1` | real / high | high, critical | real | critical | yes | ✓ |
| `kj-pyload-sqli-safe-1` | not_real | | not_real | | no | ✓ |
| `kj-postgraas-sqli-vuln-1` | real / high | high, critical | real | high | yes | ✓ |
| `kj-postgraas-sqli-safe-1` | not_real | | not_real | | no | ✓ |
| `kj-alerta-sqli-vuln-1` | real / high | high, critical | real | high | yes | ✓ |
| `kj-alerta-sqli-vuln-2` | real / high | medium, high | not_real | | no | ✗ verdict |
| `kj-alerta-sqli-safe-1` | not_real | not_real, real | real | critical | no | ✓ |
| `kj-alerta-sqli-safe-2` | real / high | real, not_real | not_real | | yes | ✓ |
| `kj-aegra-authz-vuln-1` | real / high | medium, high | real | high | yes | ✓ |
| `kj-aegra-authz-safe-1` | not_real | | not_real | | yes | ✓ |
| `kj-aegra-authz-safe-2` | real / medium | real, not_real | not_real | | no | ✓ |
| `kj-aegra-authz-safe-3` | real / medium | real, not_real | not_real | | no | ✓ |
| `kj-langflow-authz-vuln-1` | real / high | medium, high | real | high | yes | ✓ |
| `kj-langflow-authz-safe-1` | not_real | | real | high | no | ✗ verdict |
| `kj-litellm-authz-vuln-1` | real / high | high, critical | real | high | yes | ✓ |
| `kj-litellm-authz-safe-1` | undetermined | | | | | not scored |

Kev severity is shown only where Kev answered `real`; Kev also returns a severity with `not_real`.

### Remaining misses

- **`kj-alerta-sqli-vuln-2`**: Kev received the whole `sort_by_columns` function. The allowlist check runs on `sort_by` after it is rewritten to `'attributes'`; the `attribute` value split from the request parameter is never checked and reaches `f"attributes->'{attribute}'"`. Kev answered `not_real`.
- **`kj-langflow-authz-safe-1`**: Kev answered `supported: no` and `verdict: real` for the fixed delete-API-key route. The same contradiction appears on `kj-alerta-sqli-safe-1`, where `real` is accepted.

## Open items

- Rerun the 3 units of the 2026-11-06 tools run that errored on airflow cases with a degraded `graph_state` (investigator 1, authz reviewer 2; CodeGraph index timeouts).
- Policy retrieval stays not scored until gold labels exist for the real index.
- Review the draft labels (human reviewer).
- The worked examples added in rerun 2 resemble benchmark cases (a lookup by id with no ownership check, SQL built from a sort field); human review.
