# Component benchmark results, 2026-11-05

Each pipeline component scored on its own over the 12 real-world cases, against draft labels written by Claude Opus 5.5. No label has been reviewed yet; every figure below is provisional. Benchmark design and label formats: [`component-bench.md`](component-bench.md).

Models: reviewer `qwen3.8:27b` (Ollama), judge Kev-4B, both on the Origami cluster.

| Run | Commit | Components | Directory |
| --- | --- | --- | --- |
| Full run | `4815d3a` | all six | `benchmark/runs/component-bench-2026-11-05/` |
| Kev rerun 1 | `0fccd5c` | kev-judge | `benchmark/runs/component-bench-kev-2026-11-05/` |
| Kev rerun 2 | `eeb6a82` | kev-judge | `benchmark/runs/component-bench-kev-2026-11-05-r2/` |

## Summary

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

- Rerun the investigator on the 10 errored cases (`--resume`).
- Review the draft labels.
- The worked examples added in rerun 2 resemble benchmark cases (a lookup by id with no ownership check, SQL built from a sort field).
