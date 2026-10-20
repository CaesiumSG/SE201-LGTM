# LGTM Benchmark — Shoply

A deliberately reviewable Flask e-commerce API plus **26 matched PR pairs**
(52 cases) used to evaluate the LGTM PR security agent.

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
- `cases/authz/` — 14 authorization pairs (CWE-639 / CWE-862 / CWE-863).
  These are invisible to SAST by design; only policy-aware review can catch
  them.
- `labels.json` — ground truth for all 52 cases (with dev/eval split).
  Authz cases 07–14 also carry `diff_shape` (the patch shape, e.g.
  `deletion_only`, `cross_file_move`) and `vulnerable_locations`: a list of
  `{file, old_range, new_range}` entries with inclusive 1-based line ranges,
  `null` for a side the location does not have.
- `evaluate.py` — runs LGTM on every case and reports metrics.
- `tools/generate_cases.py` — regenerates all patches and `labels.json`
  from the case definitions (patches are produced by real `git diff`, so
  they always apply cleanly).

Authorization pairs 07–14 (vulnerable case; safe control):

- `authz_07` (CWE-639, dev, `deletion_only`): the profile update drops the
  ownership check; safe: the same update without the email branch, ownership
  check kept.
- `authz_08` (CWE-863, dev, `shared_helper`): `require_role` loses its rank
  comparison; safe: the comparison moves into `role_below` with identical
  semantics.
- `authz_09` (CWE-639, dev, `decorator_outside_hunk`): `my_orders` filters by
  status instead of owner; safe: the owner filter stays and a status filter is
  added.
- `authz_10` (CWE-862, eval, `deleted_file`): `app/auth.py` moves into
  `app/auth/__init__.py` with the API-key scope check removed; safe: the move
  is unchanged.
- `authz_11` (CWE-639, eval, `oversized_diff`): per-user export endpoint with
  no ownership check, appended after generated admin report routes; safe: the
  endpoint is guarded by `is_owner_or_admin`.
- `authz_12` (CWE-639, eval, `cross_file_move`): `is_owner_or_admin` moves to
  `app/ownership.py` and returns `True` for every authenticated user; safe: the
  move is unchanged.
- `authz_13` (CWE-863, dev, `renamed_route`): admin stats route renamed with
  `@require_role("admin")` swapped for `@require_auth`; safe: the route is
  renamed with the decorator kept.
- `authz_14` (CWE-862, eval, `removed_auth_decorator`): audit log route loses
  `@require_role("admin")`; safe: the audit log route is removed entirely.

## Running the evaluation

> Results measured at an earlier commit; not re-measured for the current code.

```bash
# From the repository root (install LGTM first: pip install -e .)
python benchmark/evaluate.py --mode lgtm            # full pipeline
python benchmark/evaluate.py --mode sast-only       # Semgrep baseline
python benchmark/evaluate.py --mode llm-only        # LLM-only baseline (no SAST/RAG/tools)
python benchmark/evaluate.py --mode lgtm-no-sast    # ablation: LGTM minus Semgrep
python benchmark/evaluate.py --mode lgtm --rescore  # re-score a saved run, no LLM calls
python benchmark/evaluate.py --mode lgtm --resume   # skip completed cases, re-run error results
python benchmark/evaluate.py --split dev            # development set only
python benchmark/evaluate.py --split eval           # held-out evaluation set
python benchmark/evaluate.py --cases sqli_01_vulnerable authz_02_safe  # subset
python benchmark/evaluate.py --gpu-model qwen3.8-27b
```

The `lgtm` and `lgtm-no-sast` modes use CodeGraph when the binary is found
([Configuration](../README.md#configuration)). `evaluate.py` has no
`--config-file` option, so graph settings use their defaults.

Use `--gpu-cluster` to connect through the existing tunnel at
`http://127.0.0.1:11435` with `qwen3.8:27b`. Server and tunnel startup stay
separate; see [`model/README.md`](../model/README.md). Explicit `--model`
and `--ollama-url` options override the cluster defaults.

`--gpu-model qwen3.8-27b` uses the same tunnel with `qwen3.8:27b` and
thinking disabled; it cannot be combined with `--gpu-cluster` or
`--model`, and `--ollama-url` overrides the URL. The summary records
`model` and `reasoning`.

`--resume` rebuilds `summary.json` from all case JSONs. Its refusal and skip
rules are listed in the Run manifest and `--resume` section.

**Dev/eval protocol:** pairs are split as follows (pairs 1–3, 7–9 and 13 → dev;
pairs 4–6, 10–12 and 14 → eval), so each split holds 13 vulnerable + 13 safe
cases. Tune prompts, rules, and config against
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
- "Grounded" variants of the above (`grounded_only`): a detection only counts
  if the evidence validator accepted its citations.
- `vulnerable_scored` / `safe_scored`: scored cases per expected label.
  `excluded_on_safe`: safe rows excluded from the safe-control rates.
- `abstentions` / `possible_on_safe`: rows labelled `insufficient_evidence` or
  `possible_vulnerability`, and safe rows labelled `possible_vulnerability`.
- `case_labels`: row count per case label. `legacy_rows`: rows without a run
  pin. `coverage`: review-coverage totals over rows with a coverage block.
- Off-category alarm rate: cases where an agent flags the category the case
  does *not* test (e.g. an ownership warning on a SQLi case).
- False-positive rate on the safe controls.
- Evidence grounding rate (findings whose citations all check out).
- `insufficient_evidence` rate and `possible` rate.
- Median latency per case and estimated tokens per PR.
- Errors — cases where the pipeline raised or an agent reported an
  execution or LLM failure — are counted separately (`errors`,
  `error_rate`, `error_cases`) and excluded from every other metric;
  `scored` is the number of cases the metrics cover. `--rescore` applies
  the same classification to saved results.
- Graph health per case JSON: `graph_state` (see
  [Configuration](../README.md#codegraph)), `graph_index_seconds`, `base_sha`,
  `pr_sha`.

## Regenerating cases

```bash
python benchmark/tools/generate_cases.py
```

Edit the case definitions in that script, re-run it, and commit the
refreshed patches + `labels.json`.

## Scoring

### Case labels

`lgtm` and `lgtm-no-sast` rows carry a `case_label` from the first matching
rule:

1. `scan_failure`: no coverage block, no section scheduled and the
   investigator reported an error, or scheduled sections and none completed.
2. `no_candidate`: no target section (see [Target sections](#target-sections)).
3. `detected_vulnerability`: a relevant finding has verdict `vulnerable`.
4. `missing_review`: a target section did not complete.
5. `possible_vulnerability`: a relevant finding has verdict `possible`.
6. `insufficient_evidence`: every relevant finding is `insufficient_evidence`.
7. `explicit_safe`: any other case.

A finding is relevant when its category is the case category or is empty,
`sast`, or missing.

`llm-only` and `sast-only` rows have no coverage block. Their label is
`no_candidate` when no finding is relevant; otherwise rules 3, 5, 6 and 7
apply in that order.

`case_label_grounded` applies the same rules after a `vulnerable` finding
whose evidence failed validation is treated as `possible`.

`coverage_gap` is `true` when `case_label` is `detected_vulnerability` and
the coverage is incomplete, has failed sections, or has leftover hunks.

### Target sections

`target_sections` lists the IDs of the sections the case is judged on.
Sections are selected by location overlap against every `vulnerable_locations`
entry. When none overlap, every section with a hunk in a target file is used.
Target files are the files named in `vulnerable_locations` plus the case
`file`. A case without `vulnerable_locations` uses its `file` with no line
ranges.

### Outcomes

| Expected | `case_label` | `outcome` |
| --- | --- | --- |
| `vulnerable` | `detected_vulnerability` | TP |
| `vulnerable` | any other label | FN |
| `safe` | `detected_vulnerability` | FP |
| `safe` | `explicit_safe` | TN |
| `safe` | `missing_review`, `scan_failure` | EXCLUDED |
| `safe` | `possible_vulnerability`, `insufficient_evidence`, `no_candidate` | UNCREDITED |

`correct` is `true` for TP and TN.

### Legacy rows

A result without a `pin` is scored as a legacy row: `legacy` is `true`,
`case_label` and `case_label_grounded` are `null`, and `predicted` and
`outcome` come from the category-filtered verdict of its findings.

### Summary keys

`summary.json` contains these top-level keys:

- `case_labels`: row count per `case_label`, including error rows; legacy
  rows, and legacy error rows, are counted under `legacy`.
- `legacy_rows`: number of legacy rows, including legacy error rows.
- `coverage`: totals over non-error rows with a coverage block: `rows`,
  `complete`, `complete_rate`, `sections_scheduled`, `sections_completed`,
  `sections_failed`, `sections_coalesced`, `hunks_total`, `hunks_reviewed`,
  `hunks_leftover`, `invalid_refs`, `planners`, `investigator_status` and
  `detected_with_gap`.

Each metrics block (`overall`, `per_category`, `per_split`, and the
`grounded_only` variants) covers non-error rows and reports:

- `vulnerable_scored`: scored vulnerable rows.
  `safe_scored`: scored safe rows other than EXCLUDED.
- `false_positive_rate_on_safe`: FP / `safe_scored`.
- `accuracy`: (TP + TN) / (`scored` − `excluded_on_safe`).
- `abstentions`: rows labelled `insufficient_evidence` or
  `possible_vulnerability`.
- `possible_on_safe`: safe rows labelled `possible_vulnerability`.
- `excluded_on_safe`: safe rows with outcome EXCLUDED.

### Run manifest and `--resume`

`run.json` stores `model`, `ollama_base_url`, `reasoning`, `mode` and `pin`.
The `pin` is built by `run_pin` with empty `base_sha` and `pr_sha`. Each case
result carries its own `pin` with the case's SHAs. The `code_dirty` check
excludes the output directory, so files written there do not count as changes.

`--resume` checks the existing `run.json` in this order, then runs the cases:

1. `model` and `reasoning` must match the current run; otherwise
   `--resume: <dir> was produced with a different model or reasoning setting`.
2. The manifest must have a `pin`; otherwise
   `--resume: <dir> has no run pin; start a new output directory`.
3. Every `pin` key other than `base_sha` and `pr_sha` must match; otherwise
   `--resume: <dir> was produced with a different run pin (differs in: <keys>)`.
4. A case is skipped when its result is not an error and its `case_label` is
   not `scan_failure`; other cases are run again.
