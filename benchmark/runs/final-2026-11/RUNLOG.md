# Final evaluation run log (6–7 Nov 2026)

What ran, on which code, what went wrong along the way, and what it cost. The numbers themselves are in
`RESULTS.md` and `results.json` next to this file; every run is a row in `benchmark/final_eval/manifest.jsonl`,
and every run's full console output is in `benchmark/final_eval/logs/<run_id>.log`, except the field trial
(see event 10).

## Code

- Branch `eval/final-integration` = `origin/main` (e2bd4f6) with the open PRs merged in this order:
  fix/deploy-env-bash32, docs/ai-logs-jayce-23-31-oct, feat/report-viewer, feat/real-prs-benchmark,
  feat/sqli-reviewer, feat/component-bench, demo-frontend-variations, feat/safe-markdown-frontend.
  On top: `--temperature` for the real-PR runner, the run driver and aggregation script, and a gpt-oss
  reviewer backend for Amazon Bedrock.
- **Every run used commit af878ce** (recorded per run in the manifest, `git_commit`). No pipeline or runner file
  changed while runs were going. `aggregate.py`, which no run uses, was changed between and after runs
  (cost read from the ledger's per-run labels, new tables).
- Test suite on af878ce: 3289 passed, 1 failed. The failure is a dependency check from one PR rejecting the
  `anthropic` package that another PR added: a merge conflict between PRs, not a behaviour bug.

## Hardware and models

- Reviewer Qwen3.8 27B (Ollama) and the Kev-4B judge on the SCIS GPU cluster: two Slurm jobs, each one
  NVIDIA L40S, 12 h walltime. The cluster's Blackwell partitions were tried first and dropped: they are
  MIG slices and ran at about 5 tokens/s.
- Claude Haiku 4.5, Claude Sonnet 4.6, gpt-oss-20b and gpt-oss-120b on Amazon Bedrock (Claude through the
  Anthropic SDK, gpt-oss through Bedrock's OpenAI-compatible endpoint). The Kev judge stays on the cluster
  for every variant, so only the reviewer model changes.
- Temperature: 0 unless stated. Claude on Bedrock is called without a temperature (provider default).

## Streams

Runs were split into streams that ran in parallel; each stream ran its runs one after another.

| Stream | Where | Runs |
|---|---|---|
| A | GPU job 1 | shoply (lgtm, llm-only), injection (lgtm, llm-only), field trial, dev real PRs, held-out T=0.5 |
| B | GPU job 2 | held-out T=0 runs 1, 2, 3; held-out T=1.0 |
| C | Bedrock | held-out Haiku 4.5, then Sonnet 4.6 |
| D1 | Bedrock | held-out gpt-oss-20b |
| D2 | Bedrock | held-out gpt-oss-120b |
| F | GPU job 2 + Bedrock | two single-case reruns (below) |
| G, G2 | GPU job 1 | component benchmark; G2 reran its three errored components (event 6) |
| H | GPU job 2 | held-out ablation: pipeline without Semgrep (lgtm-no-sast), T=0 |
| G3 | GPU job 2 (reviewer) + job 1 (Kev) | real-world CVE cases, lgtm and llm-only |
| R-* (12 streams) | Bedrock + Kev on both jobs | runs 2 and 3 of Sonnet 4.6, Haiku 4.5 and gpt-oss-120b on the held-out set |

Wall time: 6 Nov 16:39 to 7 Nov 02:40 SGT. 33 run ids in the manifest, all status ok. Each stream used its own
clone cache, so parallel runs never shared a git working tree.

## Events (also `_event` rows in the manifest)

1. **Shoply, first attempt (16:39).** `evaluate.py --resume` refused to continue a partial run made on an
   earlier commit (8ee8255), as designed. The partial run was moved to `shoply/lgtm-partial-8ee8255/` and
   Shoply was rerun from scratch on af878ce. Manifest: `shoply-lgtm` has a failed attempt then an ok one.
2. **Tunnel drop in held-out T=0 run 2 (18:17–18:20).** The connection to the cluster dropped for about three
   minutes during `alerta-query-string-parser-sqli-fixed`. The investigator and one authorization section failed
   with "Connection refused". That case was rerun alone on the same model, temperature and GPU job
   (`fix-r2-alerta`); the original record is kept in `heldout/_superseded/qwen27b-t0-r2-lgtm/`. Both the
   original and the rerun scored FP, so the run-2 numbers are the same either way.
3. **gpt-oss-20b, plain LLM, one unparsable reply.** `django-orderby-dotted-column-sqli-fixed` ended as ERROR
   ("plain:unparsable"). Rerun alone (`fix-gptoss20b-django`): TN. Original kept in
   `heldout/_superseded/gptoss20b-llm-only/`.
4. **Summaries regenerated.** The two reruns used `--cases`, which rewrites `summary.json` with only that case.
   Both summaries were rebuilt with `--summarize-only` over all 34 records before aggregation.
5. **Not rerun:** one field-trial PR (lgtm mode) has 1 of 2 review sections returning no parsable findings.
   This is a model output failure, not an infrastructure one, so it is reported as is: the field-trial summary
   shows coverage complete on 11 of 12 PRs.

6. **Component benchmark: three components never ran (6 Nov 23:44).** `component-bench` exited 0, but every
   investigator (12), authz (6) and evidence (24) unit was an error: the real-world case clones
   (`benchmark/real_world/.cache`, git-ignored, built by `benchmark/real_world/fetch.py`) did not exist in
   this worktree. `run.py` records such units as errors and still exits 0, so the run was logged "ok". Found
   by reading the scores, not the exit code. Clones built with `fetch.py --policies` (every SHA checked
   against `cases.json`) and the three components rerun with `--resume` (`component-bench-rerun`, stream G2).
   Retrieval, Semgrep and Kev units were not rerun.
7. **Real-world CVE cases added (7 Nov).** Found missing in a coverage check: the 12-case end-to-end
   benchmark had last run on October code (`benchmark/runs/archive/`). Run on af878ce (`realworld-qwen27b`).
   The first attempt to queue it never started (its wait loop matched its own command line); it was then
   started directly.
8. **Budget raised (7 Nov 01:15).** The user approved Bedrock spend up to USD 200 in total. New runs used a
   cap of USD 190 over the ledger. Spent on runs 2 and 3 of the three strongest Bedrock models. Each run was
   split into two halves of the advisories run in parallel, so that all twelve finished within the GPU judge
   jobs' walltime; each half used its own clone cache and Kev on one of the two jobs. The halves' partial
   `summary.json` files were rebuilt with `--summarize-only` over all 34 records.
9. **Investigator ratings.** The investigator's splits were rated against
   `component_bench/investigator/investigator_rubric.md` by Claude Opus 5.5 (the agent running these
   evaluations), one file per case in `component_bench/investigator/ratings/`, each with a `rater` field. Not
   reviewed by the team. The component `summary.json` was then rebuilt over all six components with
   `run.py --resume` (no model calls).

10. **Scrubbed before committing (7 Nov).** This repository is public. The field-trial run folder
   (`field_trial/`) and its log (`logs/field-trial.log`) name the flagged PR and describe an unreported finding,
   so they are git-ignored and kept only on the machine that ran the evaluation; `results.json` keeps the
   field-trial totals and drops its per-PR rows. In the other logs the local home directory was replaced
   with `~`. No numbers changed.

No other run has an ERROR outcome. Final per-case state: 0 errors in every variant.

## Headline results (details in RESULTS.md)

Held-out set: 17 published advisories, each reviewed on the PR that introduced it and on its fix.

- **LGTM with Qwen3.8 27B (T=0):** 15/17 caught, 14/17 exact (right file and CWE family), 1/17 false alarm on
  fixes, median 124 s per diff.
- **Repeatability:** three T=0 runs gave identical counts (15, 15, 15 caught; 14, 14, 14 exact; 1, 1, 1 false
  alarm) and the same 15 advisories caught each time. Plain LLM: 7, 7, 7.
- **Three runs per Bedrock model (LGTM):** gpt-oss-120b caught 16, 15, 15 with 5, 7, 4 false alarms; Haiku 4.5
  16, 16, 16 with 8, 6, 11; Sonnet 4.6 16, 16, 17 with 5, 5, 3. Plain LLM stays at 4–7 for every model and run.
  The cloud models catch about one advisory more than Qwen and raise 3–11 false alarms per run against Qwen's 1.
- **Ablation (Qwen, T=0):** without Semgrep the pipeline catches 14/17 (13 exact) with 3 false alarms, against
  15/17 (14 exact) and 1 with it.
- **Real-world CVE cases (12, Qwen):** both modes catch all 6 vulnerable cases. LGTM raises 2 false alarms on
  the 6 safe cases, the plain LLM none (scored without the 3 out-of-scope cases: F1 0.91 against 1.00). These
  vulnerable cases are synthetic reverts of small fixes; LGTM shows no advantage on them.
- **Component benchmark:** retrieval hit@k 1.00; investigator mean rubric rating 0.98 (12 rated, see event 9);
  authz reviewer alone precision 0.29, recall 0.67, F1 0.40; Semgrep SQLi F1 0.75; evidence validator F1
  1.00; Kev verdicts correct 0.87. Labels are drafts by Claude Opus 5.5, not reviewed by the team.
- **Temperature:** T=0.5 gives 15/17 with 2 false alarms; T=1.0 gives 14/17 with 3.
- **Same pipeline, other reviewer models (run 1 of each; runs 2 and 3 above):**

| Reviewer | Caught | Exact | False alarms | Cost |
|---|---|---|---|---|
| Qwen3.8 27B | 15/17 | 14/17 | 1/17 | GPU cluster |
| Claude Sonnet 4.6 | 16/17 | 16/17 | 5/17 | $22.06 |
| Claude Haiku 4.5 | 16/17 | 16/17 | 8/17 | $9.31 |
| gpt-oss-120b | 16/17 | 14/17 | 5/17 | $2.60 |
| gpt-oss-20b | 7/17 | 7/17 | 1/17 | $1.43 |

  Costs cover the LGTM and plain LLM runs together.
- **Baselines:** plain LLM with the same model: 3–7/17 caught. Semgrep only: 3/17 caught, 2 false alarms.
- **Dev set** (13 advisories used to build the SQLi reviewer): LGTM 13/13 exact, 2 false alarms. Plain LLM
  7/13. Semgrep 0/13.
- **Shoply** (52 synthetic cases): LGTM precision 1.00, recall 1.00, F1 1.00. Plain LLM F1 0.94 (1 FP, 2 FN).
- **Prompt injection** (6 attacks on cases that are flagged without the injection): 0/6 succeeded, in both
  LGTM and plain LLM mode.
- **Field trial** (12 recently merged PRs): no crashes, median 78 s per PR, 1 PR flagged (judge-supported).
  The flagged finding is unreported and is not described in this repository.

## Cost

Bedrock spend for these final runs: **$101.72**.
- Run 1 (6 Nov): $35.41 — Sonnet 4.6 $22.06, Haiku 4.5 $9.31, gpt-oss-120b $2.60, gpt-oss-20b $1.43
  (including its rerun). These had a hard cap of $95 on the ledger total.
- Runs 2 and 3 (7 Nov): $66.30 — Sonnet 4.6 $21.22 + $21.39, Haiku 4.5 $9.28 + $9.54, gpt-oss-120b
  $2.44 + $2.43. Cap $190 on the ledger total, after the user raised the budget to $200 (event 8).

Smoke tests on 6 Nov: $0.40. Earlier work (4–5 Nov) logged in the same ledger: $16.73. Ledger total:
**$118.85**, under the $200 budget.

Source: `~/.lgtm/bedrock-spend.jsonl` (one line per call: model, tokens, USD, run label), summed by label.
The manifest's `bedrock_usd_run` field (ledger total after minus before) is **not** a per-run cost: streams
ran in parallel, so it includes other streams' spend. `aggregate.py` no longer uses it.
