# Where each number on the slides comes from

This file maps every figure used in the final presentation to the record it was read from, so a reader can check any slide against the raw results. `deck-numbers.json` holds the same keys and values. The "Extras" section at the end has failure analysis, re-runs and caveats that did not fit on the slides.

Every value comes from the final evaluation run in `benchmark/runs/final-2026-11/` (added by PR #37, branch `eval/final-integration`). That run and all of its records were made on commit **af878ce** (af878ce46af7d57419d8237931aa1c8100a8d6a3), 6 Nov 16:39 to 7 Nov 02:40 SGT. When this file was written (8 Nov), #33's component-bench runs from 5–6 Nov were superseded by `final-2026-11/component_bench`.

"Final held-out run" = `heldout/qwen27b-t0-r1`: Qwen3.8 27B reviewer, Kev-4B judge, T=0, all 17 advisories, 34 diffs (each introducing PR plus its fix).

Short names for the source files used below:
- **R** = `benchmark/runs/final-2026-11/results.json` (written by `benchmark/final_eval/aggregate.py`)
- **RM** = `benchmark/runs/final-2026-11/RESULTS.md`, **RL** = `benchmark/runs/final-2026-11/RUNLOG.md`
- **H/** = `benchmark/runs/final-2026-11/heldout/qwen27b-t0-r1/` (one JSON file per diff)

Rounding: medians are rounded to whole seconds (124.0 → 124, 7.3 → 7, 139.8 → 140), and F1 and USD to two decimals.

## Held-out benchmark

| Key | Value | Source |
|---|---|---|
| heldout.lgtm.caught | 15 / 17 | R `heldout["qwen27b-t0-r1/lgtm"].all.caught` |
| heldout.llm.caught | 7 / 17 | R `heldout["qwen27b-t0-r1/llm-only"].all.caught` |
| heldout.sast.caught | 3 / 17 | R `heldout["qwen27b-t0-r1/sast-only"].all.caught` |
| heldout.lgtm.exact | 14 / 17 | R `…/lgtm.all.exact` |
| heldout.llm.exact | 7 / 17 | R `…/llm-only.all.exact` |
| heldout.sast.exact | 3 / 17 | R `…/sast-only.all.exact` |
| heldout.lgtm.sqli_exact | 7 / 8 | R `…/lgtm.sqli.exact` |
| heldout.llm.sqli_exact | 4 / 8 | R `…/llm-only.sqli.exact` |
| heldout.sast.sqli_exact | 3 / 8 | R `…/sast-only.sqli.exact` |
| heldout.lgtm.authz_exact | 7 / 9 | R `…/lgtm.authz.exact` |
| heldout.llm.authz_exact | 3 / 9 | R `…/llm-only.authz.exact` |
| heldout.lgtm.fa | 1 / 17 | R `…/lgtm.all.false_alarms` |
| heldout.llm.fa | 2 / 17 | R `…/llm-only.all.false_alarms` |
| heldout.sast.fa | 2 / 17 | R `…/sast-only.all.false_alarms` |
| heldout.lgtm.sec | 124 | R `…/lgtm.median_seconds_per_diff` = 124.0 |
| heldout.llm.sec | 7 | R `…/llm-only.median_seconds_per_diff` = 7.3 |
| heldout.sast.sec | 1 | R `…/sast-only.median_seconds_per_diff` = 1.1 |
| heldout.lgtm.caught_noweak | 13 / 14 | R `…/lgtm.without_weak.caught` |
| heldout.llm.caught_noweak | 6 / 14 | R `…/llm-only.without_weak.caught` |
| TITLE | LGTM caught 15 of 17 real advisories with 1 false alarm on the 17 fixes; the same model with only the diff caught 7 | from the rows above |

## Per advisory (final run)

"other file" = the aggregator's `caught` cell: flagged and judge-supported, but not in an advisory file (R: `caught` true, `on_target` false). Source for every row: R `heldout["qwen27b-t0-r1/lgtm"|"qwen27b-t0-r1/llm-only"].per_advisory[<id>]`, as rendered in RM "Per advisory", columns "Q r1 lgtm" and "Q r1 llm".

| Key | LGTM | Key | Plain LLM | Advisory id |
|---|---|---|---|---|
| adv.s1.lgtm | exact +FP | adv.s1.llm | exact | alerta-query-string-parser-sqli |
| adv.s2.lgtm | miss | adv.s2.llm | miss | django-orderby-dotted-column-sqli |
| adv.s3.lgtm | exact | adv.s3.llm | miss | django-raster-band-index-sqli |
| adv.s4.lgtm | exact | adv.s4.llm | miss | ormar-aggregate-minmax-sqli |
| adv.s5.lgtm | exact | adv.s5.llm | exact | piccolo-savepoint-name-sqli |
| adv.s6.lgtm | exact | adv.s6.llm | miss +FP | rucio-oracle-json-meta-filter-sqli |
| adv.s7.lgtm | exact | adv.s7.llm | exact +FP | rucio-postgres-meta-filter-sqli |
| adv.s8.lgtm | exact | adv.s8.llm | exact | taiga-epic-order-sqli |
| adv.a1.lgtm | exact | adv.a1.llm | miss | authentik-ssf-stream-authz |
| adv.a2.lgtm | exact | adv.a2.llm | miss | django-cms-structure-endpoint-authz |
| adv.a3.lgtm | exact | adv.a3.llm | miss | khoj-subscription-email-idor |
| adv.a4.lgtm | exact | adv.a4.llm | miss | openedx-support-manage-course-team-authz |
| adv.a5.lgtm | other file | adv.a5.llm | miss | paperless-ngx-global-search-mail-authz |
| adv.a6.lgtm | exact | adv.a6.llm | exact | plane-bulk-issue-dates-idor |
| adv.a7.lgtm | miss | adv.a7.llm | miss | readthedocs-team-access-filter-authz |
| adv.a8.lgtm | exact | adv.a8.llm | exact | sentry-notification-option-delete-idor |
| adv.a9.lgtm | exact | adv.a9.llm | exact | sentry-rule-snooze-idor |

## Reviewer-model comparison

All rows use the same pipeline (lgtm mode) and the same Kev-4B judge on the GPU cluster, run 1 of each model. Claude models were called at the provider's default temperature, the others at T=0. USD is the Bedrock cost of the **whole run, lgtm and plain LLM together** (from the spend-ledger label).

| Key | Value | Source |
|---|---|---|
| MODEL.SET | 17 held-out | R `heldout` keys `<model>/lgtm` |
| model.qwen27b.caught / exact / fa / sec / usd | 15 / 17 · 14 / 17 · 1 / 17 · 124 · 0.00 | R `heldout["qwen27b-t0-r1/lgtm"]`; ran on the GPU cluster (`bedrock_usd_run_total` 0.0) |
| model.gptoss20b.caught / exact / fa / sec / usd | 7 / 17 · 7 / 17 · 1 / 17 · 231 · 1.43 | R `heldout["gptoss20b-bedrock/lgtm"]` (231.2 s; `bedrock_usd_run_total` 1.434) |
| model.gptoss120b.caught / exact / fa / sec / usd | 16 / 17 · 14 / 17 · 5 / 17 · 120 · 2.60 | R `heldout["gptoss120b-bedrock/lgtm"]` (120.4 s; 2.6004) |
| model.haiku45.caught / exact / fa / sec / usd | 16 / 17 · 16 / 17 · 8 / 17 · 140 · 9.31 | R `heldout["haiku45/lgtm"]` (139.8 s; 9.3127) |
| model.sonnet46.caught / exact / fa / sec / usd | 16 / 17 · 16 / 17 · 5 / 17 · 156 · 22.06 | R `heldout["sonnet46/lgtm"]` (156.3 s; 22.0649) |
| model.verdict | The local 27B model catches one advisory fewer than Sonnet 4.6, Haiku 4.5 and gpt-oss-120b (15 vs 16 of 17) but raises 1 false alarm against their 5–8, at no Bedrock cost | from the rows above |

## Repeatability and temperature (Qwen3.8 27B, lgtm, held-out)

| Key | Value | Source |
|---|---|---|
| repeat.lgtm.caught_runs | 15 / 15 / 15 | R `repeatability["Qwen3.8 27B (T=0)/lgtm"].caught` = [15, 15, 15] |
| repeat.lgtm.stable | 17 / 17 | R `heldout["qwen27b-t0-r{1,2,3}/lgtm"].per_advisory`: the full outcome cell (exact/other file/miss, ±FP) is identical in all three runs for all 17. Counted by script from R (no stored field). `repeatability.sometimes` and `false_alarm_sometimes` are both empty |
| temp.0.caught | 15 / 17 | R `heldout["qwen27b-t0-r1/lgtm"].all.caught` |
| temp.0.5.caught | 15 / 17 | R `heldout["qwen27b-t0.5/lgtm"].all.caught` |
| temp.1.0.caught | 14 / 17 | R `heldout["qwen27b-t1.0/lgtm"].all.caught` |

## Failure analysis

| Key | Value | Source |
|---|---|---|
| fail.django_orderby.lgtm | miss | R `…/lgtm.per_advisory["django-orderby-dotted-column-sqli"]` (0 findings on either diff) |
| fail.readthedocs.lgtm | miss | R `…/lgtm.per_advisory["readthedocs-team-access-filter-authz"]` (0 findings on either diff) |
| fail.unparsable.count | 6 | R `heldout["qwen27b-t0-r1/lgtm"].agent_errors` = 6. All six are "returned no parsable findings" after the re-asks (`max_answer_reasks` = 3 in `src/lgtm/config.py`), across 4 diffs: H/`alerta-…-vulnerable` 1, `alerta-…-fixed` 1, `authentik-…-vulnerable` 1, `rucio-oracle-…-vulnerable` 3. All four advisories were still caught |

## Shoply, field trial, injection

| Key | Value | Source |
|---|---|---|
| shoply.lgtm.f1 | 1.00 | R `shoply.lgtm.summary.overall.f1` (52 cases, TP 26, FP 0, FN 0, TN 26) |
| shoply.llm.f1 | 0.94 | R `shoply["llm-only"].summary.overall.f1` (TP 24, FP 1, FN 2, TN 25) |
| shoply.lgtm.f1_eval | 1.00 | R `shoply.lgtm.summary.per_split.eval.f1` (26 cases) |
| shoply.llm.f1_eval | 0.88 | R `shoply["llm-only"].summary.per_split.eval.f1` (TP 11, FP 1, FN 2, TN 12) |
| fieldtrial.lgtm.reach | 12 / 12 | R `field_trial.lgtm.summary.prs_reviewed_by_agent` = 12 of `cases` 12 |
| fieldtrial.lgtm.fa | n/a | The field trial has no ground truth, so the scorer counts no false alarms. It records PRs flagged: lgtm 1 / 12, judge-supported (R `field_trial.lgtm.summary.prs_with_vulnerable_verdict`, `judge.supported`) |
| fieldtrial.llm.fa | n/a | Same reason; plain LLM flagged 1 / 12 PRs (R `field_trial["llm-only"].summary.prs_with_vulnerable_verdict`) |
| fieldtrial.lgtm.sec | 78 | R `field_trial.lgtm.summary.latency_median_seconds` = 78.1 |
| fieldtrial.llm.sec | 7 | R `field_trial["llm-only"].summary.latency_median_seconds` = 6.8 |
| injection.lgtm.asr | 0 / 6 | R `injection.lgtm.summary.attacks_succeeded` = 0, `total_cases` 6 |
| injection.llm.asr | 0 / 6 | R `injection["llm-only"].summary.attacks_succeeded` = 0, `total_cases` 6 |

## Cost and provenance

| Key | Value | Source |
|---|---|---|
| cost.gpu_hours | n/a | Not recorded. RL says two Slurm jobs, each one L40S with **12 h walltime reserved**; actual GPU hours are not logged anywhere |
| cost.bedrock_usd | 101.72 | R `bedrock_usd_total` = 101.7162; RL "Cost": Bedrock spend for these final runs |
| cost.total_usd | 118.85 | RL "Cost": whole Bedrock ledger total = 101.72 final runs + 0.40 smoke tests + 16.73 earlier work (4–5 Nov). The GPU cluster is not billed. If the deck means "cost of the final evaluation", use 101.72 |
| cost.tokens_per_diff | n/a | The held-out runner does not record tokens (no token field in H/ records or the summary). Only Shoply records `median_est_tokens_per_pr` (see Extras) |
| run.commit | af878ce | `git_commit` in H/`lgtm/summary.json` and in every row of `benchmark/final_eval/manifest.jsonl`; RL "Every run used commit af878ce" |
| run.dates | 6–7 Nov 2026 | RL: wall time 6 Nov 16:39 to 7 Nov 02:40 SGT; manifest start/end timestamps |

## Deep dive: SQLi (S3 django-raster-band-index)

Chosen because it is the strongest finished case of the three: LGTM exact in all 5 Qwen runs (3 × T=0, T=0.5, T=1.0) and without Semgrep, plain LLM and Semgrep both missed it, and the fix stayed clean. S7 had a plain-LLM catch; S8 was also caught by the plain LLM.

| Key | Value | Source |
|---|---|---|
| DEEPDIVE.sqli.case | S3 django-raster-band-index | |
| DEEPDIVE.sqli.headline | Django's raster band index went straight into PostGIS SQL: LGTM traced it, the plain LLM and Semgrep did not | |
| DEEPDIVE.sqli.flaw | GHSA-mwm9-4648-f68q (CVE-2026-1207), django/django, CWE-89, advisory severity high. Adding spatial lookups to RasterField formatted the band index from the lookup tuple into the PostGIS SQL template unvalidated, so any user whose input an application passes as a raster lookup's band index could inject SQL. | `benchmark/real_prs/heldout.json` (id, ghsa, cve, cwe, severity, title, where) |
| DEEPDIVE.sqli.finding | CWE-89, Kev severity critical, django/contrib/gis/db/backends/postgis/operations.py:61. check_raster() concatenates lookup.band_lhs/band_rhs into the SQL text with '%s, %s' % (...) instead of binding them, and band_rhs comes verbatim from the lookup tuple (lookups.py:87). Kev verdict: real (supported). A second finding flagged lookups.py:87 (CWE-89, critical, real). | H/`lgtm/django-raster-band-index-sqli-vulnerable.json` `findings[0..1]` (`cwe_id`, `file`, `line`, `kev_severity`, `kev_verdict`, `supported`; `explanation` paraphrased). The `severity` field itself is empty; the severity shown is Kev's |
| DEEPDIVE.sqli.evidence | Cited operations.py:58–66 and lookups.py:82–87 (PR snapshot, i.e. the changed code, not base), opened with read_file after grep_repo 'band_lhs\|band_rhs' and one investigate_base_code query on where band_lhs/band_rhs are set: 5 tool calls in that SQLi section. Policy passage: Django docs/topics/security.txt via search_policy. | same file, `findings[*].evidence` and `trace.runs[section="sqli:raster-ops"]` |
| DEEPDIVE.sqli.others | Plain LLM (same model): miss, answered safe. Semgrep: no findings on the vulnerable or the fix diff. LGTM on the fix commit: 0 findings (clean). | H/`llm-only/…-vulnerable.json` (`verdicts` {"safe": 2}), H/`sast-only/…-{vulnerable,fixed}.json` (0 findings), H/`lgtm/…-fixed.json` (outcome TN, 0 findings) |

## Deep dive: authz (A3 khoj-subscription-email-idor)

Chosen over A1 and A6: A6 (plane) was also caught by the plain LLM. A1 (authentik) is exact but raised a judge-supported finding on the fix in the Claude runs, and one of its sections returned no parsable answer in the final run. A3 is exact in all 5 Qwen runs, missed by the plain LLM and Semgrep, and clean on the fix.

| Key | Value | Source |
|---|---|---|
| DEEPDIVE.authz.case | A3 khoj-subscription-email-idor | |
| DEEPDIVE.authz.headline | Logged in is not authorised: LGTM caught khoj's subscription endpoint acting on any email the caller names | |
| DEEPDIVE.authz.flaw | GHSA-hq4h-w933-jm6c (CVE-2024-52294), khoj-ai/khoj, CWE-639, advisory severity moderate. The billing PR added PATCH /api/subscription, which took the target customer's email from a query parameter instead of the logged-in user, so any authenticated user could cancel or resume anyone's Stripe subscription. | `benchmark/real_prs/heldout.json` |
| DEEPDIVE.authz.finding | CWE-639, Kev severity high, src/khoj/routers/subscription.py:85. update_subscription is guarded only by @requires(["authenticated"]) and looks up and modifies the Stripe customer for a caller-supplied email, never comparing it with the requesting user. Kev verdict: real (supported). Two findings, both at line 85. | H/`lgtm/khoj-subscription-email-idor-vulnerable.json` `findings[0..1]` |
| DEEPDIVE.authz.policy | No relevant policy passage: all 19 search_policy calls returned unrelated docs (notion/github integration guides, app README; relevance 0.06–0.33) and neither finding cites policy. The check compared against was code: the @requires(["authenticated"]) gate (subscription.py:82), configure.py authenticate() (63–79, outside the diff), grep for request.auth: no matches. | same file, `trace.runs[*]` search_policy results; `findings[0].evidence[2]` (`grounded_in_pr` false); `trace.runs[section="fallback:src/khoj/routers/subscription.py"]` grep_repo results |
| DEEPDIVE.authz.others | Plain LLM (same model): miss, answered safe. Semgrep: no findings on the vulnerable or the fix diff. LGTM on the fix commit: 0 findings (clean). | H/`llm-only/…-vulnerable.json` (`verdicts` {"safe": 2}), H/`sast-only/…` (0 findings), H/`lgtm/…-fixed.json` (TN, 0 findings) |

## Extras

Flagged for the team to decide on. None of these is in a key.

**Numbers that contradict the 5 Nov figures the deck still quotes**
- Median seconds per diff (LGTM, held-out): **124**, not 191. The 191 s is the 5 Nov v2.1 run (`docs/real-prs-eval.md`). The final runs 2 and 3 took 106.8 and 104.1 s. Source: R `heldout["qwen27b-t0-r{1,2,3}/lgtm"].median_seconds_per_diff`.
- Plain LLM median: **7 s** (7.3), not 10. Source: R `…/llm-only.median_seconds_per_diff`.
- Shoply: **lgtm F1 1.00, plain LLM 0.94**, against the deck's 0.94 / 0.75 / 0.62. The final run has no Semgrep-only Shoply mode, so there is nothing to compare with the third number. Source: R `shoply.*.summary.overall.f1`.
- "Authz 0/6 → F1 0.92": not reproduced. On the 6 real-world authz cases the final run gives lgtm authz F1 **0.86** (TP 3, FP 1, TN 2), plain LLM 1.00. Source: R `real_world.*.summary.per_category.authz`.
- "SQLi FP 75% → 0%": I could not find which set this refers to in the final run. Real-world SQLi lgtm false-positive rate on safe cases is 0.0, but only 1 safe SQLi case is in scope. Shoply SQLi FPR is 0.0 for both modes. Source: R `real_world.lgtm.summary.per_category.sqli`, `shoply.*.summary.per_category.sqli`. Please confirm where the deck's number came from.
- "Semgrep 0/13 on the dev set" holds (R `real_prs_dev["sast-only"].all.caught` = 0). New: Semgrep was run on the held-out set this time and caught **3 / 17** (ormar, piccolo, rucio-oracle), with 2 / 17 false alarms. The 5 Nov doc says it was not run there.
- Component results: retrieval hit@k 1.00 holds. Validator 24/24 holds (evidence: 24 units, TP 12, TN 12, F1 1.00). Judge 13/15 holds (`verdict_correct` 0.867 of 15 units). Not on the deck: authz reviewer alone has precision 0.29, recall 0.67, F1 0.40, and Semgrep SQLi has F1 0.75. **All component labels are drafts by Claude Opus 5.5, not reviewed by the team.** Source: R `component_bench.components`; RL event 9.

**Outcome changes from v2.1 to the final run**
- None. All 17 per-advisory cells for LGTM and for the plain LLM are identical between v2.1 (`docs/real-prs-eval.md`, 5 Nov) and the final run 1. Only latency changed.

**Interesting false alarms and misses**
- alerta fix (the only LGTM false alarm): the fixed `SearchTerm.to_sql` still puts the `?q=` field name into SQL as an f-string quoted identifier (`queryparser.py:152`), and Kev ruled it real. This may be a real residual issue in the fix and not a pure false alarm (see "Fixed is not safe" in `docs/real-prs-eval.md`). Source: H/`lgtm/alerta-query-string-parser-sqli-fixed.json`.
- Kev filtered 5 findings on fix commits that would otherwise have been false alarms: rucio-oracle fix 3 and piccolo fix 2, all ruled `not_real`. Source: H/`lgtm/rucio-oracle-…-fixed.json`, `piccolo-…-fixed.json`.
- Missed by every Qwen mode: django-orderby (a regex check removed deep inside `Query.add_ordering()`) and readthedocs (two chained `.filter()` calls on a many-valued relation make separate joins). Root causes per `docs/real-prs-eval.md`. readthedocs **is** caught (exact) by Qwen at T=0.5 and T=1.0, by gpt-oss-120b and Haiku 4.5 in all 3 runs, and by Sonnet 4.6 in runs 2 and 3. Source: RM "Per advisory".
- Taiga (S8): LGTM also posted a CWE-639 authz finding on the same SQLi line next to the CWE-89 one. Source: H/`lgtm/taiga-epic-order-sqli-vulnerable.json`.

**Tool calls, budgets, re-asks**
- Final held-out run, summed by script over the 34 records in H/`lgtm/`: investigator 571 tool calls, reviewers 1,105, SAST triage 91. The "tool call budget exhausted" message appears 46 times in 17 of the 34 diffs. These are derived counts (no stored total); fields `investigator_tool_calls`, `reviewer_tool_calls`, `sast_triage_tool_calls`, and the trace text.
- Re-asks are not counted separately in the records. Only failures after re-asks are stored (`agent_errors`: 6 in run 1, see fail.unparsable.count).
- Agent errors by variant (R `heldout[*].agent_errors`): Qwen r1/r2/r3 lgtm 6/6/6, T=0.5 1, T=1.0 3, **gpt-oss-20b 70**, gpt-oss-120b 24/16/14, Haiku 2/3/2, Sonnet 1/2/6. gpt-oss-20b's weak result (7 / 17) coincides with 70 section failures.
- Shoply (52 cases) tool calls: investigator 1,248, reviewer 417, SAST triage 167. Median estimated tokens per PR: lgtm 938, plain LLM 580. Source: R `shoply.*.summary.tool_calls`, `median_est_tokens_per_pr`.

**Re-runs and infrastructure**
- 2 single-case re-runs. (1) A cluster tunnel dropped for about 3 min during Qwen run 2 on the alerta fix, and the case was re-run (`fix-r2-alerta`); both attempts scored FP. (2) gpt-oss-20b plain LLM returned an unparsable reply on the django-orderby fix, and the re-run gave TN (`fix-gptoss20b-django`). Originals are in `heldout/_superseded/`. Source: RL events 2–3.
- Shoply's first attempt was refused on resume (commit moved from 8ee8255 to af878ce). 32 finished cases were set aside in `shoply/lgtm-partial-8ee8255/` and the run restarted. Source: RL event 1.
- Component bench: 42 units (investigator 12, authz 6, evidence 24) errored because the case clones were missing, and were re-run. Source: RL event 6.
- A Claude Code session ended on 6 Nov at about 16:02 SGT and killed 5 streams. They were resumed; finished cases were kept. Source: `benchmark/final_eval/manifest.jsonl` first `_event` row.
- One field-trial PR had 1 of 2 review sections unparsable, so coverage was complete on 11 / 12 PRs. It was not re-run. Source: RL event 5; R `field_trial.lgtm.summary.prs_coverage_complete`.
- Test suite on af878ce: 3,289 passed, 1 failed (a dependency check that conflicts between PRs). Source: RL "Code".

**Additional runs the keys don't cover**
- Ablation without Semgrep (Qwen, T=0): 14 / 17 caught, 13 exact, **3 / 17 false alarms**, 101 s. Semgrep earns its place by cutting false alarms and adding one catch (ormar). Source: R `heldout["qwen27b-t0-r1/lgtm-no-sast"]`.
- Runs 2 and 3 for the Bedrock models, LGTM caught: gpt-oss-120b 16 / 15 / 15 (FA 5 / 7 / 4), Haiku 16 / 16 / 16 (FA 8 / 6 / 11), Sonnet 16 / 16 / 17 (FA 5 / 5 / 3). Plain LLM stays at 4–7 for every model and run. Source: R `repeatability`.
- Dev set (13 advisories), final code: LGTM 13 / 13 exact, 2 / 13 false alarms, 105 s. Plain LLM 7 / 13. Semgrep 0 / 13. Source: R `real_prs_dev`.
- Real-world CVE cases (12; 3 out of scope): both modes catch all 6 vulnerable. LGTM F1 0.91 against plain LLM 1.00, and LGTM raises 2 false alarms on the 6 safe cases. **This set shows no LGTM advantage**, and RL says so. Source: R `real_world`; RL headline results.
- Bedrock models at T=0.5/T=1.0 were not run. Claude was called only at the provider default temperature.

**Live-hunt leads since published**
- GHSA-jrgm-fhgv-hmj9 (wagtail PR #14488) and GHSA-c2xx-cjmh-9q8f (wagtail PR #14490). Source: `docs/real-prs-eval.md` "Live hunt". The live-hunt run outputs are git-ignored, so this is the only committed record.

**Possible mistakes in the keys as specified**
- `fieldtrial.*.fa`: the field trial has no ground truth, so no false-alarm metric exists. The scorer counts "PRs flagged" (1 / 12 in each mode).
- `cost.tokens_per_diff` and `cost.gpu_hours` are not recorded for the held-out run.
- `run.dates` example "8–9 Nov": the final runs ran 6–7 Nov. Nothing ran after 7 Nov.
- `model.*.usd` covers the lgtm and plain LLM runs together. The ledger is per run label, not per mode.
- `model.verdict` example "within one case of Sonnet 4.6": the case count is right, but on exact matches Qwen is 14 against Sonnet's 16, and on false alarms it is 1 against 5.
- Per-advisory value set: the aggregator has one more cell, `on file` (right file, wrong CWE family). It does not occur in the Qwen run-1 lgtm or llm columns, but does occur for other models.
- `DEEPDIVE.sqli.evidence` asks for "base-code lines". In S3 the cited lines were read from the PR snapshot (the changed files). The only base-side call was one `investigate_base_code` query.
- `DEEPDIVE.authz.policy` assumes a policy passage was retrieved. For khoj (and for authentik and plane) the repo has no security policy, so search_policy returned unrelated docs. The deck's "retrieval hit@k 1.00" comes from the 6 real-world authz cases, which have a written policy, not from the held-out set.
- `heldout.*.sec` is the median over all 34 diffs (vulnerable and fixed), not over 17.
