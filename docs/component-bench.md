# Component benchmark

Scores each pipeline component separately over the 12 real-world cases in `benchmark/real_world/cases.json`, against gold labels.

## Command

```
python benchmark/component_bench/run.py [--components NAME ...] [--resume] [--results-dir DIR]
```

| Option | Effect |
| --- | --- |
| `--components` | Run only the named components. Default: every registered component. |
| `--resume` | Keep completed units and rerun units recorded as error. Each unit is saved as it completes. Any run is refused when the results directory holds results written under a different model setting (agent model and endpoint, judge model and endpoint). |
| `--results-dir` | Output directory. Default: `benchmark/component_bench/results/` (git-ignored). |
| `--labels-dir` | Label directory. Default: `benchmark/component_bench/labels/`. |
| `--gpu-model` | GPU model key from `lgtm.config.GPU_MODELS`. Default: `qwen3.8-27b`. |

## Output

- `<results-dir>/<component>.json`: label counts and one record per unit (`case_id`, `label_id`, `status`, `scores`, `wall_time_s`, `input_tokens`, `output_tokens`, `tools`; scored units may also carry `label_ids` and `detail`, which for `evidence` holds `validator_reasons` and `stated_reason`).
- `<results-dir>/summary.json`: per component, mean scores, units scored, errored and not scored, draft and approved label counts (`n/a` for the investigator), wall time total, token totals and tool calls.

Unit status is `scored`, `error` (model, judge or dependency failure; excluded from scores, rerun on resume) or `not_scored` (counted separately). A metric scored `None` is left out of that metric's mean. Tokens the model did not return are stored as null and shown as `not recorded`.

## Labels

`benchmark/component_bench/labels/<component>.json` holds `component` and `items`; each item has `label_id`, `case_id`, `source`, `review_state` (`draft` or `approved`), `gold_input`, `gold` and optionally `distractor`. Loading rejects an unknown `case_id`, a duplicate `label_id`, a missing field or a case outside the component's applicable set.

## Adding a component

Add `benchmark/component_bench/<name>.py` exposing `run_item(item, ctx)` and `score(item, output)`, and one line in `benchmark/component_bench/registry.py`: `REGISTRY["<name>"] = Entry("<name>", applicable=frozenset({"<case id>", ...}))`. `applicable` is the set of case ids the component's labels may use; omit it to allow every case. `InfraError` and `NotScored` are imported from `benchmark.component_bench.outcomes`.

## Policy retrieval

`--components retrieval` runs one unit per case over the 6 authz cases (aegra, langflow, litellm; vulnerable and safe). The 6 sqli cases are recorded as `not_scored` (not applicable). Each authz case indexes its project policy from `benchmark/real_world/policies/` into a temporary Chroma directory and queries it with the case description at `rag_top_k`. No model is called.

Gold labels in `labels/retrieval.json` are policy passages (`gold`: `source`, `start_line`, `end_line`; source `security-policy.md` is the indexed policy name). A retrieved chunk is a hit when it is in the same source and its line range overlaps a gold passage.

| Score | Meaning |
| --- | --- |
| `hit_at_k` | 1 when any gold passage is retrieved in the top k, else 0. |
| `recall_at_k` | Fraction of the case's gold passages retrieved in the top k. |
| `mrr` | Reciprocal rank of the first chunk overlapping a gold passage, 0 when none. |

The summary section `aggregate` lists the draft and approved label counts and the gold label ids of each case.

## Investigator

Runs the investigator on each of the 12 cases and has no label file. The split is rated offline, not by the benchmark.

- Written results: `<results-dir>/investigator/<case_id>.json` with `case_id`, `diff` (the PR diff) and `sections` (`id`, `title`, `rationale`, `hunks` with each hunk's id and lines). Only the investigator's own proposed sections are written, with no fallback sections. A case whose output fails plan validation, or has no section with a valid hunk, is `not_scored`, writes no result and is listed as `plan_invalid`; a model or dependency failure is `error`.
- Rubric: `benchmark/component_bench/investigator_rubric.md`, copied to `<results-dir>/investigator/` on each run. It states the criteria and the 0.00, 0.50 and 1.00 anchors.
- Rating records: `<results-dir>/investigator/ratings/<case_id>.json` as `{"case_id": ..., "rating": ..., "reason": ...}`, written once per case by a Claude Code subagent. A `rating` outside 0.00 to 1.00, or a missing or empty `reason`, is rejected.
- Summary: the `aggregate` section holds `ratings` per case, `mean` over rated cases (null when none), `rated`, `with_result`, `unrated` and `plan_invalid`.

## authz

Runs the authz reviewer on the gold section of each of the 6 authz cases (aegra, langflow, litellm; vulnerable and safe), with the gold policy passages as its policy input. Labels: `benchmark/component_bench/labels/authz.json`; `gold_input` holds `section` and `policy_passages`; `gold` holds `vulnerable`, `locations` (`file`, `start`, `end`, inclusive; new-side lines), optional `old_locations` (same shape; base-side lines of removed checks; a finding inside either range is a hit) and `known_issues` (`id`, `file`, `start`, `end`).

Scores per unit: `tp`, `fn`, `fp`, `tn`.

| Case | Finding | Score |
| --- | --- | --- |
| Vulnerable | on a gold location | `tp` 1 |
| Vulnerable | none on a gold location | `fn` 1 |
| Vulnerable | not on a gold location | `fp` 1 each |
| Safe | none | `tn` 1 |
| Safe | inside a known issue | not counted |
| Safe | elsewhere | `fp` 1 each |

The reviewer's tools read the case repository from the clone under `benchmark/real_world/.cache/<project>`.

## SAST SQLi

`sast-sqli` runs `SASTTriageAgent.triage` on one Semgrep hit per label and scores keep or drop. Semgrep is not run. Labels cover the 6 sqli cases: `gold_input` holds the `SemgrepFinding` fields (`rule_id`, `path`, `start_line`, `end_line`, `message`, `severity`, `matched_code`) plus `excerpt` (`start_line` and the exact source `lines` around the hit, from the upstream file). The run writes the excerpt into a temporary local git repo at `path`, blank-padded so the lines keep their real numbers, and triages against it. The triage result then goes through the production judge step (`judge_candidates` with `ctx.judge`, request format `current`); a hit is kept when the judge marks it supported, so a candidate with no evidence is dropped without a judge call. `gold` is `{"keep": true}` for a gold hit at the gold sink. A distractor hit on parameterised code carries `"distractor": true` and `{"keep": false}`.

Per unit scores: `tp`, `fp`, `fn`, `tn` and `correct`. The aggregate reports `precision`, `recall` and `f1` over the scored units. An unreachable model endpoint, a judge that does not answer, or a failed temporary repo setup records the unit as `error`; an unparsable answer records it as `not_scored`.

## Evidence validator

Component `evidence`. Each label is one citation: a gold finding's correct evidence (`gold.accept` true) or a distractor with a single fault (`distractor` true, `gold.accept` false, `gold.fault` one of `snippet_not_in_file`, `nonexistent_file`, `lines_out_of_range`, `wrong_snapshot`, and `gold.reason` stating it).

`run_item` resolves the citation with `EvidenceValidator` against the case branches `rw/<case_id>/base` and `rw/<case_id>/pr` in the clone cache (`CLONE_CACHE`, default `benchmark/real_world/.cache`). A missing clone or branch is recorded as an error unit.

The positive class is accept. Gold accepted is `tp`, gold rejected is `fn`, distractor accepted is `fp`, distractor rejected is `tn`. The aggregate reports precision, recall and F1.

## kev-judge

Scores the Kev-4B judge (`src/lgtm/validation/judge.py`) on candidate findings derived from all 12 cases. Labels: `benchmark/component_bench/labels/kev-judge.json`.

- Each label is one candidate: `gold_input` holds the claim, CWE and cited code; `gold` holds `verdict` (`real`, `not_real` or `undetermined`) and, on `real`, `severity` (`low`, `medium`, `high` or `critical`). Where more than one answer is defensible, `gold.acceptable` lists every acceptable `verdict` and `severity`, and `gold.rationale` says why. Criteria: `docs/kev-labeling-criteria.md`.
- Real candidates cite a vulnerable location, including known issues in the case tree. Not-real candidates cite the fixed code of a safe case as a flaw.
- Scores: `verdict_correct` with `real_verdict_correct` and `not_real_verdict_correct`, and `severity_correct` over gold-real candidates only. An answer in the acceptable set is correct. A gold-real candidate judged `not_real` is a severity miss unless `not_real` is acceptable, in which case it has no severity score.
- An `undetermined` candidate is not judged and is counted as not scored.
- An unreachable judge, or a reply without a `real` or `not_real` verdict, is an error.
- Needs the Kev endpoint (`judge_endpoint`); input tokens are taken from the judge reply, output tokens show as not recorded.
