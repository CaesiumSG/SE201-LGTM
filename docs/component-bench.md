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

- `<results-dir>/<component>.json`: label counts and one record per unit (`case_id`, `label_id`, `status`, `scores`, `wall_time_s`, `input_tokens`, `output_tokens`, `tools`).
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

