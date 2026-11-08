# Component benchmark

Scores each pipeline component separately over the 12 real-world cases in `benchmark/real_world/cases.json` and the 13 development cases in `benchmark/real_prs/cases.json` (see [Cases](#cases)), against gold labels. Results: [`component-bench-results.md`](component-bench-results.md).

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

- `<results-dir>/<component>.json`: label counts and one record per unit (`case_id`, `label_id`, `status`, `scores`, `wall_time_s`, `input_tokens`, `output_tokens`, `tools` (calls and invalid calls per tool, per agent); units that ran a production toolbox also carry `graph_state`; scored units may also carry `label_ids`, `detail`, and `stages` for `sast-sqli`). A unit whose `graph_state` is not `ok` is recorded as `error`.
- `<results-dir>/summary.json`: per component, mean scores, units scored, errored and not scored, draft and approved label counts, wall time total, token totals, tool calls per agent and tool, `codegraph_calls` and `search_policy_calls`; top-level `commit` and `dirty` (HEAD commit of the executing checkout and whether it has uncommitted changes to tracked files; null when git is unavailable).

Unit status is `scored`, `error` (model, judge or dependency failure; excluded from scores, rerun on resume) or `not_scored` (counted separately). A metric scored `None` is left out of that metric's mean. Tokens the model did not return are stored as null and shown as `not recorded`.

## Cases

The benchmark loads 25 cases: the 12 real-world cases, then the 13 development cases of `benchmark/real_prs/cases.json` (4 SQLi, 9 authz). Each development case has `repo_url` (`https://github.com/<repo>`), `base_ref` (`introducing.base_commit`), `pr_ref` (`introducing.merge_commit`), `category`, `cwe`, `description` (the case `title`) and `split` `real_prs`.

A development case runs against the code at its introducing PR: the clone `benchmark/real_world/.cache/<project>` with local branches `rw/<case id>/base` and `rw/<case id>/pr` at `base_ref` and `pr_ref`. Create them once:

```
python -m benchmark.component_bench.fetch_real_prs
```

The command clones each project into the shared cache (reusing an existing clone), fetches both revisions and sets the two branches. It can be re-run.

Before a component runs on a development case, the runner checks the clone and both branches. A missing clone, a missing branch, or a branch not at the pinned revision records the unit as `error` with a reason naming the missing item and the fetch command; the component is not called.

## Labels

`benchmark/component_bench/labels/<component>.json` holds `component` and `items`; each item has `label_id`, `case_id`, `source`, `review_state` (`draft` or `approved`), `gold_input`, `gold` and optionally `distractor`. Loading rejects an unknown `case_id`, a duplicate `label_id`, a missing field or a case outside the component's applicable set.

## Adding a component

Add `benchmark/component_bench/<name>.py` exposing `run_item(item, ctx)` and `score(item, output)`, and one line in `benchmark/component_bench/registry.py`: `REGISTRY["<name>"] = Entry("<name>", applicable=frozenset({"<case id>", ...}))`. `applicable` is the set of case ids the component's labels may use; omit it to allow every case. `InfraError` and `NotScored` are imported from `benchmark.component_bench.outcomes`.

## authz

Runs the authz reviewer on the gold section of each of the 15 authz cases (the 6 real-world cases aegra, langflow, litellm, vulnerable and safe, and the 9 development authz cases), with the production toolbox over the case clone (graph tools and `search_policy` over the case-repo policy index). Labels: `benchmark/component_bench/labels/authz.json`; `gold_input` holds `section` and `policy_passages`; `gold` holds `vulnerable`, `locations` (`file`, `start`, `end`, inclusive; new-side lines), optional `old_locations` (same shape; base-side lines of removed checks; a finding inside either range is a hit) and `known_issues` (`id`, `file`, `start`, `end`).

Scores per unit: `tp`, `fn`, `fp`, `tn`.

| Case | Finding | Score |
| --- | --- | --- |
| Vulnerable | on a gold location | `tp` 1 |
| Vulnerable | none on a gold location | `fn` 1 |
| Vulnerable | not on a gold location | `fp` 1 each |
| Safe | none | `tn` 1 |
| Safe | inside a known issue | not counted |
| Safe | elsewhere | `fp` 1 each |

The reviewer's tools read the case repository from the clone under `benchmark/real_world/.cache/<project>`. `policy_passages` in `gold_input` are not passed to the reviewer.

## SAST SQLi

`sast-sqli` runs `SASTTriageAgent.triage` on one Semgrep hit per label and scores keep or drop. Semgrep is not run. Labels cover the 10 sqli cases: `gold_input` holds the `SemgrepFinding` fields (`rule_id`, `path`, `start_line`, `end_line`, `message`, `severity`, `matched_code`) plus `excerpt` (`start_line` and the exact source `lines` around the hit, from the upstream file). The run triages against the case clone with the production toolbox (`read_file`, `grep_repo`, `search_policy`; no graph tools). The triage result then goes through the production judge step (`judge_candidates` with `ctx.judge`, request format `current`); a hit is kept when the judge marks it supported and its verdict is not `not_real`, so a candidate with no evidence is dropped without a judge call. Each unit records `stages`: `triage` holds the number of evidence items and the `explanation`; `judge` holds `decision` (`keep`, `drop` or `not_run`) and `explanation`. `gold` is `{"keep": true}` for a gold hit at the gold sink. A distractor hit on parameterised code carries `"distractor": true` and `{"keep": false}`.

Per unit scores: `tp`, `fp`, `fn`, `tn` and `correct` for the keep or drop decision; a hit the judge did not run on counts as dropped. The aggregate reports `precision`, `recall` and `f1` over the scored units. An unreachable model endpoint, a judge that does not answer, or a missing case clone or commit records the unit as `error`; an unparsable answer records it as `not_scored`.

## kev-judge

Scores the Kev-4B judge (`src/lgtm/validation/judge.py`) on candidate findings derived from all 25 cases. Labels: `benchmark/component_bench/labels/kev-judge.json`.

- Each label is one candidate: `gold_input` holds the claim, CWE and cited code; `gold` holds `verdict` (`real`, `not_real` or `undetermined`) and, on `real`, `severity` (`low`, `medium`, `high` or `critical`). Where more than one answer is defensible, `gold.acceptable` lists every acceptable `verdict` and `severity`, and `gold.rationale` says why. Criteria: `docs/kev-labeling-criteria.md`.
- Real candidates cite a vulnerable location, including known issues in the case tree. Not-real candidates cite the fixed code of a safe case as a flaw.
- Scores: `verdict_correct` with `real_verdict_correct` and `not_real_verdict_correct`, and `severity_correct` over gold-real candidates only. An answer in the acceptable set is correct. A gold-real candidate judged `not_real` is a severity miss unless `not_real` is acceptable, in which case it has no severity score.
- Kev is given each cited code item as its enclosing function with decorators, read from the case clone in `benchmark/real_world/.cache`. Without the clone, Kev gets the quoted code. A request over the bound is trimmed to the function up to the last cited line, then to the quoted code.
- Each unit's `detail.kev` holds Kev's raw `supported`, `verdict`, `severity` and `provenance_confidence` answers.
- An `undetermined` candidate is not judged and is counted as not scored.
- An unreachable judge, or a reply without a `real` or `not_real` verdict, is an error.
- Needs the Kev endpoint (`judge_endpoint`); input tokens are taken from the judge reply, output tokens show as not recorded.

## sqli-review

Runs `SQLiReviewerAgent.review_section` on the gold section of each of the 10 sqli cases (the 6 real-world cases and the 4 development cases). Labels: `benchmark/component_bench/labels/sqli-review.json`; `gold_input` holds `section` (as for authz, without policy passages); `gold` holds `vulnerable`, `locations` (the gold sink function: `file`, `start`, `end`, inclusive), optional `old_locations` and `known_issues` (`id`, `file`, `start`, `end`).

A section that `needs_sql_review` rejects is `not_scored` with that reason and the agent does not run. The agent's `kind` on its error records decides the rest: all `unparsable` is `not_scored`; any other error is `error`.

Every Semgrep hit that `labels/sast-sqli.json` lists for the case, kept or dropped, is passed to the reviewer as its related-SAST notes, as the pipeline passes every Semgrep hit in the section's files. The kept hits stand in for SAST triage output: reviewer findings and the kept hits go through `dedup_findings`; a reviewer finding merged with a hit is tagged `sast_also`, any other is `reviewer_only`, and hits that stay alone are not scored.

A finding is a hit when it is in the same file and the same enclosing function as a gold location, as the base-side range of a removed check (`old_locations`), or as a known issue on a safe case, by the same rule as authz (see Tolerant scoring). There is no line tolerance. Repeated findings at the same file and line count once.

| Case | Finding | Score |
| --- | --- | --- |
| Vulnerable | hit on a gold location | `tp` 1, tagged `sast_also` or `reviewer_only` |
| Vulnerable | no hit on a gold location | `fn` 1 |
| Vulnerable | not a hit | `fp` 1 each |
| Safe | none | `tn` 1 |
| Safe | hit on a known issue | not counted |
| Safe | elsewhere | `fp` 1 each |

The aggregate reports `hits`, `false_positives`, `precision`, `recall`, `f1` (null where undefined) and the `sast_also` and `reviewer_only` hit counts over the scored units. The reviewer's tools read the case repository from the clone under `benchmark/real_world/.cache/<project>`.

## Tolerant scoring

- authz: a finding is a hit when it lies in a gold range or in the same file and the same enclosing function as the range. There is no line tolerance. The function is derived from the source (`lgtm.agents.authz_reviewer._enclosing_functions`: innermost function, decorators included), never from the label or a finding field. `locations` and `known_issues` resolve against the PR-side source, `old_locations` against the base-side source, read from the case clone by `read_source(file, side)` with side `pr` or `base`. A file that cannot be read or parsed is scored on the exact range. A finding in another file or another function is `fp`.
- authz, base-side ranges (`old_locations`): a finding is a hit when the name of its line's PR-side enclosing function equals the name of the function enclosing the base range, or when the line falls inside that base function in base-source line numbers and is not inside a differently named function on the PR side. The function names are derived from the source, never from the label or a finding field. Finding lines carry no side, so a line that lands in the base function only by base numbering and sits in no PR-side function still counts; this over-counts.
- sqli-review uses the same hit rule as authz for `locations`, `old_locations` and `known_issues`: same file and same enclosing function, no line tolerance. The base-side over-count note above applies to both components.
- authz and sast-sqli: an unparsable answer is read from the `kind` of the agent's error record. `unparsable` is `not_scored`; `failed` is `error`, whatever the message text. authz records `not_scored` only when every error is `unparsable`.
