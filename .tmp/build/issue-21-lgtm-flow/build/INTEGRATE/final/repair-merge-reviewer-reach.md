# Merge repair: reviewer-reach into origin/main (bad831d)

All conflict markers removed from the 8 files. Nothing was run or verified (no shell; `git show` unavailable, so both sides were read from the marker text and surrounding merged code).

## src/lgtm/agents/base.py
- Upstream: `budget_spent` early exit in `run_tool_loop` (forced-final request once `calls_used >= budget`).
- Slice: `_close_run` / `steps_exhausted`; `fill_record` sets `limit_hit`.
- Combined (H1 fix): the tail logs invalid-cap, budget-spent, or iteration-cap; calls `_close_run(toolbox, answer, steps_exhausted=not (invalid_capped or budget_spent), budget_spent=budget_spent)`. `_close_run` also stores `toolbox.budget_spent`. `fill_record` treats `getattr(toolbox, "budget_spent", False)` like the old refused-call-logged case.
- Result: budget stop -> "tool_calls"; iteration cap -> "steps"; invalid-input cap -> null (unless a refused call was also logged beyond budget, unchanged slice behavior); normal answer -> null.
- `budget_spent` is set dynamically on the toolbox (tools.py not in scope; `AgentToolbox.__init__`/`reset_budget` do not declare it).

## src/lgtm/cli.py
- Upstream: `--graph/--no-graph`, `--authz-planner`, tri-state `--strip-comments/--no-strip-comments` and `--detect-prompt-injection/...` (default on).
- Slice side: `--judge-*` options (already in the shared base) and old `is_flag` mitigation options.
- Combined: upstream's four options plus the three judge options, in the decorators and the signature. Old `is_flag` options dropped.

## src/lgtm/config.py
- `__post_init__` validation: kept upstream's `authz_planner` check and the judge_model / judge_timeout checks.

## src/lgtm/pipeline.py
- Triage loop: slice's `if finding is None: continue` plus upstream's `toolbox.graph_stamp("pr")`.
- Stage 3 tail: `meta.agent_errors.extend(section_stage.errors)` plus upstream's `endpoints_reviewed` and session-None-safe `graph_state`/`graph_index_seconds`.
- `_review_sections`: `run_records` list created before the planner branch; endpoint branch has no investigator (no record); investigator branch appends `investigation.run_record`.
- Section loop: slice's error-slice / `SectionResult(supported=...)` / `section_findings.extend(reviewed)` with `graph_stamp`. Upstream's `failed_finding_id` / `_section_result` / `failed_findings` side was dropped: those helpers no longer exist in the merged tree (slice replaced failed pseudo-findings with `authz_agent.errors`), so keeping them would NameError.

## tests/test_graph_tools.py
- `test_rejected_calls_after_saturation_are_answered_without_tools`: upstream's budget early-exit channel assertion (`channels[:5] == bound*5`, no bound after), slice's `not result.verdict` and "Produce your final JSON answer NOW" (current prompts.toml text).

## tests/test_graph_pipeline.py
- Missing-binary triage test: slice's judge-era name and `not triage.verdict` (judge unreachable leaves it unjudged), upstream's `pr_graph_ok is None` (`graph_stamp` returns None without a session). `CAP_MARKER` assertion dropped (undefined in the merged file).

## tests/test_baselines.py
- Kept upstream's `possible_vulnerability` / `insufficient_evidence` rows (FN, TN) in `test_outcome_by_label_and_expectation`; merged `score_case` uses `outcome_for(predicted, ...)`.
- Removed the slice's `test_baseline_only_labels_score_as_before` (expected "UNCREDITED", which `score_case` no longer returns; now duplicated by the rows above).
- Removed upstream's two `test_grounded_only_*` tests and a param list for a body that no longer exists: they call `_f(..., valid=False)`, but the merged `_f(category, verdict)` has no `valid` argument.

## tests/model_input_lock/expected.json
- Took the bad831d (HEAD) side verbatim; the slice's two entries (`push_back_before_first_tool` wording, `text_tool_call_result`) dropped. Regenerate after the final merge.

## Follow-up: upstream failed-finding handling restored (supersedes the pipeline.py note above)
- Cause: the slice removed `failed_finding_id` from src/lgtm/agents/authz_reviewer.py (its `review_section` returns [] and records `errors`); upstream's untouched uses in pipeline.py were left dangling.
- src/lgtm/agents/authz_reviewer.py: restored `failed_finding_id(section_id)`; added `AuthzReviewerAgent.failure_finding(section, message)` (insufficient_evidence, CWE-862, stamped like upstream's `_failure`). `review_section` is unchanged: still returns [] and appends to `errors` (tests/test_agents.py asserts that).
- src/lgtm/pipeline.py: imports `failed_finding_id`; restored `_section_result` (now builds `SectionResult(supported=...)`) and `failed_findings`. In the section loop, when the agent recorded an error for the section, a failure finding built from the error message is appended, stamped with `graph_stamp`, marks the section failed, and is kept out of `dedup_findings` and appended after it (`findings=[*dedup_findings(...), *failed_findings]`). `section_stage.errors` still feeds `meta.agent_errors`, so a failed section appears both as an agent error and as a failure finding.
- Dropped upstream's `verdict == "safe"` skip (slice clears verdicts before judging; the slice never filtered).
- Risk: tests asserting the slice's exact finding list or `agent_errors` for a failed section may now see one extra failure finding; not run.

## Open items
- No tests added for the three `limit_hit` outcomes (out of the 8-file set to author new tests; tests/test_agents.py / test_investigator.py not conflicted). Intake H1 asked for them.
- benchmark/evaluate.py (clean auto-merge) still has dead `outcome_for_label` (UNCREDITED/EXCLUDED) and `EXCLUDED` filters in `metrics`; inconsistent with `score_case`. Needs a decision by the evaluate owner.
- `benchmark/evaluate.py` `grounded_only` kept; tests/test_baselines.py lost its two dedicated grounded tests.
- Check `tests/test_agents.py` budget cases against the early exit (intake pending check).

## Tests restored
Only tests/test_baselines.py changed. `_f(category, verdict, valid=None)` now sets `supported` when `valid` is given (the flag merged grounded scoring reads on baseline-form findings; `_case_row` still recomputes it for judged modes).
- `TestOutcomeTable::test_baseline_only_labels_score_as_before` (slice, UNCREDITED): restored verbatim. FAILS (2 params): `score_case` returns `TN` for safe rows, not `UNCREDITED`. Production gap: merged `score_case` uses `outcome_for`; `outcome_for_label` (UNCREDITED/EXCLUDED) is dead. Same conflict as the slice's `..._is_never_a_true_negative` / EXCLUDED expectations already rewritten to TN in this file; evaluate owner must pick one rule.
- `TestSummaryContract::test_grounded_only_uses_the_grounded_outcome` (upstream): restored, `valid=False` -> `supported=False`, mode `llm-only`. PASSES.
- `TestSummaryContract::test_grounded_only_metrics_use_the_grounded_label` (upstream): restored, unsupported-vulnerable row in `llm-only`. FAILS: `plain/grounded abstentions` expected (1,1), got (0,0). Production gap: `derive_case_labels` sets `grounded_label = label`, so the grounded label no longer downgrades an ungrounded detection to `possible_vulnerability`.
- Run: `.venv/Scripts/python -m pytest tests/test_baselines.py` -> 28 failed, 229 passed. Of these, 3 are the tests above; the other 25 were not caused by this change (judged-mode `_as_judged` rows vs merged `score_case` keying on `verdict`/round-2 rule, e.g. TestOutcomeTable lgtm params, TestCaseLabels predicted, TestNonAuthzCoverageRows, test_metrics_score_every_non_error_row); not triaged.
- Not restored (outside the three): upstream `test_grounded_scoring_discounts_unvalidated_detections`, `test_ungrounded_vulnerable_is_downgraded_to_possible_in_grounded_label`, `test_grounded_label_*valid*` tests; the same grounded-label gap would fail the label ones.
