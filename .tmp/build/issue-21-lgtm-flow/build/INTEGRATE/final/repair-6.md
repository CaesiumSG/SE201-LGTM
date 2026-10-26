# repair-6: test-quality-01..04 (Unit tier)

Files: tests/test_baselines.py, tests/test_graph_pipeline.py, tests/test_graph_tools.py, tests/test_agents.py.

## test-quality-01
Restored/adapted in tests/test_baselines.py (judged rows carry `supported`, never possible/insufficient, and have no grounded downgrade, so the grounded and precedence cases run in findings-only modes llm-only/sast-only):
- TestCaseScoring.test_grounded_scoring_discounts_unvalidated_detections: main original, unchanged.
- TestFindingsOnlyLabels.test_non_vulnerable_verdict_precedence (from test_non_vulnerable_verdict_precedence_in_coverage_modes): possible+insufficient+safe -> possible_vulnerability; insufficient+safe -> explicit_safe; all insufficient -> insufficient_evidence. Mutation (possible/all-insufficient labels swapped in _verdict_label): 8+ failures here and in test_label_mapping.
- ...test_ungrounded_vulnerable_is_downgraded_to_possible_in_grounded_label (llm-only, sast-only; vulnerable and safe expectations), test_grounded_label_stays_detected_with_one_valid_vulnerable_finding, test_grounded_label_prefers_a_valid_possible_over_an_invalid_vulnerable (replaces test_grounded_downgrade_applies_in_findings_only_modes coverage), test_sqli_grounded_label_downgrades_an_ungrounded_detection. Mutation (downgrade `if False`): 7 failures.
- test_judged_modes_have_no_grounded_downgrade: new, pins the merged contract.
- TestSummaryContract.test_metrics_denominators_exclude_excluded_safe_rows and test_metrics_are_none_when_every_safe_row_is_excluded: slice originals rewritten with hand-built EXCLUDED rows (EXCLUDED filters in summarize() still exist; scan_failure/missing_review now score TN/FP per the logged UNCREDITED->round-2 decision, so the old scenario inputs no longer produce EXCLUDED).
- test_no_relevant_finding_on_safe_case_is_never_a_true_negative: already rewritten at HEAD as test_no_relevant_finding_on_safe_case_is_a_true_negative (logged decision); nothing added.
tests/test_graph_pipeline.py:
- test_safe_findings_never_appear_in_the_report, ..._failed_section_finding_is_never_merged..., ..._failed_section_surfaces..., findings_reach_the_validator..., vulnerable_*_downgrade*: already present as rewritten candidate-design tests (test_model_emitted_verdicts_never_reach_the_report, test_a_failed_section_is_recorded_as_an_agent_error_and_never_merged..., test_a_failed_section_is_recorded_as_an_agent_error_and_the_rest_still_run, test_findings_reach_the_validator_deduplicated, TestCapIntegration candidates tests). Not restored: stats.by_verdict safe filter (report has no by_verdict key; verdicts are not in the candidate report), evidence_valid/evidence_issues cap exemption (AgentFinding has neither field).
- test_coverage_is_in_the_json_metadata_and_endpoint_count_is_informational: uses repo_with_endpoints and literals (sections_scheduled == 5, meta.endpoints_reviewed == 2) instead of recomputing with extract_changed_endpoints. Decision: slice intent was "endpoint count gone"; merged code keeps meta.endpoints_reviewed (pipeline.py:258, upstream's, per final/repair-merge-reviewer-reach.md). This is not an entry in log.md Decisions; the test follows the merged behavior. Open: remove endpoints_reviewed or record the decision (review-test-quality.md "Decisions needed"). The value is not serialized into the report JSON review block, so the test asserts meta only.

## test-quality-02
tests/test_baselines.py::TestIsJudgedRow: no pin -> False; baseline modes -> False; verdict-only findings on pinned judged-mode row -> False (and scores TP on verdict); supported/judged findings -> True; supported-only or judged-only finding -> True; empty findings -> True (currently-decided behavior, pinned); mixed verdict-only + judged -> False. Mutation (is_judged_row returns True after the pin/mode check): 3 failures.

## test-quality-03
tests/test_agents.py:
- TestAnswerUntilParsedStop (4): stop true after first failed parse -> 1 ask; no stop -> 4 asks; a parse is never discarded by stop; stop true at second check -> 2 asks.
- TestBudgetSpentStopsTheAnswerRetries: authz and sast_triage, real toolbox (max_tool_calls=1), scripted LLM; exactly 2 model calls (bound turn + forced final), no loop re-run.
- TestLimitHitOutcomes: budget stop -> limit_hit "tool_calls" and toolbox.budget_spent; iteration cap -> "steps"; clean answer -> None.
Mutations (copy): stop lambda dropped in answer_until_resolved: 2 failures; `if stop()` -> `if False`: 4 failures; "steps" -> "tool_calls": 1 failure; budget_spent never set: 3 failures.

## test-quality-04
tests/test_graph_tools.py: the 8 `assert not result.verdict` lines (the 9th mentioned does not exist) became `assert result.explanation == "ok"` (the scripted answer's explanation; "x" for test_verdict_json_is_a_final_answer_not_a_tool_call). authz stand-in now carries explanation=None on the [] path (so the assertion fails there), still asserts agent.errors non-empty, and now asserts agent.errors == [] when findings return; tool_calls_used still comes from the toolbox. Mutation (forced-final answer replaced in run_tool_loop): fails with `'forced' == 'ok'`.

## Verification
Mutations ran in a throwaway copy under the scratchpad (PYTHONPATH override); the worktree src was not touched.
Final run (with the parallel base.py/tools.py edits present): `.venv/Scripts/python -m pytest tests/test_baselines.py tests/test_graph_pipeline.py tests/test_graph_tools.py tests/test_agents.py -q` -> 864 passed in 277s.

## Not done
test-quality-05..07 and the invalid-cap limit_hit None / budget_spent reset interplay (not asked). Dead outcome_for_label still untested (decision pending).
