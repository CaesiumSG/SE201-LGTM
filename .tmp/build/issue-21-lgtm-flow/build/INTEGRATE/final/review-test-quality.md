# Test-quality review: INTEGRATE 84bece6 (Unit, Component, Integration tiers)

Method: test-function name diff across bad831d, ebe9dff and HEAD, then mutations in a throwaway copy (deleted). Scope: tests/test_baselines.py, test_graph_pipeline.py, test_graph_tools.py, test_mitigation_defaults.py, model_input_lock/expected.json.

## test-quality-01 (Medium, coverage / changed expectations) log.md says Removed tests none; tests from both sides vanished unlogged [inspected, reproduced]
Absent at HEAD, existed on one side, not renamed anywhere in tests/:
- main, test_baselines.py (7): test_grounded_downgrade_applies_in_findings_only_modes, test_grounded_label_prefers_a_valid_possible_over_an_invalid_vulnerable, test_grounded_label_stays_detected_with_one_valid_vulnerable_finding, test_grounded_scoring_discounts_unvalidated_detections, test_non_vulnerable_verdict_precedence_in_coverage_modes, test_sqli_grounded_label_downgrades_an_ungrounded_detection, test_ungrounded_vulnerable_is_downgraded_to_possible_in_grounded_label.
- slice, test_baselines.py (3): test_metrics_are_none_when_every_safe_row_is_excluded, test_metrics_denominators_exclude_excluded_safe_rows, test_no_relevant_finding_on_safe_case_is_never_a_true_negative. The UNCREDITED/EXCLUDED decision is logged; these deletions are not.
- main, test_graph_pipeline.py: 9 names; most were rewritten to the slice candidate-without-verdict design (legitimate). No equivalent found for test_safe_findings_never_appear_in_the_report (report-level safe filtering, stats.by_verdict).
- slice, test_graph_pipeline.py: test_coverage_is_in_the_json_metadata_and_endpoint_counts_are_gone became ..._endpoint_count_is_informational and asserts the opposite (meta.endpoints_reviewed present). No decision recorded.
Evidence: swapping the possible and all-insufficient_evidence branches in evaluate.py _verdict_label leaves test_baselines.py at 270 passed (the dropped precedence test catches it). Replacing the grounded downgrade in _relevant_verdicts with if False fails only 1 test; per-label case_label_grounded assertions for authz, sqli and findings-only rows are gone.
Fix: restore the precedence test (possible+insufficient+safe -> possible_vulnerability; insufficient+safe -> explicit_safe) and a findings-only-mode case_label_grounded == possible_vulnerability test; correct the Removed-tests list; record the endpoints_reviewed decision.

## test-quality-02 (Medium, fault detection) is_judged_row verdict-shaped detection untested [reproduced]
Mutating is_judged_row to return True after the pin/mode check: test_baselines.py plus test_evaluate_real.py give 377 passed. No test feeds a row with pin, a judged mode and verdict-only findings; none covers mixed rows. A wrong implementation would rescore legacy rows as all safe.
Fix: unit test is_judged_row: no pin -> False; baseline mode -> False; judged mode with only verdict findings -> False; judged mode with supported and judged findings -> True; empty findings (decision needed, currently True); mixed -> False.

## test-quality-03 (Medium, coverage) budget-stop no-retry in base.py is covered only by three authz-parametrized graph_tools tests [reproduced]
Mutation: drop the stop lambda passed to answer_until_parsed in answer_until_resolved. Exactly 3 failures (text-call budget tests, authz_reviewer param); tests/test_agents.py unaffected; native variants and sast_triage do not detect it. No direct test of answer_until_parsed stop, of the invalid-cap plus budget interplay (budget_spent reset when the cap is hit), or of the three limit_hit outcomes at run_tool_loop level (repair report: intake H1 asked for them, not added; only test_limit_hit_only_when_calls_exceed_budget exists).
Fix: parametrize the text budget-stop tests over sast_triage; add unit tests for answer_until_parsed stop semantics and limit_hit values (budget stop tool_calls, iteration cap steps, invalid cap None).

## test-quality-04 (Medium, fault detection) not result.verdict replaces result.verdict == safe in about 9 test_graph_tools.py assertions and proves nothing [inspected]
AgentFinding.verdict defaults to empty string and agents never set it; the authz stand-in returns verdict=None. The assertion holds for accepted answers, rejected answers and failures, so the former proof that the final answer was accepted after refusals or budget exhaustion is gone. For authz only assert agent.errors (in the fixture, only when no findings) remains, and a valid zero-finding answer also satisfies it.
Fix: assert observables: authz agent.errors == [] for a valid findings payload and a specific message otherwise; sast_triage explanation or raw_response equals the scripted answer rather than the unparsable placeholder.

## test-quality-05 (Low) adapted fixtures [inspected]
- authz run_agent stand-in: sound for tool_calls_used and channel assertions (from the real toolbox and scripted LLM); justified by AC-S2-4 and test_agents.py. Verdict side is vacuous, see 04.
- FORCED_MARK from registry: sound, tracks prompt edits; _loop_stopped_after still pins channels (main contract).
- _f(valid=) sets supported: sound for findings-only modes; _case_row converts to judged form in lgtm modes where valid has no effect; the name is misleading.
- test_mitigation_defaults agent_errors = []: sound (cli.py:155 exits 2 on truthy); truthy path covered in tests/test_cli.py.
- ..._endpoint_count_is_informational computes the expected value with extract_changed_endpoints, which reproduces production logic; use a literal.

## test-quality-06 (Low, coverage) score_case legacy branch judged flag and alarms_outside_target [reproduced]
Dropping judged=judged from the legacy-row predicted_grounded call keeps 377 passed. The non-legacy branch is covered (mutation fails 8+ tests). alarms_outside_target reads f.get("verdict"), always empty for judged rows, with no test; decision needed whether it should use finding_verdict.
Fix: one judged-mode legacy-row test and a judged-row alarms_outside_target case.

## test-quality-07 (Low, reliability) lock regenerated from current output [inspected]
Self-fulfilling by nature; lock-regen.md attributes each diff and reports none unexplained; 5 passed. Duplicate JSON keys from the merge passed silently in the loader.
Fix: reject duplicate keys in the lock loader (object_pairs_hook).

## Decisions needed
- Dead evaluate code: outcome_for_label (UNCREDITED/EXCLUDED) and EXCLUDED filters in metrics remain untested; scan_failure and missing_review safe rows now score TN. Delete or keep the slice accounting.
- Whether endpoints_reviewed stays in meta (slice: gone; pipeline.py:258 keeps it).

## Judged justified
- UNCREDITED to TN and removal of the two judged-mode param rows: main round-2 rule; judged rows never carry those labels; test_baseline_only_labels_score_as_before still exists.
- Failed section: pseudo failure finding replaced by agent_errors (AC-S2-4); HEAD tests assert authz findings == [] and error source equals the section id.
- test_graph_tools renames (..._the_loop_stops_without_backend, _is_never_taken) are main contract, not integration weakening.

## Coverage statement
Tiers Unit, Component, Integration; no tier-boundary violations seen (fakes and tmp git repos). Inspected name diffs across three revisions, test_graph_tools and test_mitigation_defaults diffs, named reports. Mutations (throwaway copy, deleted): stop-hook removal, is_judged_row=True, judged dropped in score_case (both branches), grounded downgrade removal, verdict precedence swap. Not run: full suite (checks-full-suite.md: 2869 passed), live E2E.
