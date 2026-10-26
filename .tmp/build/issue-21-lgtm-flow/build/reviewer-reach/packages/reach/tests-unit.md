# reach: Unit tests

Tier: Unit. Fake models only (DEC-9). Git I/O replaced by patching `lgtm.agents.tools.run_git`; no repo, network, or clock.

## Interfaces the tests assume (production must provide)
- `LGTMConfig.read_file_max_lines: int` (default > 200). `AgentToolbox.read_file_impl` caps one read at this value (replaces module constant `MAX_READ_LINES = 200`).
- `LGTMConfig.investigator_max_tool_calls` > 12 and `investigator_max_iterations` > 16 (existing fields).
- Initial input of `AuthzReviewerAgent.review_section` (system + user messages sent to the model) contains the whole enclosing Python function of each hunk, read through the toolbox git path (`run_git ... cat-file blob <sha>:<path>`): PR snapshot for hunks with additions, base snapshot (old line numbers) for removed-only hunks. Neighbouring functions are not included.
- The enclosing-definition read must go through `lgtm.agents.tools.run_git`. An implementation reading git elsewhere (e.g. `read_file_at_ref`, graph session) fails these tests for the wrong reason; adjust the seam then.

## Tests added
| Criterion | Test | File |
| -- | -- | -- |
| AC-S2-1 | TestEnclosingDefinitionInInitialInput: removed-only hunk (base snapshot), added hunk (PR snapshot), one function per hunk with untouched middle function excluded, hunk outside any function still reviewed, unreadable snapshot file does not stop review | tests/test_agents.py |
| AC-S1-4 | TestDeletionOnlyNonSecurityChange::test_removing_non_security_code_yields_no_finding_and_no_review_error | tests/test_agents.py |
| AC-S2-2 | TestReadFileLineCap: 260-line read with range, without range, stops at configured cap, lowered cap shortens read | tests/test_graph_tools.py |
| AC-S2-5 | test_default_investigator_budgets_and_read_cap_exceed_their_previous_values; test_default_investigator_tool_budget_is_applied_to_the_run | tests/test_investigator.py |

## Run (once)
Command: `.venv/Scripts/python.exe -m pytest tests/test_agents.py tests/test_graph_tools.py tests/test_investigator.py -q -k "EnclosingDefinition or DeletionOnlyNonSecurity or ReadFileLineCap or default_investigator"`
Result: 9 failed, 3 passed, 483 deselected.

### Expected behavioral failures (behavior absent)
- test_removed_only_hunk_brings_the_whole_enclosing_function_from_the_base_snapshot: `'DEL_TOP'` not in model input.
- test_added_hunk_brings_the_whole_enclosing_function_from_the_pr_snapshot: same, absent.
- test_each_hunk_of_a_section_brings_its_own_enclosing_function: same, absent.
- TestReadFileLineCap::test_one_read_returns_a_function_longer_than_the_previous_cap_without_truncation: reads 200 lines, 60 missing (lines 201-260).
- TestReadFileLineCap::test_read_without_a_range_returns_a_whole_file_beyond_the_previous_cap: same cap fault (same failure family, run once).
- TestReadFileLineCap::test_read_stops_at_the_configured_cap and test_lowering_the_configured_cap_shortens_a_read: `LGTMConfig` has no `read_file_max_lines` (AttributeError / TypeError).
- test_default_investigator_budgets_and_read_cap_exceed_their_previous_values: `assert 12 > 12`.
- test_default_investigator_tool_budget_is_applied_to_the_run: `assert 12 > 12`.

### Passing as existing coverage
- test_hunk_outside_any_function_is_still_reviewed and test_unreadable_snapshot_file_does_not_stop_the_review: guard rails that must keep passing once enclosing-definition lookup is added.
- test_removing_non_security_code_yields_no_finding_and_no_review_error (AC-S1-4): passes today; protects against the new input path turning a clean deletion-only section into a finding or a review error.

## Skipped as already covered
- Deletion-only hunks stay in scope, render with correct headers, split with old ranges: tests/test_sections.py::test_deleted_file_uses_old_path_and_deletion_only_hunks_are_in_scope, test_deletion_only_hunk_splits_with_old_ranges_advancing_and_new_side_fixed.
- Deletion-only fallback line uses old_start: tests/test_agents.py::test_deletion_only_section_falls_back_to_old_start and the context-line variant.
- Zero or only-safe findings report no issue: tests/test_agents.py::test_zero_or_only_safe_findings_report_no_issue.
- Investigator budget override and restore: tests/test_investigator.py (reset_budget assertions around line 256) and tests/test_agents.py::test_budget_is_restored_for_each_section_after_an_investigator_override.

## Handed off
- AC-S1-4 end to end (a real model producing no vulnerability finding for a real deletion-only PR), AC-S1-1, AC-S1-2, AC-S2-4: INTEGRATE (DEC-9).
- CT-reviewer-reach-1 run records (tool_calls, raw_answer, limit_hit) and AC-S2-3: not in this package's criteria; no test written. Needs a Connectivity/contract or pipeline-level assignment.
- A section-level test that the read_file cap reaches the model-facing `read_file` tool wrapper is not written; `read_file_impl` is the proving seam.

## Not done
- tests/test_sections.py, test_coverage.py, test_graph_prompts.py, test_graph_pipeline.py, test_diff.py untouched; no unit-provable behavior for these criteria beyond the existing coverage above.
- tests/model_input_lock/expected.json untouched; adding enclosing context will change the locked model input (regenerated later).
- No lint, type checks, or other suites run.

## Unresolved
- Config field name `read_file_max_lines` is my choice (plan leaves the name to the build); rename in tests if production picks another.
- The "previous value" constants in test_investigator.py (12, 16, 200) are the 7f642e1 values from AC-S2-5.

## Follow-up: CT-reviewer-reach-1 (section run records)

Tests: tests/test_graph_pipeline.py::TestSectionRunRecords (6 tests), fake model only (`_RoutedLLM`), `lgtm-no-sast` mode through `ReviewPipeline.run`. They use the file's existing `repo` fixture (a tiny local git repo) and `install_graph`; no network, no live model.

Assumed interface:
- `ReviewResult.run_records: list[record]`, one record for the investigator run (`section == "investigator"`) and one per section review (`section` == section id, e.g. `fallback:a.py`).
- Record type is free (dataclass or dict; tests read via attribute or key) with `section: str`, `tool_calls: list[{"tool": str, "args": dict}]`, `raw_answer: str` (final model answer text), `limit_hit: None | "tool_calls" | "steps"`.
- `tool_calls` entries for `read_file` carry `args["path"]`.
- "tool_calls" = tool budget (`max_tool_calls` / `investigator_max_tool_calls`) exhausted; "steps" = iteration cap (`max_agent_iterations` / `investigator_max_iterations`) reached and the answer forced.

Cases: one record per investigator and section; fields and no limit when none hit; investigator tool budget -> "tool_calls"; investigator step budget -> "steps"; section tool budget -> "tool_calls" on exactly one section, none elsewhere; section step budget -> "steps" on exactly one section.

Run (once): `.venv/Scripts/python.exe -m pytest tests/test_graph_pipeline.py -q -k TestSectionRunRecords`
Result: 6 failed, 98 deselected. All 6: `AttributeError: 'ReviewResult' object has no attribute 'run_records'` (raised after the pipeline run completed, so the fixtures work). Behavior absent, as expected.

Not covered: persistence of records to the JSON/Markdown report and the benchmark per-case result (AC-S2-3, benchmark-scope-trace). The attribute name `run_records` is my choice; rename in tests if production picks another.
