# reach: package check

Worktree worktrees/reviewer-reach, HEAD 7f642e1, uncommitted changes (11 modified files: 7 src, 4 tests) verified as-is; tree unchanged by checks.
Command: `.venv/Scripts/python.exe -m pytest tests -q -p no:cacheprovider` -> 12 failed, 2697 passed, 8 skipped (617s). Skips not investigated individually.
A second subset run (agents, tools, investigator, pipeline, prompts, sections, coverage, diff, agents_doc, request_format, lock) gave the same set minus test_report: 10 failed, 885 passed, 1 skipped.
No lint/type-check defined; not run.

## Status: FAILED (12 failures)

| Test | Fault | Why |
| -- | -- | -- |
| tests/test_graph_tools.py::TestGitOnlyReads::test_read_is_capped_at_200_lines | test (stale) | Asserts `lines=1-200`; production default `read_file_max_lines` is now 600 (file has 300 lines -> `1-300`). Replaced behavior, test not updated. |
| ...::TestGitOnlyReads::test_end_before_start_is_treated_as_end_unset | test (stale) | Expects `5-204`; now `5-300`. Same cause. |
| TestReadFileLineCap::test_read_stops_at_the_configured_cap | unresolved: production/test mismatch | cap=600, 650-line file: output stops at line 514, expected 600. `render_read(..., MAX_OUTPUT_CHARS=8000)` truncates by chars before the 600-line cap. The new test assumes the line cap is the binding limit; with default 600 and 8000 chars the char limit binds first for lines of ~12 chars. Either production should reconcile the caps (raise MAX_OUTPUT_CHARS) or the test should use a lower cap via config. Production decision needed (AC-S2-2 intent: a function longer than 200 lines read whole; passes for 260 lines). |
| tests/test_agents_doc.py::test_documented_tools_equal_registered_tools_under_each_condition and 4 TestDriftFailsTheCheck tests | test (stale) | Recorder `record(llm, tools, system, user, config)` takes 5 args; production `run_tool_loop` now gets a 6th `record` arg (authz_reviewer.py:271), so review raises "takes 5 positional arguments but 6 were given", logged as "Authz section review failed", loop never recorded. Production change is intended (RunRecord); fix tests/test_agents_doc.py:73 to accept `record=None`. File is outside the package's listed test files. |
| tests/test_report.py::TestSectionConfig::test_default_value[investigator_max_tool_calls-12] and [investigator_max_iterations-16] | test (stale) | Defaults intentionally raised to 24/32 (AC-S2-5); test asserts old values. Update to 24 and 32. Outside the listed test files. |
| tests/model_input_lock/...[agent_inputs] | expected regeneration, but not the enclosing-definitions block | Only investigator/full_legacy, full_control_chars_in_path, manifest_only differ, by one line: "strict budget of 12 tool calls" -> 24. No scenario output contains the enclosing-definitions block, so that prompt change is not exercised by the lock. |
| tests/model_input_lock/...[tool_results] | expected regeneration | read_file/legacy_long_file_cap changed (read cap change); sibling scenarios not fully enumerated (pytest stopped at first). My diagnostic enumeration of this group errored (harness tmp dir pre-existing), so unconfirmed that it is the only changed scenario. |

The lock therefore fails from the budget and read-cap changes, not from the enclosing-definitions block as the assignment expected.

Regeneration command: none exists. No script, flag, or README entry for expected.json (searched repo); it is rewritten manually or by an ad hoc dump of `GROUPS[group](tmp_path)` from tests/model_input_lock/scenarios.py. Not regenerated.

## Package tests
New/changed tests in test_agents.py, test_investigator.py, test_graph_pipeline.py (TestSectionRunRecords) all passed, as did the EnclosingDefinition, DeletionOnlyNonSecurity and default_investigator tests; in test_graph_tools.py TestReadFileLineCap passed except the configured-cap test above. Acceptance coverage: AC-S1-4, AC-S2-1, AC-S2-5, CT-reviewer-reach-1 pass; AC-S2-2 partial (260-line reads pass; configured-cap test fails).

## Not run / gaps
Lint, type checks (none defined); live-model/real-world cases (INTEGRATE). Required verification is NOT complete.

## Cleanup
Throwaway dir removed (nothing was written there); stray temp dirs from the lock diagnostic were removed. No remaining resources.
