# reach: tests-unit repair 1

Tier: Unit. Edited: tests/test_graph_tools.py, tests/test_report.py (2 assertions), tests/model_input_lock/expected.json.

- test_graph_tools.py: `test_read_is_capped_at_200_lines` renamed `test_read_without_a_range_returns_the_whole_file_within_the_configured_cap`; expects 1-300 / 100-300 / 250-300 (big.txt has 300 lines, cap 600). `test_end_before_start_is_treated_as_end_unset` 5-204 -> 5-300. TestReadFileLineCap untouched. Cap-binding coverage remains only in TestReadFileLineCap (test_read_stops_at_the_configured_cap, test_lowering_the_configured_cap_shortens_a_read), both pass.
- test_report.py: investigator_max_tool_calls 12->24, investigator_max_iterations 16->32.
- expected.json: regenerated with the GROUPS producers (json indent=2, ensure_ascii=False; byte-identical format to the old file). Diffs, all explained:
  - agent_inputs investigator/full_legacy, full_control_chars_in_path, manifest_only: "strict budget of 12" -> 24 (budget change).
  - tool_results read_file/legacy_long_file_cap: lines=1-200 -> 1-250, lines 201-250 added (read cap lift; fixture file has 250 lines).
  - No other diff. Enclosing-definitions block appears in no scenario (as check.md noted). Unexplained diffs: none.

## Full run
`.venv/Scripts/python.exe -m pytest tests -q -p no:cacheprovider` -> 2 failed, 2707 passed, 8 skipped (599s). Both remaining failures are PRODUCTION-side (render_read clamp lift); tests assert the old 8000-char ceiling:
1. tests/test_graph_export.py::TestProvenanceFormatting::test_read_and_grep_hard_ceiling[render_read-args0] (outside assigned files; not edited).
2. tests/test_graph_tools.py::TestGitOnlyReads::test_read_output_is_capped_at_8000_characters_with_end_marker: wide.txt read now returns 19984 chars (> 8000), no truncation or marker kept. Not edited: either production still owes an 8000-char ceiling (production bug) or the contract changed and both tests need an explicit decision. Recommend decision from the story: AC-S2-2 says a long function is read whole, which the 8000-char ceiling contradicts at 600 lines, so likely the ceiling for read_file was intentionally lifted and both tests should be retired/updated to the new ceiling.
Previously failing configured-cap test and the test_agents_doc / lock failures now pass.

Skipped: lint/type (none defined). Temp regen test removed from tests/.

## Repair 1b (render_read clamp lift)
- test_graph_export.py::test_read_and_grep_hard_ceiling: render_read case now asserts len(out) <= 9000 (caller's max_chars; body 9001 so it still truncates), header/end marker unchanged; render_grep case still <= 8000.
- test_graph_tools.py: renamed to `test_read_output_is_bounded_by_the_line_cap_character_limit_with_end_marker`; config read_file_max_lines=60 (limit 9600), asserts 8000 < len(out) <= 9600 with START/END READ markers (wide.txt ~19.5k chars, so truncation occurs).
- Full run: `.venv/Scripts/python.exe -m pytest tests -q -p no:cacheprovider -x` -> all passed, 0 failures (1 skipped shown; no -x stop).
