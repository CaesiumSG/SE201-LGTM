# Repair 1 r3: tests/test_tool_loop_context.py (Unit)

Changes (test file only; src unchanged, nothing committed):
- M1/M2: CHARS_PER_TOKEN imported from lgtm.agents.base (structure L1, common-sense L1). Request bound is (CONTEXT-OUTPUT)*CHARS_PER_TOKEN with <=; tool runs asserted == TOOL_ROUNDS_THAT_FIT (2); requests == 3; bound_requests == 2 (replaces `len(requests) > 2`, tests L1).
- M3: new test_context_full_stop_is_not_reported_as_steps_exhausted; tools carry a SimpleNamespace toolbox via metadata, asserts steps_exhausted is False.
- Unused `runs` removed in the final-request test.
- Deleted test_context_setting_defaults_to_32768 (structure finding 6-2 in review-structure-r3; restated config default).

Mutants (applied to src, reverted with git checkout; baseline 6 passed):
- projected term removed: 3 failed (runs == 2 / requests count)
- CHARS_PER_TOKEN 3->4: 3 failed
- steps_exhausted ignores context_full: 1 failed (the new test)
Worktree: only the test file modified. Command: .venv/Scripts/pytest.exe tests/test_tool_loop_context.py -q

Not done: tests-L2 edges (non-str content, precedence, window<=0), needs a behaviour decision; num_ctx test left in place (structure L2 optional).
