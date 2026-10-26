# Common-sense review r3 (acfb780..6d00729)
Inspected the diff in base.py, config.py, tests/test_tool_loop_context.py. tests/test_tool_loop_context.py: 6 passed at 6d00729. No High or Medium findings.

## Low
1. tests/test_tool_loop_context.py:11 CHARS_PER_TOKEN = 4 contradicts src CHARS_PER_TOKEN = 3. The test's bound is looser than production's, which misleads the reader. Replace with `from lgtm.agents.base import CHARS_PER_TOKEN` and use it in `limit`.
2. tests/test_tool_loop_context.py test_context_setting_defaults_to_32768 restates the config default; delete.
3. tests/test_tool_loop_context.py test_ends_with_a_final_request_after_the_guard_trips: `runs` is unused (`dump, runs = _tool()`); use `dump, _`. Same in test_short_conversation... (there `runs` is used, fine).
4. base.py: `_message_chars` is duplicated as the test's `_chars`; import the production helper or accept it. `final_chars` computed each call is fine.

## Not checked
Real Ollama num_ctx behaviour; 3 chars/token is a heuristic with no tokenizer check.
