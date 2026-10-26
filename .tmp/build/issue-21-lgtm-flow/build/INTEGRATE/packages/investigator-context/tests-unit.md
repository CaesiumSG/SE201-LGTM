# investigator-context: unit tests

Tier: Unit. File: tests/test_tool_loop_context.py (new, in worktrees/INTEGRATE).

Setting: `LGTMConfig.llm_context_tokens` (default 32768).

Fixture: context 1400 tokens, output 200, 1500-char tool results, 30 scripted calls. At 3 chars/token two tool rounds fit and a third does not; the 4 chars/token bound in the assertions is looser.

Covered:
- default 32768; build_llm passes it as ChatOllama num_ctx.
- guard stops tool calls before any request exceeds context: fewer than 30 tool runs, every request < context*4 chars, final answer returned.
- every request, including the final one, starts with the original system and user messages (asserts at least 3 requests, i.e. two tool rounds).
- a final unbound request follows once the guard trips.
- short conversation unchanged: 2 tool runs, 3 requests.

Command: `.venv/Scripts/pytest.exe tests/test_tool_loop_context.py -q` (worktree venv)
Result: 6 passed (against the current implementation in the worktree).
Earlier red run (no implementation): 5 failed, 1 passed, on the missing field and `assert 30 < 30`.

Changed after the first version: CONTEXT_TOKENS 2000 -> 1400, RESULT_CHARS 3000 -> 1500; no assertion changed.
