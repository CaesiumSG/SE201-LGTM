# Package check: investigator-context (INTEGRATE)

Worktree: C:\JR Cache\se201-lgtm\.tmp\build\issue-21-lgtm-flow\worktrees\INTEGRATE, HEAD acfb780.
Working tree: M src/lgtm/agents/base.py, M src/lgtm/config.py, ?? tests/test_tool_loop_context.py (uncommitted, under verification).
File mtimes unchanged across runs; no edits made. tests-unit.md: not present.

## Results
1. tests/test_tool_loop_context.py: FAILED. 1 failed, 5 passed (run twice: initial and one diagnostic rerun, same result).
   Failing: test_every_request_keeps_the_original_system_and_user_messages, line 96 `assert len(llm.requests) > 2` -> 2.
2. Existing suites touching base.py/config.py (test_agents, test_investigator, test_graph_tools, test_graph_pipeline, test_cli, test_gpu_model): PASSED, 693 passed.
3. Full pytest (.venv python -m pytest -q): 1 failed, 2946 passed, 7 skipped, 1 warning, 713s. Only failure is the new test above. The 7 skips were not itemised.
4. Lint/type-check: NOT RUN. pyproject.toml and README document none; ruff/mypy not installed in .venv.
No live model endpoints contacted (fakes only; build_llm test only constructs the client).

## Failure analysis (test/implementation mismatch)
Test assumes 4 chars/token (its own constant) but base.py uses CHARS_PER_TOKEN=3. Window = (2000-200)*3 = 5400 chars. Each tool round adds ~3000 chars, so the guard `used + (used-round_start) + final_chars > window` trips after round one: requests = 1 bound + 1 forced-final = 2, so `> 2` fails. Log "Agent history nears the context window" confirms the guard fired as designed.
Sibling test test_stops_tool_calls_before_a_request_exceeds_the_context passes.
Proposed fix (parent): lower RESULT_CHARS (e.g. 1000) or raise CONTEXT_TOKENS so 2+ tool rounds fit at 3 chars/token; optionally import CHARS_PER_TOKEN from lgtm.agents.base.

## Coverage gaps
- Real Ollama num_ctx honoring unverified (only `llm.num_ctx == 12345` on the client object).
- 3 chars/token is a heuristic, not validated against a real tokenizer.

## Status
Required verification NOT passing: 1 failing new test. Cleanup: no resources created; I created the report directory only.
