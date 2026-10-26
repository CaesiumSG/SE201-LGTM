# Structure review r3: investigator-context (acfb780..6d00729)

Verdict: no High or Medium findings. 2 Low.

## Low
L1. Competing CHARS_PER_TOKEN constants. src/lgtm/agents/base.py:515 defines 3; src/lgtm/rag/indexer.py:33 defines 4; tests/test_tool_loop_context.py:11 defines 4 (the cause of the earlier check.md failure). Same name, different values, no single owner. Consequence: a reader or test author assumes one ratio; the test already drifted once. Smallest fix: have the test import CHARS_PER_TOKEN from lgtm.agents.base; leave indexer as is (chunking is a different concern) or rename base's to signal the conservative estimate (e.g. HISTORY_CHARS_PER_TOKEN).
L2. tests/test_tool_loop_context.py is a new file, while build_llm config tests live in tests/test_agents.py:880 (num_ctx test sits in the new file instead). Minor discoverability only; acceptable as a feature-named file, optionally move test_build_llm_passes_context_size_as_num_ctx next to the sibling build_llm test.

## Checked, fine
- llm_context_tokens sits beside llm_max_output_tokens in LGTMConfig (single owner); build_llm and run_tool_loop both derive from it, no second default.
- Context guard lives in run_tool_loop alongside the other budget exits (budget_spent, invalid_capped); steps_exhausted accounting extended consistently. _message_chars is private and used once, fine.
- No env/CLI wiring exists for sibling llm_* fields, so none expected here. No stray artifacts in the diff (3 files: base.py, config.py, test).

Inspected: full diff, config.py, base.py, repo-wide grep for the constants. Not read: slices/INTEGRATE.md, architecture.md, tests-unit.md (only check.md excerpt via the parent's summary of it was not needed). No throwaway folder created.
