# Unit test review r3: tests/test_tool_loop_context.py (acfb780..6d00729)

Tier: Unit. Result: no High findings; 3 Medium, 2 Low.

Mutation runs on a copy (reproduced); worktree clean, tmp removed.
- CHARS_PER_TOKEN 3->4: 6 pass (survives)
- CHARS_PER_TOKEN 3->6: 1 fail (caught)
- drop the projected-next-round term (used + final_chars > window): 6 pass (survives)
- guard disabled: 2 fail (caught)
- steps_exhausted ignores context_full: 6 pass (survives)
- num_ctx removed: 1 fail (caught)

## Findings
M1 fault detection (reproduced): the projection `used + (used-round_start)` is untested. Mutant without it passes. Production check can overshoot the window by one round; tests only bound requests at context*4 chars (looser than the 3 chars/token window). Fix: assert every request <= (CONTEXT_TOKENS-OUTPUT_TOKENS)*3 (import CHARS_PER_TOKEN from base) and the exact tool-run count (2 at current fixture).
M2 fault detection (reproduced): CHARS_PER_TOKEN=4 mutant passes; the test constant hides the real heuristic. Same fix as M1 (exact counts/bound).
M3 coverage (reproduced): steps_exhausted=False when context_full is unasserted; mutant passes. Check run record / toolbox state (_close_run) after guard trip.
L1 fault detection (inspected): test_every_request_keeps_... `len(requests) > 2` is satisfied by a minimal fixture; fine but tied to fixture sizing (failed in r2 for that reason). Assert == expected count instead.
L2 coverage (inspected): untested edges: guard with a non-str/list message content (str() length), invalid-input cap / budget_spent taking precedence over context_full in log/flags, window <= 0 (context < output tokens) trips immediately after first round, first request itself already over window. Decision needed: desired behaviour when initial prompt exceeds window (currently one round then final).
Also: num_ctx test only checks client attribute; real Ollama honoring unverifiable here. test_ends_with_a_final_request has unused `runs`.

Reliability: deterministic fakes, no I/O, no sleeps. Boundary: Unit-clean. Duplication: none. Changed existing tests: none. Full suite r3 passes (2947) per checks-pytest-r3.md; not rerun.
