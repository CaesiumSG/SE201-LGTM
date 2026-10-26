# Lock regeneration: tests/model_input_lock/expected.json (follow_ups)

Computed with GROUPS["follow_ups"](tmp) (the test's code path); wrote only the follow_ups group.
Result: `pytest tests/model_input_lock -q` -> 5 passed.

## Changes, all attributed
- push_back_before_first_tool: "Before giving a verdict ... judging" -> "Before answering ... reviewing". b76795e (agent candidates without verdict or confidence; prompts.toml shared.verify_with_tools). The pr-scoped-review side's lock already held this wording; the merged file held the older text.
- budget_exhausted: forced_final HumanMessage now appended after the budget-spent break. 4597a3c (main; run_tool_loop budget_spent) reached via the bad831d side of merge b2867af; the other parent's lock predates it.
- text_tool_call_result: key re-added with unchanged-from-base-side value. Merge b2867af dropped it from follow_ups; present in both merge parents' locks, value equals current output.

## Not attributable to a prompt change (file repair)
expected.json follow_ups contained duplicate keys from merge b2867af (authz_reviewer_reask, budget_exhausted, forced_final_at_invalid_input_cap, forced_final_at_iteration_cap, no_tools_given_unknown_tool, plain_reviewer_reask, reask_after_non_json_answer; JSON loader keeps the last). Rewriting follow_ups removed the duplicates; every deduplicated value equals current output. authz_reviewer_reask already matched (the 7bf523a/f036cc5 "cites a changed or removed line" rule is in the recorded value).

Unexplained differences: none. Other groups untouched (diff hunks confined to follow_ups). Existing key order kept, text_tool_call_result appended last in follow_ups; CRLF working-copy endings kept (index is LF via autocrlf).
Throwaway folder tmp/lock removed.
