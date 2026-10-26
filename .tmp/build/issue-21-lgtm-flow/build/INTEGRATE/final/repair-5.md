# repair-5

Nothing was run or verified.

## structure-01, common-sense-02
- src/lgtm/agents/tools.py: `self.budget_spent = False` declared in `AgentToolbox.__init__` and reset in `reset_budget`, beside `steps_exhausted`.
- src/lgtm/agents/base.py ~330: `getattr(toolbox, "budget_spent", False)` replaced with `toolbox.budget_spent`. The same function already reads `toolbox.repo`, `toolbox.config` and `toolbox.shas`, so `toolbox` is never None there.
- src/lgtm/agents/base.py `fill_record` (~506): getattr kept. tests/test_agents.py `TestFillRecordToolCallBudget` (~1307) passes a `SimpleNamespace` with no `budget_spent`, so a direct read raises AttributeError. Tests were not edited. Smallest follow-up: add `budget_spent=False` to that namespace, then change the read to `toolbox.budget_spent`.

## structure-01 (tail), common-sense-03
- src/lgtm/agents/base.py `run_tool_loop`: `budget_spent = False` set once before the loop. The `for ... else:` assignment and the post-loop `if cap...: budget_spent = False` are removed. Behavior is unchanged: the invalid-input cap `break` precedes the budget `break`, so `budget_spent` is never True when the cap is hit.
- Not done: folding the flags into one stop_reason variable (optional in the review).

## Skipped
No tests or checks run. The `_close_run` `toolbox is None` handling is untouched.
