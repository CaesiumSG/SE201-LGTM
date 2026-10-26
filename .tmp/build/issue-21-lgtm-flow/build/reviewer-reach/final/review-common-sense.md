# Common-sense review: reviewer-reach (7f642e1..012fe4b)

Counts: High 0, Medium 1, Low 3.

## M1 Medium - src/lgtm/agents/base.py (_close_run, fill_record)
Limit-hit detection goes through a hidden side channel: run_tool_loop writes `toolbox.steps_exhausted` via `_close_run`, and fill_record reads it back with `getattr(..., False)`. The attribute is not declared or reset in AgentToolbox.__init__/reset_budget (tools.py:146-163). The getattr default is dead: fill_record is reached only after run_tool_loop returned, and `_close_run` has already set the attribute (when toolbox is not None; fill_record dereferences toolbox.call_log anyway).
Simplest replacement: declare `self.steps_exhausted = False` in AgentToolbox and reset it in reset_budget; use `toolbox.steps_exhausted` directly in fill_record; fold `_close_run` into a single line at the two exits. Fewer places to keep in sync.

## L1 Low - src/lgtm/agents/authz_reviewer.py (_enclosing_block)
Calls private `toolbox._snapshot_sha` from outside the class, and the `except KeyError` plus `toolbox.shas is None and label == "pr"` branches duplicate what `_snapshot_sha` already decides. Make `_snapshot_sha` public (or return None for an unknown label) and drop the two branches.
Also: enclosing context covers only Python functions; hunks in class bodies or module level get nothing, while the outcome says "enclosing definition". Truncation at read_file_max_lines is silent (no marker). Uncertain whether class/module scope is required (AC-S2-1 text not checked beyond the slice file).

## L2 Low - src/lgtm/agents/tools.py
`READ_CHARS_PER_LINE = 160` with `max(MAX_OUTPUT_CHARS, cap * 160)` is a second knob derived from the first. Acceptable (recorded in the log as the smallest option); no action needed except that render_read's clamp lift in graph/format.py is outside Modifies (approved by orchestrator).

## L3 Low - src/lgtm/agents/investigator.py
`run_record` default_factory builds a throwaway `RunRecord("investigator")` that both return paths override. Make the field required (no default) and drop the `field` import if tests allow.

## Not flagged
RunRecord/fill_record keeping the 5-arg recorder contract is justified by the log. No comments or process leakage found in the added source. Budget raises are config-recorded as required.

Inspected: full src diff, slice file, build log. Not inspected: test diffs in detail, package reports under packages/reach/. Tests were not run.
