# repair-3: run_agent authz branch (tests/test_graph_tools.py)

Tier: Unit. Only tests/test_graph_tools.py changed.

## Changed expectation
`run_agent` authz branch now keeps the agent instance. If `review_section` returns findings it takes `findings[0]`. Otherwise it asserts `agent.errors` is non-empty (failure reported, AC-S2-4) and returns `SimpleNamespace(tool_calls_used=toolbox.calls_used, verdict=None)`.

Reason: merged authz reviewer records unparsable/budget-spent failure in `agent.errors` and returns `[]` (tests/test_agents.py:1032-1035); upstream took `[0]` of a stamped failure finding. The `tool_calls_used == 5` and "loop stops without backend" assertions are untouched.

## Run
`<wt>/.venv/Scripts/python -m pytest tests/test_graph_tools.py tests/test_agents.py tests/test_integration_flags.py tests/test_baselines.py -q`
Result: 715 passed in 189.05s. The three target tests pass; test_integration_flags also passed in this run.

## Not checked
No lint/type tools installed. Full suite not rerun; model_input_lock failure from checks-merge-reviewer-reach.md not touched.
