# repair-2: fill_record tool_calls boundary (Unit)
File: tests/test_agents.py, class TestFillRecordToolCallBudget (parametrized, 3 cases, budget=3).
- 2 calls -> None; 3 calls (exactly budget) -> None; 4 calls (one over) -> "tool_calls". The 3-call case kills the `>` -> `>=` mutant.
- Toolbox is a SimpleNamespace with steps_exhausted=False (current base.py reads it directly, so it must be set).
- Command: `.venv/Scripts/python.exe -m pytest tests/test_agents.py -k FillRecordToolCallBudget -q` -> 3 passed. Nothing else run.
- Not run: mutation re-check. Production untouched.
