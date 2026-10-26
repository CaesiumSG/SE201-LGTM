# Workspace

- Worktree: C:/JR Cache/se201-lgtm/.tmp/build/issue-21-lgtm-flow/worktrees/kev-judge-measurement
- Branch: build/issue-21-lgtm-flow/kev-judge-measurement
- Slice base: efc85996e400c09c124cfa9366f58da9b3298214 (head of build/issue-21-lgtm-flow/benchmark-scope-trace)

## Setup
- git worktree add -b build/issue-21-lgtm-flow/kev-judge-measurement <wt> build/issue-21-lgtm-flow/benchmark-scope-trace: ok
- python -m venv .venv && . .venv/Scripts/activate && pip install -e ".[dev]" semgrep: ok (lgtm 0.1.0 editable, pytest 9.1.1, semgrep 1.182.1)
- codegraph init: ok (4,823 nodes, 14,982 edges)
- Slice Setup section: none

## Baseline
Command: pytest tests/test_judge_eval.py tests/test_judge.py tests/test_cli.py tests/test_report.py tests/test_e2e_judged_bench.py tests/test_e2e_review_judge.py tests/test_kev_support_bench.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py tests/test_graph_benchmarks.py tests/model_input_lock
Result: 763 passed, 0 failed, 1 warning (102s). Failing test IDs: none.
