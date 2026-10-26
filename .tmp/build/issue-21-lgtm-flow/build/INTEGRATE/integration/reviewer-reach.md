# Integration intake: reviewer-reach

Slice branch `build/issue-21-lgtm-flow/reviewer-reach`, base 7f642e1, head ebe9dff (result.json: accepted, 2716 passed, 8 skipped). Read-only survey; trial merges via `git merge-tree` only.

## Verdict: ACTION (1 High, 3 Medium, 3 Low)

## Findings

### H1 High - src/lgtm/agents/base.py, src/lgtm/agents/tools.py: origin/main budget early-exit breaks the slice's limit_hit (CT-reviewer-reach-1)
- origin/main (since 7f642e1's lineage split) adds to `run_tool_loop`: once `toolbox.calls_used >= toolbox.budget` it sets `budget_spent = True`, breaks, and asks for the verdict immediately. It also adds `AgentToolbox.graph_stamp`.
- Slice `fill_record` sets `limit_hit = "tool_calls"` only when `len(call_log) > budget` (a refused call was logged by `charge`), and `"steps"` when `toolbox.steps_exhausted`. Slice `run_tool_loop` sets `steps_exhausted = not invalid-cap` on every loop exit that is not a normal answer.
- After a textual conflict resolution, the upstream early exit means no refused call is ever logged, so `tool_calls` is never reported. The same exit falls into the slice's `steps_exhausted = True` path, so a budget stop is recorded as `"steps"`. CT-reviewer-reach-1 (null, "tool_calls", "steps") and benchmark-scope-trace's `run_records` (benchmark/evaluate.py `run_record_fields`, benchmark/README.md) would report the wrong limit.
- Fix at merge: in the resolved loop, treat the `budget_spent` exit as `limit_hit = "tool_calls"` (not `steps_exhausted`), and leave `limit_hit` null at the invalid-input cap. Add a test for each of the three outcomes (the slice has none for the invalid-input cap: result.json outstanding).

## Expected conflicts

Trial merge `git merge-tree origin/main reviewer-reach` (merge-base ae5406c). Text conflicts:

| Path | Branch | Notes |
| -- | -- | -- |
| src/lgtm/agents/base.py | origin/main | run_tool_loop tail (budget_spent) vs slice `_close_run`/`steps_exhausted`; see H1 |
| src/lgtm/config.py | origin/main | slice raises investigator_max_tool_calls 12 to 24, iterations 16 to 32, adds read_file_max_lines; origin/main edits the same block (ollama_base_url, authz_planner, graph_enabled, strip_comments/detect_prompt_injection default True). Keep both |
| src/lgtm/pipeline.py | origin/main | slice's `run_records` (ReviewResult, _SectionStage, investigator record, `authz_agent.run_records`) vs origin/main's `authz_planner == "endpoint"` branch in the section stage, `mitigations_apply`, `graph_enabled`. Keep both; in the endpoint branch the investigator record is absent, so `run_records` holds only section records |
| src/lgtm/cli.py | origin/main | conflict not in the slice's Scope (slice diff does not list cli.py; the conflict arises because of lineage divergence in the stacked history); resolve toward origin/main unless it hides a slice change |
| tests/model_input_lock/expected.json | origin/main | Regenerated artifact; do not merge text |
| tests/test_baselines.py, tests/test_graph_pipeline.py, tests/test_graph_tools.py | origin/main | merge by hand |

Clean auto-merges: src/lgtm/agents/tools.py, src/lgtm/review/coverage.py, README.md, benchmark/evaluate.py, tests/test_cli.py, tests/test_coverage.py, tests/test_investigator.py.

Local `main` (ff110c3) is an ancestor of 7f642e1 (132 commits behind) and has no upstream changes to the slice files. `origin/main` (bad831d) does not contain 7f642e1; 12 commits and the diff above are relative to the merge-base ae5406c.

Other slice branches: all three (pr-scoped-review, benchmark-scope-trace, kev-judge-measurement) are stacked on reviewer-reach and contain its 15 files unchanged. Trial merges of reviewer-reach with each: no conflicts. Overlap beyond reviewer-reach's own files is outside this slice (README.md, benchmark/*, src/lgtm/validation/evidence.py, git_diff.py, report_builder.py, cli.py).

## Contract drift

- CT-reviewer-reach-1: slice code matches. `ReviewResult.run_records: list[RunRecord]`; `RunRecord(section, tool_calls: list[dict{tool,args}], raw_answer, limit_hit)`; investigator record has section "investigator". benchmark-scope-trace consumes it via `asdict(r)` in benchmark/evaluate.py (keys section, tool_calls, raw_answer, limit_hit; matches). Drift risk is semantic only: H1.
- `limit_hit` null at the invalid-input cap is implemented (steps_exhausted False) but untested.
- Run record lost when the LLM raises mid-run in the section reviewer; investigator failure keeps the partially filled record. Consumers must tolerate a missing section entry.

## Scope drift (slice file vs diff)

- Modifies lists files the slice did not change: src/lgtm/review/sections.py, coverage.py, prompt_parts.py, provenance.py, diff/git_diff.py, prompts.toml (changed, listed), and tests test_sections.py, test_coverage.py, test_graph_prompts.py, test_diff.py. Provenance budgets still omit `read_file_max_lines` (src/lgtm/review/provenance.py, result.json outstanding).
- Changed outside Modifies (accepted in result.json): src/lgtm/graph/format.py, tests/test_graph_export.py, tests/test_report.py.
- pr-scoped-review's later edits to authz_reviewer.py, prompts.toml, git_diff.py are sequential (stacked), not a conflict.

## Artifacts to regenerate

- tests/model_input_lock/expected.json: regenerate once after the final merge. The slice changed 116 lines (enclosing block, budgets of 24/32, 600-line cap). origin/main also changes it (budget_exhausted follow-up now ends with the forced-final message), and the origin/main default-on mitigations and `authz_planner` change model inputs. Do not merge text.
- CodeGraph index in the integration checkout after merging.

## Pending-integration checks

- Live-model AC-S1-4 (unit test only proves no crash).
- AC-S1-1, AC-S1-2, AC-S2-4 on real-world cases (DEC-9; INTEGRATE journeys 1 and 2, run once, no tuning).
- Regenerate expected.json (above); then full pytest.
- Re-run the Shoply dev set after reviewer-reach and pr-scoped-review are both merged (prompt interaction).
- Re-run tests covering the origin/main loop change (tests/test_agents.py budget cases) after resolving base.py.

## Outstanding items from result.json to carry (not blocking)

- Medium: enclosing-definitions block has no total size cap; per-definition cut at the line cap is silent (src/lgtm/agents/authz_reviewer.py).
- Medium: `_enclosing_functions` recursion raises RecursionError at about 2000 nesting levels (final-04).
- Medium: `_enclosing_block` uses the toolbox's private `_snapshot_sha`.
- Low: untested enclosing edges (line-cap truncation, dedupe, .py filter, innermost nesting); renamed, non-Python and module-level hunks get no enclosing definition; re-ask keeps only the last attempt's record; the slice worktree's `codegraph sync` failed on a held lock after the last commits (index there may be stale; irrelevant to integration but re-index).

## Other merge needs

- CON-2: no dependency changes in the slice diff (pyproject.toml, requirements.txt untouched).
- origin/main sets `graph_enabled`; with it off, `_enclosing_block` calls `toolbox._snapshot_sha` and the read cap path must still work with `session is None`. Check in the merged tests.
- Not checked: runtime behaviour, test execution, docs/README mentions of the new budgets.
