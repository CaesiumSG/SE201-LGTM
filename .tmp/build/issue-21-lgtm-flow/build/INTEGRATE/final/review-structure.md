# Structure review: INTEGRATE (84bece6)

Result: no High findings. Two Medium/Low items, one open decision.

## structure-01 (Medium) budget_spent is an undeclared toolbox attribute that base.py writes and reads through getattr
Paths: src/lgtm/agents/base.py (_close_run L495, fill_record L506, run_tool_loop L330/L604-623), src/lgtm/agents/tools.py (AgentToolbox.__init__ L146, reset_budget L164).
steps_exhausted is declared and reset in AgentToolbox; budget_spent, the sibling loop-outcome flag, is set only from outside (_close_run) and read with getattr(..., False) in two places. reset_budget clears steps_exhausted but not budget_spent, so the two flags have different lifecycles on the same object. The merge repair note confirms tools.py was out of scope and this was deliberate for the merge.
Consequence: a reused toolbox (reset_budget then a path that skips _close_run) reports a stale tool_calls limit_hit; a maintainer cannot find the flag by reading AgentToolbox.
Smallest fix: declare self.budget_spent = False next to steps_exhausted in __init__ and reset_budget; drop the getattr calls. Alternatively return the stop reason from run_tool_loop and drop both flags (larger).
Also: run_tool_loop tail keeps `else: budget_spent = False` on the for loop and a follow-up `if cap...: budget_spent = False`, redundant with the invalid_capped branch order; fold into one stop_reason variable when touching it.

## structure-02 (Low) judged-row detection has two predicates
Paths: benchmark/evaluate.py (is_judged_row L256, JUDGED_MODES L646) versus benchmark/evaluate.py L586, benchmark/real_world/evaluate_real.py L247/L280, benchmark/injection/run_injection_bench.py L112, benchmark/judge_eval.py (mode in JUDGED_MODES).
Writers decide by config mode; readers of stored rows decide by shape (pin present, mode in JUDGED_MODES, no findings that carry verdict without supported/judged). Both live in evaluate.py and the writers all call finding_verdict(f, judged), so ownership is consistent and the heuristic is confined to legacy-row handling. Real-world rows get "pin" (evaluate_real L226/L278), so they classify as judged. No break found; the risk is drift if a new judged mode or row writer omits "pin" (it would silently score on verdict). Keep is_judged_row as the only reader-side predicate; no action required now.

## Checked, intact
- Failure reporting layer: authz_reviewer.review_section returns [] and appends to errors; pipeline._review_sections slices errors per section (seen_errors) and builds SectionResult(status="failed", error=...) via _section_result; errors reach meta.agent_errors (pipeline L257) and the CLI exit code 2 (cli.py). Failure is not a finding, no pseudo-finding helpers remain (failed_finding_id/failure_finding removed, no dangling references found in src). Agent owns detection, pipeline owns result shape. Report builder text points to Agent Errors. Consistent with the log decision (feature contract, AC-S2-4).
- Config/flags: cli.py keeps upstream tri-state --strip-comments/--detect-prompt-injection, --graph, --authz-planner, and adds --judge-endpoint/--judge-model/--judge-timeout with default None falling through to LGTMConfig defaults; config.py validates authz_planner and the judge fields in the one __post_init__. No competing defaults, one owner (LGTMConfig). Old is_flag mitigation options are gone with no remaining consumers seen in cli.py.
- CT-reviewer-reach-1 (limit_hit values "tool_calls"/"steps"/None on RunRecord) is produced by fill_record from the merged loop; the budget-stop path now yields "tool_calls" as required. CT-benchmark-scope-trace-1 (case_scope, scope_fields) is unchanged in evaluate.py. Not verified at runtime.

## Open decision (not a finding)
benchmark/evaluate.py still holds dead outcome_for_label (UNCREDITED/EXCLUDED) and EXCLUDED filters in metrics (repair-1 note); the log records the round-2 rule as chosen. Delete the dead branch or keep it as an explicit legacy path; owner: evaluate.py maintainer.

## Limits
Static read only; no tests run. The merge-resolution diff for b2867af (diff --cc) lists only two clean files, so conflict-file resolutions were judged from the final tree against bad831d. No tmp folder was created.
