# Structure review: benchmark-scope-trace

Verdict: no High or Medium findings. 2 Low.

## Findings

### L1 (Low) Case-data flag is named `scope` in cases.json and `case_scope` in results
Paths: benchmark/real_world/cases.json, benchmark/real_world/evaluate_real.py (lines ~225, ~251), benchmark/evaluate.py `scope_fields`.
The same concept has two spellings. The case flag `scope: out` is copied into each result as `case_scope` because the computed headline `scope` ("in"/"out", CT-benchmark-scope-trace-1) would collide. The mapping is split across two `case.get("scope","in")` copies in error_result and run_unit instead of a CASE_FIELDS entry, so a third result path would silently miss it. Smallest fix: keep the names, but write the copy once (a helper in evaluate_real.py), or document `case_scope` next to the cases.json schema. Not a contract problem; the contract keys `scope` and `off_category` are as specified.

### L2 (Low) Scope rule ownership is correct, but older real-world results cannot be re-scoped
Paths: benchmark/evaluate.py `scope_fields`, `score_case`, `rescore`.
Ownership is sound: evaluate.py owns `scope_fields` (single definition), and evaluate_real.py only supplies the per-case input (`case_scope`) and calls `evaluate.score_case`/summarize. No duplicate logic. Consequence: `--rescore` derives scope from the stored `case_scope`/`mode`; a saved real-world result written before this slice has no `case_scope`, so the three alerta/postgraas rows rescore as "in". That matches the contract ("no scope key reads as in") but means rescored old real-world runs still include out-of-scope rows. Open decision: accept, or have rescore look up cases.json scope by id.

## Checked, no problem
- Contract shape: every result gets `scope` and `off_category` via `score_case` and `mark_error`; summary keeps base keys and adds `out_of_scope_cases`, `off_category`; headline blocks (overall, per_category, per_split, grounded_only) use the `headline` subset. `sql_cases_semgrep_warns_on` lives in write_dir_summary. Missing `scope` defaults to "in" in summarize.
- The old inline off-category predicate in summarize was replaced by `scope_fields(r)["off_category"]`, so one definition remains.
- Dependencies: evaluate_real.py -> evaluate.py only (existing direction); no new imports across features; `asdict` is stdlib.
- Docs: benchmark/README.md Scope and Run records sections sit next to the metrics description; README.md and docs/project-proposal.md carry the same statement (DEC-12).
- generate_cases.py is the source of labels.json and the Shoply patches; regenerated outputs are in the diff.
- No stray artifacts in the diff.

## Inspected / limits
Full diff of benchmark/, README, docs; slice file and decisions. Tests and package reports not read in depth; pytest not run. real_world/README (if any) not found to mention scope.
