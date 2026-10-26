# Replan intake 1: kev-judge-measurement and INTEGRATE

Run: issue-21-lgtm-flow. Source of the items: accepted slice benchmark-scope-trace (commit efc8599, branch build/issue-21-lgtm-flow/benchmark-scope-trace, base ebe9dff). The same two items appear in `build/benchmark-scope-trace/result.json`, `build/benchmark-scope-trace/closed-note.md` and the Linear comment 54154404-3521-42d6-89ac-7a9f24514099 on LGT-168 (`plan/reports/linear-build-results.md`). The wording is identical in all three, so Linear and the local copy do not differ.

Build state of the target slices: `build/kev-judge-measurement/result.json` and `build/INTEGRATE/result.json` do not exist. LGT-169 and LGT-170 have no comments.

Blockers recorded for kev-judge-measurement or INTEGRATE: none. `blockers` in benchmark-scope-trace `result.json` is `[]`; Linear records no blockers on LGT-165, LGT-169 or LGT-170.

Existing replan files before this one: none.

## R-1

* Item (verbatim): "Regenerated Shoply safe patches shift lines cited by run6-final candidates"
* change (verbatim): "Re-anchor or regenerate the candidate citations for sqli_04_safe, sqli_07_safe, sqli_11_safe"
* slices (verbatim): ["kev-judge-measurement"]
* Source: `build/benchmark-scope-trace/result.json` needs_replan[0]; `build/benchmark-scope-trace/closed-note.md`; Linear LGT-168 comment 54154404-3521-42d6-89ac-7a9f24514099 item 1 (recorded under LGT-169 by source).
* Plan entries cited or touched:
  * `slices/kev-judge-measurement.md` Scope, Consumes: "the Shoply candidates in the stored lgtm run under benchmark/runs/run6-final/lgtm/"; Resources: "stored run benchmark/runs/run6-final/lgtm/ (read only)".
  * Same Scope, Owns and package judge-measurement: AC-S6-1, AC-S6-2, AC-S6-3, AC-S6-5 (labels over Shoply candidates) and AC-S5-1 to AC-S5-4.
  * `slices/benchmark-scope-trace.md` Scope, Regenerated: "benchmark/labels.json and the Shoply patches under benchmark/cases/sqli/"; AC-S4-7 (Shoply safe SQL cases trigger Semgrep).
  * DEC-8 (labels from a model against stored candidates). `slices/INTEGRATE.md` risk: "kev-judge-measurement labels the stored run benchmark/runs/run6-final/lgtm/, which predates the reviewer changes".
* Code facts (efc8599 against ebe9dff):
  * Changed files: `benchmark/cases/sqli/case_04_safe.patch`, `benchmark/cases/sqli/case_07_safe.patch`, `benchmark/cases/sqli/case_11_safe.patch`, `benchmark/labels.json`.
  * `case_04_safe.patch` and `case_11_safe.patch` each gain a line `table = "<name>"`, and the SQL becomes `"DELETE FROM %s ..." % table`. The case_04 hunk header changes from `+43,16` to `+43,17`; case_07 changes by the same diffstat (7 lines).
  * Stored candidates under `benchmark/runs/run6-final/lgtm/` are unchanged by the slice. Their citations: `sqli_04_safe.json` finding at `app/routes/admin.py` line 46, code evidence lines [47, 53], content quotes `cursor.execute("DELETE FROM audit_log WHERE user_id = ?", (user_id,))`; `sqli_07_safe.json` finding at `app/routes/orders.py` line 57, evidence [54, 60]; `sqli_11_safe.json` finding at `app/routes/admin.py` line 46, evidence [43, 52]. The cited content is the pre-regeneration text, so quoted lines and line numbers no longer match the regenerated patches.
  * `benchmark/runs/run6-final/lgtm/*`, `benchmark/cases/sqli/*` and `benchmark/labels.json` are not in kev-judge-measurement's Modifies or Creates. run6-final appears only under Consumes and Resources as read only. Re-anchoring or regenerating citations would write files outside that Scope. INTEGRATE has whole-feature fix authority under build-rules but names none of these files.
  * Readers of the citations in kev-judge-measurement Modifies: `benchmark/citation_export.py`, `benchmark/judge_eval.py`, `benchmark/kev_support/fixtures.py`.
* Change class if resolved: Scope contract between slices (and a Resource strategy). Either option edits a stored run that the Scope lists as "read only", or adds a generated artifact outside Modifies/Creates. No outcome, acceptance criterion, constraint or CT-benchmark-scope-trace-1 key changes. If the plan only adds a file path inside kev-judge-measurement's existing Scope it would be minor; run6-final is not inside that Scope today.
* Accepted slice it could invalidate: benchmark-scope-trace, if the regenerated patches or `benchmark/labels.json` (its Regenerated entries) change again. None identified for reviewer-reach or pr-scoped-review.

## R-2

* Item (verbatim): "Older tracked real-world runs re-summarized or resumed count alerta_sqli_vulnerable, alerta_sqli_safe, postgraas_sqli_safe as in scope"
* change (verbatim): "Apply cases.json scope on rescore/summarize-only, or produce fresh real-world runs"
* slices (verbatim): ["INTEGRATE"]
* Source: `build/benchmark-scope-trace/result.json` needs_replan[1] (also pending_integration "Real-world stored-run measurement (DEC-9)"); `build/benchmark-scope-trace/closed-note.md`; Linear LGT-168 comment 54154404-3521-42d6-89ac-7a9f24514099 item 2, example `gpu-qwen3.8-27b/real_world/lgtm` (recorded under LGT-170 by source).
* Plan entries cited or touched:
  * AC-S4-3: "`alerta_sqli` (pair) and `postgraas_sqli_safe` are reported with scope "out" and are not counted in the headline metrics." Real-world part proved by INTEGRATE only.
  * AC-S4-5: "The real-world summary reports how many SQL injection cases Semgrep warns on." Real-world part proved by INTEGRATE only.
  * CT-benchmark-scope-trace-1: "A result written before this slice has no scope key and reads as "in", even where AC-S4-3 would now score it "out"."
  * DEC-9 (real-world cases held out; "a failure is reported, not tuned"). `slices/INTEGRATE.md` journey 2: `python benchmark/real_world/fetch.py --policies`, then `python benchmark/real_world/evaluate_real.py --modes sast-only lgtm` plus the policy mode, run once; risk: "Run the real-world set once, after the final Shoply-based change".
  * `slices/benchmark-scope-trace.md` Scope, Modifies: `benchmark/real_world/evaluate_real.py`, `benchmark/real_world/cases.json`; Resources: "real-world fetch and runs (defer), per DEC-9".
  * AC-S6-1 and AC-S6-2 real-world parts (INTEGRATE journey 4 labels candidates from journey 2).
* Code facts (efc8599):
  * `benchmark/real_world/cases.json` has `"scope": "out"` on `postgraas_sqli_safe`, `alerta_sqli_vulnerable` and `alerta_sqli_safe` only. `postgraas_sqli_vulnerable` and `pyload_sqli_*` carry no scope key.
  * `benchmark/real_world/evaluate_real.py` writes `case_scope: case.get("scope", "in")` into a per-case result when the case runs (lines 225 and 251). `--summarize-only` ("rebuild summary.json files from existing results") and `--resume` (skips units where `evaluate.is_done(path)`) reuse stored result files and do not re-read cases.json scope.
  * `benchmark/evaluate.py` `scope_fields(result)` takes scope from mode `lgtm-no-sast` or a stored `case_scope == "out"`; the headline filter is `r.get("scope", "in") == "in"`. Stored results `benchmark/runs/gpu-qwen3.8-27b/real_world/lgtm/alerta_sqli_vulnerable.json`, `alerta_sqli_safe.json` and `postgraas_sqli_safe.json` have no `scope` or `case_scope` key, so they read "in". `benchmark/runs/real_world/lgtm/` holds the same three case files and the same condition applies.
  * `rescore` in `benchmark/evaluate.py` (line 958) is the Shoply-side path; the outstanding item "The --rescore test does not cover an old no-sast sqli row" is related and unresolved.
  * `benchmark/real_world/evaluate_real.py` and `benchmark/real_world/cases.json` are in benchmark-scope-trace's Modifies; `benchmark/evaluate.py` is also in kev-judge-measurement's Modifies. INTEGRATE has no Scope table; build-rules give it authority to fix defects in any slice's code.
* Change class if resolved: fresh real-world runs match INTEGRATE journey 2 and need no plan change (minor). A code fix applying cases.json scope on summarize-only/resume is a defect fix INTEGRATE may make without changing an outcome, criterion or constraint (AC-S4-3 already states the required result), but it would contradict the CT-benchmark-scope-trace-1 sentence that a result with no scope reads "in" for stored results, so the contract wording would change (cross-slice contract). Which option the build picks is not stated in the item.
* Accepted slice it could invalidate: benchmark-scope-trace, if `evaluate_real.py`/`evaluate.py` or CT-benchmark-scope-trace-1's absent-scope rule change. kev-judge-measurement (not yet built) Consumes CT-benchmark-scope-trace-1 and would see any contract change.

## Related outstanding items of benchmark-scope-trace (not needs_replan; context only)

* "Error rows and real-world error rows have no test asserting `scope`."
* "The --rescore test does not cover an old no-sast sqli row."
* "Non-headline rates include out-of-scope rows."
* "`case_scope` duplicates `scope`."
* "benchmark/README.md duplicates the case id list from cases.json and has one rationale clause." (`benchmark/README.md` is in kev-judge-measurement Appends.)
