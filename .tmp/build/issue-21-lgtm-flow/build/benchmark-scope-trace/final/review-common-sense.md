# review: common-sense, slice benchmark-scope-trace
Verdict: CLEAN. Critical 0, High 0, Medium 0, Low 4.

- common-sense-01 (Low) benchmark/README.md "Out-of-scope cases and modes": hand-listed real-world case ids duplicate the `"scope": "out"` flags in benchmark/real_world/cases.json and can drift; drop the id list, keep the rule. The clause "the mode removes the Semgrep signal that SQL injection triage depends on" is rationale prose; delete it.
- common-sense-02 (Low) benchmark/README.md Shoply sentence restates S4; trim to "`sqli_04_safe`, `sqli_07_safe` and `sqli_11_safe` stay in scope." Keep the `sql_cases_semgrep_warns_on` sentence.
- common-sense-03 (Low) benchmark/evaluate.py: `summarize` recomputes `scope_fields` up to three times per row although results already store `scope` and `off_category`; read stored values with fallback for old results. `case_scope` duplicates `scope` on real-world results; setting `scope` from `case.get("scope")` in evaluate_real.py would remove the second key. Optional.
- common-sense-04 (Low) README.md and docs/project-proposal.md scope statement duplicated as DEC-12 requires; no change.

Not flagged: Shoply patch rewrites, generate_cases.py and labels.json updates (AC-S4-7, DEC-11); run_records section (AC-S7-1). No rationale or process comments in code.
Inspected: non-test diff against ebe9dff, slice file, S2/S4/S7, decisions. Tests and package reports not read; no tests run.
