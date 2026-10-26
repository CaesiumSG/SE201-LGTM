# technical-planner report: benchmark-scope-trace

Written: Packages and Checks in slices/benchmark-scope-trace.md. Setup omitted (default covers it; regeneration of labels and patches belongs to the benchmark package).

## AC-S4-7 open question: confirmed with one caveat
- sqli_04_safe, sqli_07_safe, sqli_11_safe are the three Shoply safe SQL cases whose stored sast-only runs (run3-bugfixes at 7f642e1) show n_findings 0 and outcome TN. Their generator entries (benchmark/tools/generate_cases.py) use only `?` placeholders in execute/exec_driver_sql, which no rule in src/lgtm/sast/rules/sql-injection.yaml matches.
- Semgrep can be made to warn by changing the safe case bodies in generate_cases.py (for example a constant-derived fragment joined into the query string, which matches the `"..." + $X` and f-string patterns) and regenerating. No rule change needed, so the Scope holds (src/lgtm/sast is not touched).
- Not verified: the Semgrep binary was not run (planner does not run checks). benchmark/README.md currently claims safe cases "still look SQL-ish enough to trigger SAST"; the docs package should correct that.
- Constraint for the builder: the safe cases must stay safe (still bound or allowlisted), and the other nine safe SQL cases are untouched.

## Open decisions
None.

## Notes
- Docs criteria AC-S4-1 and AC-S4-2 have no test file; tier Unit is nominal and they are proved by review of the statements. If build-ready requires a test per criterion, hand-off to the solution architect: either add a doc-assertion test inside tests/test_benchmark_cases.py (in Scope) or mark them review-only.
- Two packages: docs and benchmark share no files and neither needs the other's code.
- Second check needs the model endpoint and consumes CT-reviewer-reach-1; it is runnable once reviewer-reach is merged as prerequisite, so not marked pending integration. AC-S4-3 and AC-S4-5 real-world parts are INTEGRATE-only (DEC-9) and are proved here with fixtures and stored runs through the unit tests.

## Scope corrections
None.
