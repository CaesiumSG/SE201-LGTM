# Build log

## Removed tests


- Decision: How is a real-world sqli case marked out of scope?
  - Answer: A `scope: out` flag per case in benchmark/real_world/cases.json, plus mode lgtm-no-sast; the measured Semgrep count is reported separately as `sql_cases_semgrep_warns_on`
  - Source: build decision inside Scope (developer), plan/stories.md S4
  - Removed tests: none

- Decision: Correct CT-benchmark-scope-trace-1 wording to match delivered code?
  - Answer: Yes; headline metrics defined, absent-scope rule clarified, added keys listed
  - Source: final-reviewer final.md; orchestrator APPROVED
