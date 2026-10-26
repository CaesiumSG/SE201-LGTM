# solution-architect: docs criteria back in benchmark-scope-trace

- AC-S4-1 and AC-S4-2 are cited by benchmark-scope-trace again (citation line, Owns names README.md, docs/project-proposal.md per DEC-12, and benchmark/README.md). Removed from INTEGRATE.md (criteria list and the review line) and from architecture.md (slice cut row and INTEGRATE-only list). INTEGRATE keeps only the CON-3 exit-code review line.
- DEC-11 and DEC-12 added to the benchmark-scope-trace citation line. AC-S4-7 stays.
- benchmark/real_world/README.md dropped from Modifies: no cited criterion needs it (AC-S4-2 names benchmark/README.md; AC-S4-3 and AC-S4-5 are code and results).
- Fixed the model_input_lock count in INTEGRATE.md: three slices, not four (story-planner stories-05).

## Hand-off to the technical planner
- benchmark-scope-trace Packages row docs still reads "review in INTEGRATE" and lists benchmark/real_world/README.md; change tier to Unit with a doc-assertion test (in Scope: tests/test_benchmark_cases.py, or another listed test file), and drop real_world/README.md.
- benchmark-scope-trace Checks line: remove the "except the docs statements" wording.
