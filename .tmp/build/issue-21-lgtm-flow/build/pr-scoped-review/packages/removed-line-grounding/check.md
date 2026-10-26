# removed-line-grounding: check (AC-S3-4, Unit)

Worktree pr-scoped-review, HEAD ebe9dff (uncommitted): modified git_diff.py, evidence.py, test_diff.py, test_graph_evidence.py, test_validation.py (plus other package's prompts.toml / test_graph_prompts.py, ignored). Files unchanged during run.

## Run (once)
`.venv/Scripts/python.exe -m pytest <18 files> -q -p no:cacheprovider -rs`
Files: test_validation, test_graph_evidence, test_diff (package) + callers of evidence.py/git_diff.py: test_agents, test_baselines, test_coverage, test_e2e_benchmark_replay, test_graph_pipeline, test_graph_tools, test_investigator, test_judge, test_judge_eval, test_kev_confidence, test_pipeline_request_format, test_report, test_sanitizer, test_sections, test_semgrep.
Result: exit 0, 1571 passed, 2 skipped, 0 failed (353s).
Skips: test_coverage.py:510 ('*' invalid in Windows filenames), test_semgrep.py:227 (semgrep not installed). Both unrelated to this change.

## Status
- Package new/changed tests (AC-S3-4): Passed. Previously 11 failing tests now pass; no per-test breakdown captured beyond the combined run.
- Existing suites covering evidence.py / git_diff.py: Passed.
- Lint / type-check: Not run (pyproject configures neither ruff nor mypy; workspace.md agrees).
- Not run by instruction: tests/test_graph_prompts.py, model input lock test.
- Gap: callers found by grep of tests for imports/names, not full CodeGraph caller trace; model_input_lock/scenarios.py excluded.
- Tier note: grounding tests go through public validate with real temp git/diff inputs per the test files; not inspected for tier violations in depth.

Cleanup: no throwaway files created.
Verification complete for assigned scope.
