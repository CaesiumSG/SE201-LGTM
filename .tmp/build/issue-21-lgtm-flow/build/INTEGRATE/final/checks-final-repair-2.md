# checks-final-repair-2

Target: worktrees/INTEGRATE at bf63915, uncommitted. `git status --porcelain` (before and after):
 M README.md
 M benchmark/real_world/README.md
 M src/lgtm/cli.py
 M src/lgtm/validation/evidence.py
 M tests/test_cli.py
?? tests/test_removed_line_citation.py
(benchmark/citation_export.py is unmodified.)

Command: `.venv/Scripts/python -m pytest <test_removed_line_citation, test_judge_eval, test_cli, test_e2e_benchmark_replay, test_graph_evidence, test_graph_pipeline, test_judge, test_kev_confidence, test_pipeline_request_format, test_validation> -q -rA`
Files are every tests/*.py referencing validation.evidence, read_cited_code or citation_export (grep). Result: 2 failed, 717 passed, 0 skipped (137s). Tests in these files that touch semgrep/model-down logged ERROR lines are expected logs, not failures.

Failures (both Failed):
- tests/test_removed_line_citation.py::TestCitationExportRemovedLines::test_unlabelled_removed_line_citation_exports_removed_code[pr-lines-exist]
- same [pr-lines-past-end]
Error: AssertionError: assert [] == ['    if thre... Forbidden()'] (unit["code"] is empty; expected the removed base lines).
Cause: the test expects citation_export.export_run to fall back to base for a null snapshot; the follow-up revert of benchmark/citation_export.py removed that behavior (null snapshot reads PR head only), as tests/test_judge_eval.py:1567-1586 require. Test/product conflict: the new export test contradicts the reverted product code and the judge_eval test. Proposed fix: delete these 2 parametrized cases (and the export tests that no longer apply) or change them to assert the unreadable/PR-head behavior. test_judge_eval.py null-snapshot tests pass now.

Per-test, tests/test_removed_line_citation.py (production function; status):
read_cited_code (evidence.EvidenceValidator.read_cited_code):
- test_unlabelled_removed_line_citation_returns_removed_code[pr-lines-exist]: PASSED
- ...[pr-lines-past-end]: PASSED
- test_unlabelled_added_line_citation_returns_pr_code: PASSED
- test_unlabelled_context_line_citation_returns_the_line: PASSED
- test_unlabelled_citation_matching_neither_snapshot_keeps_pr_read: PASSED
- test_labelled_citations_read_their_own_snapshot: PASSED
citation_export (benchmark/citation_export.export_run):
- test_unlabelled_removed_line_citation_exports_removed_code[pr-lines-exist]: FAILED
- ...[pr-lines-past-end]: FAILED
- test_unlabelled_added_line_citation_exports_pr_code: PASSED
- test_unlabelled_citation_matching_neither_snapshot_exports_pr_head: PASSED
- test_labelled_base_citation_exports_base_code: PASSED
Totals 11: 9 passed, 2 failed.

Not run: the full suite. Cleanup: wrote only this report; pytest run with -p no:cacheprovider; scratch log in $TEMP. Tracked files unchanged.
Verification NOT green: 2 failures.
