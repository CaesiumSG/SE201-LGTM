# repair-7 tests (final-01), Unit tier

File: worktrees/INTEGRATE/tests/test_removed_line_citation.py (11 tests; only file written)

Covered
- read_cited_code: unlabelled removed-line citation returns base code (PR lines exist / PR lines past end); added-line, context-line, neither-matches (keeps PR read), labelled base/pr unchanged.
- citation_export.export_run: same cases; unit snapshot stays null; labelled base unchanged.
Doubles: ev._committed_blob_lines, ce._resolve, ce.subprocess.run replaced (no git/fs).

Results
- Developer's fix present in tree: `.venv/Scripts/python -m pytest tests/test_removed_line_citation.py -q` -> 11 passed.
- Production diff of evidence.py + citation_export.py reverse-applied (then restored, git status identical): 4 failed, 7 passed. Failures: the 4 removed-line cases (4 parametrized: 2 per module), each returning PR lines/empty instead of base lines ("assert [] == ['    if thre... Forbidden()']"). Right reason.

Not covered
- Null-shas (no snapshot) read path: unchanged, covered by tests/test_validation.py.
- Judge-state text (build_judge_request) not tested; follows from read_cited_code.
- Export selection is asserted via content matching only; a fix that selects by another rule for content-less citations is not pinned.

## Follow-up: final-02 exit codes per mode (Unit)
File: tests/test_cli.py (only CLI test file). `_exit_code` gained a `mode` param passing `--mode`; `_finding` gained "injection" and "injection-not-judged" (verdict vulnerable, without/with not_judged_reason).
- New test_baseline_modes_exit_1_on_a_vulnerable_verdict (sast-only, llm-only): vulnerable -> 1 (also with agent error); safe -> 0; safe + agent error -> 2.
- New test_judged_modes_ignore_a_vulnerable_verdict_without_a_supported_judgement (lgtm, lgtm-no-sast): injection -> 0; injection with not_judged_reason -> 2; injection + agent error -> 2; injection + supported -> 1; vulnerable-verdict alone -> 0; supported -> 1; unsupported + agent error -> 2.
- Changed existing expectation: removed ["baseline-vulnerable","baseline-safe"] -> 1 from the default-mode (lgtm) parametrization; it contradicted README (verdict clause is baseline-only). Moved to the baseline-mode test.
- No contradiction with README.md or final.md found. Note: cli.py `lgtm review` help text (line 97) already says "baseline mode reports a vulnerable finding"; consistent.
Mutation: reverted clause to `f.verdict == "vulnerable"` -> 8 failed (the 4 injection/vulnerable-only cases x 2 judged modes), 59 passed; cli.py restored (diff unchanged).
Run: `.venv/Scripts/python -m pytest tests/test_cli.py tests/test_removed_line_citation.py -q` -> result below.
Result: 78 passed (test_cli.py 67 + test_removed_line_citation.py 11).

## Follow-up: export-side removed-line cases removed
Removed TestCitationExportRemovedLines::test_unlabelled_removed_line_citation_exports_removed_code (both params). Reason: export fallback reverted; citation_export cannot tell a null-snapshot citation from a PR-head one, and tests/test_judge_eval.py requires no base fallback for null snapshots. 9 tests remain in test_removed_line_citation.py (the 4 export tests left pin unchanged behavior).
Run: `.venv/Scripts/python -m pytest tests/test_removed_line_citation.py tests/test_judge_eval.py tests/test_cli.py -q` -> 215 passed.
