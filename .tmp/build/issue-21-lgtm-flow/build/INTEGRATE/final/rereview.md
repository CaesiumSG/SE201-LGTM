# Re-review: final-review repair (bf63915..5cec8e1)

Verdict: ACTION. 1 High, 1 Medium.

Scope: repair diff only (README.md, benchmark/real_world/README.md, src/lgtm/cli.py, src/lgtm/validation/evidence.py, tests/test_cli.py, tests/test_removed_line_citation.py) and the paths it touches (read_cited_code -> judge_candidates, citation_export -> judge_eval rejudge, CLI exit rule).
Criteria checked: AC-S3-4 / S1 business rule on removed-line evidence (judge read path), AC-S5-3/AC-S5-4 and CON-3 (exit code and README), INTEGRATE whole-feature check "README documents the changed exit code", journey 4 inputs (AC-S6-1/2) for the export decision.

## Findings

### rereview-01 High (reproduced): final-01 fix picks PR when the removed text still exists elsewhere in the PR file
- Location: src/lgtm/validation/evidence.py read_cited_code (new label selection) via _validate_snapshot_item, which range-checks the lines and searches the content in the whole file, not at the cited lines.
- Trigger: the usual authz deletion. Base app.py has get() and delete(), each with `if thread.owner_id != user.id: raise Forbidden()`. The PR removes the check from delete() only. The finding cites base lines 7-8, unlabelled, with that content. The PR file is still at least 8 lines long, and the same check text survives in get(). So the PR copy validates and is read first.
- Expected: S1 business rule ("Removed lines are valid evidence for a finding about removed behavior"). The final-01 correction says Kev sees the removed check.
- Actual (throwaway repro with the worktree venv, test doubles as in tests/test_removed_line_citation.py): resolves True. read_cited_code returns `'    thread.delete()\n'`, but the expected text is `'    if thread.owner_id != user.id:\n        raise Forbidden()'`. Kev is shown unrelated PR code. The same rule leaves the shifted-lines case from final-01 (unchanged code cited with base numbers) unfixed whenever the PR file is long enough. The code comment "Removed or shifted lines resolve only at base" does not hold for either case. The new tests pass only because their PR fixture holds no other copy of the removed text.
- Smallest correction: rank snapshots by whether the content occurs within the cited lines (for example, the cited range plus or minus the 5-line window _validate_unlabelled_item already uses), then by whole-file validation, then fall back as now. Add one test with the two-handler fixture above.

### rereview-02 Medium (inspected): export leaves journey 4 labelling and judging deletion citations on code production no longer shows
- Location: benchmark/citation_export.py export_run/_read_lines. A null snapshot reads PR head only.
- Production now reads base for an unlabelled removed-line citation. The export still reads PR head: wrong lines, or unreadable/not judged when the lines fall past the PR end or the file was deleted. Authz evidence carries no snapshot field, so every fresh journey 2/3 citation is null-snapshot. Journey 4 labels and Kev judgements for deletion findings then rest on inputs that differ from production. That skews AC-S6-1/2 numbers for exactly the reviewer change under test. It does not fail an AC outright.
- The repair's reason ("indistinguishable from a PR-head citation; the test requires no base fallback") is not accurate. The citation content distinguishes the two, which is the same signal production uses. tests/test_judge_eval.py TestNullSnapshotCitationsAreReadAtPrHead uses content "c", which matches neither snapshot. So a rule of "read base only when base validates the content and PR does not" keeps all three of its parametrizations unreadable. The reverted attempt fell back whenever the PR read lacked the content, without checking base, and that is why it broke the test.
- Recommend: resolve before journey 4 runs, using the same selection as rereview-01's fix (ideally the shared rule, not a copy). The unit keeps snapshot null as the rejudge key. If deferred, the journey 4 report must state how many null-snapshot units cite removed or shifted lines.

## Checks with no defect found
- final-02: cli.py now counts `verdict == "vulnerable"` only outside lgtm/lgtm-no-sast. This matches README.md (exit-code paragraph names sast-only, llm-only), the `lgtm review` help text, AC-S5-3/AC-S5-4 and evaluate.py scoring (the injection finding scores safe). It does not hide a detection the plan requires to signal. No AC or slice outcome requires the injection-detector finding to set exit 1. It still appears in the report, and it sets exit 1 when Kev supports it or exit 2 when it is not judged. In judged modes an unjudged vulnerable finding now gives exit 2, which the README states. tests/test_cli.py pins both mode groups, and the repair-7-tests mutation run shows they fail on the old clause. The changed default-mode expectation traces to README/AC-S5-4.
- final-03: the benchmark/real_world/README.md text matches evaluate_real.py (aborted after two git start failures in a row -> 4, else 0; --resume continues).
- final-01 single-occurrence cases (removed lines with the PR line present, past the end of the PR file, added, context, neither, labelled) behave as intended. Labelled, conflict and null-shas paths are unchanged. model_copy keeps _validate_unlabelled_item's in-place file rewrite off the original item.
- Tests run at 5cec8e1: tests/test_removed_line_citation.py, test_cli.py, test_judge_eval.py, test_validation.py -> 233 passed.

## Plan check
- minor: stories.md S1 business rules. Before: "Removed lines are valid evidence for a finding about removed behavior". After: "...about removed behavior, and the judge and the judge-eval export are shown the removed code they cite". Reason: rereview-01/02. This extends final.md's minor item to cover the export.
- minor: slices/INTEGRATE.md journey 4. Add: "citation_export reads null-snapshot citations by the same snapshot rule as the production judge read." Reason: rereview-02.
- Carried, not re-raised: final.md needs-replan on AC-S1-2 (alerta SQL in lgtm mode) is still open. The final.md minor item on the evaluate_real exit-code README line is done by the repair.
- Follow-up outside the repair (pre-existing): docs/prompt-injection.md threat model says CI "exits with code 1 only on `vulnerable`", which judged modes no longer do (stale since the Kev exit rule, not introduced here).

## Coverage
Axes: correctness of the snapshot selection (single and duplicated content, line shifts, missing file, labelled and conflict paths), exit-code rule per mode against README/AC/help text, README accuracy for exit 4, test evidence. One throwaway repro under build/INTEGRATE/tmp/final with the worktree venv and monkeypatched blob reads (no git, no network). Not run: full suite, live journeys, Semgrep. Cleanup: tmp/final removed by an exit trap and verified absent. Worktree git status clean.
