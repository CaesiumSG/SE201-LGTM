# Re-review 2: repair-8 (5cec8e1..acfb780)

Verdict: CLEAN. 0 Critical, 0 High, 0 Medium. One open question.

Scope: repair diff only: src/lgtm/validation/evidence.py (read_cited_code, new _content_at_lines), benchmark/citation_export.py (export_run, _read_lines, _norm, _holds), tests/test_removed_line_citation.py. Paths touched: read_cited_code -> judge input; export_run -> judge_eval rejudge units.

## rereview-01 (High): resolved
- read_cited_code keeps the snapshots where the citation validates. Among them it now prefers the ones where the normalized content is a substring of exactly the cited lines. In the two-handler fixture, base lines 7-8 hold the check, and PR lines 7-8 (`thread.delete()`, blank) do not. Base is picked even though the text survives in get() at PR lines 3-4. The new test (SIBLING_BASE/SIBLING_PR, lines [7,8]) is the rereview-01 trigger, and it fails on the old rule (repair-8-tests baseline: 4 failed, for the right reason).
- Shifted lines: unchanged code cited with base numbers holds at base, not at the PR lines, so base is read. That is the same rule.
- Added lines: PR holds at the cited lines, base does not validate, so PR is read. Context lines hold in both, so PR is read first. Unchanged.
- Labelled, conflict and no-shas paths: unchanged. Empty content or an invalid range returns False from _content_at_lines, so the earlier rule applies as before. The slice cannot go out of range, because only snapshots that already passed the range check are kept.
- _content_at_lines uses the same _normalize and exact-substring test as _validate_snapshot_item, so the rule cannot pick a snapshot the validator would reject.

## rereview-02 (Medium): resolved
- The export reads PR head for a null snapshot. When the content is non-empty and the PR text at the cited lines lacks it, the export reads base at the cited lines (with REBUILT_COMMITS resolution for "base") and uses base only when it holds the content. The unit keeps snapshot null as the rejudge key.
- This matches production on the decisive cases: removed lines with PR lines present, removed lines past the PR end, the surviving-copy case (three new tests), added lines, and context lines (PR holds, so PR is read).
- Null-snapshot unreadable cases (tests/test_judge_eval.py TestNullSnapshotCitationsAreReadAtPrHead, content "c") stay unreadable, because base does not hold "c" at the cited lines. Those 3 parametrizations pass.
- One remaining divergence, which the parent's constraint requires: production can read base when PR does not validate and base validates only by whole-file content (content not at the cited lines). The export keeps such a unit unreadable. That is the "null-snapshot unreadable stays unreadable" requirement, not a defect.

## Open question (not blocking)
- Imprecise line numbers: the cited range is off by one or more lines and does not fully contain the removed text, and the text survives elsewhere in the PR file. Then _content_at_lines matches neither snapshot, and the PR-first fallback reads unrelated PR code again (the export keeps the PR read). Whether models cite removed lines imprecisely often enough to matter is unmeasured. Recommend: defer. Journey 4 labelling will surface any mislabelled units. Repair-8 rejected rereview-01's suggested 5-line window, because that window also contains the surviving copy.

## Plan check
- No new contradictions. The rereview.md minor corrections still apply and are now satisfied by the code: the stories.md S1 business rule extension, and the slices/INTEGRATE.md journey 4 line "citation_export reads null-snapshot citations by the same snapshot rule as the production judge read". Recommend applying them as written, with "same" softened to "the same content-at-cited-lines rule". The export intentionally does not use production's whole-file fallback.
- Carried, not re-raised: the final.md needs-replan item on AC-S1-2 (alerta SQL in lgtm mode) is still open.

## Coverage
Axes: correctness of snapshot selection (unique or duplicated text, shifted lines, past the end, missing file, empty content, invalid range, labelled, conflict); export parity with production; tests as evidence. Run at acfb780: `pytest tests/test_removed_line_citation.py tests/test_judge_eval.py` -> 152 passed. checks-repair-8 reports the full suite green (2941 passed, 7 host skips). Not run: live journeys, lint/type checks. No throwaway folder was created. Worktree git status is clean.
