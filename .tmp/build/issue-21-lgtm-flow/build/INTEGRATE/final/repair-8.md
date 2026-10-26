# repair-8

Files: src/lgtm/validation/evidence.py, benchmark/citation_export.py. Nothing run or verified.

## rereview-01 rule (evidence.py read_cited_code, new _content_at_lines)
Unlabelled, non-conflict citation, shas known. Snapshots = those of pr, base that validate (as before). Pick, in order:
1. snapshots where the normalized content (whitespace-collapsed, lowercase) is a substring of the text of exactly the cited lines (lines[start-1:end]);
2. else all validating snapshots (pr first);
3. else [pr, base] as before.
First readable label wins. Missing lines, empty content or invalid range: rule 1 matches nothing.

## rereview-02 rule (citation_export.py export_run)
Null snapshot only. Read PR head at cited lines. If content is non-empty and the PR text lacks it (normalized substring), read base_sha at cited lines; if base text contains it, use base code. Otherwise keep the PR read (None -> unreadable). Labelled snapshots unchanged; unit snapshot stays null. Content "c" in test_judge_eval.py 1561-1580 matches neither base fixture (old1.., s4..s6, base2/3), so those stay unreadable. Local helpers _norm/_holds; _read_lines gained an optional snapshot arg. No shared module fit; rule duplicated locally.

## Notes
- Cited-line match is exact range, no +-5 window (the window would still include the surviving copy in get() in the rereview-01 fixture).
- Export compares by plain substring; evidence.py uses the same normalize but without fuzzy.
- Not added: two-handler test (test-developer).
