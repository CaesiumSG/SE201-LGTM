# Re-review: reviewer-reach repair diff (4422298..59a878b)

Verdict: ACTION. final-02 is resolved. final-01 is resolved for the cases it named, but the repair's name-based dedup adds a narrower form of the same defect (final-03, High).

Scope: only the repair diff (src/lgtm/agents/authz_reviewer.py `_hunk_lines`, `_enclosing_functions`, `_strip_comments`, `_enclosing_block`; tests/test_agents.py, 3 new tests) and the paths it touches.

Acceptance criteria checked:
- AC-S2-1 (corrected wording: "every changed line, including removed lines (a hunk spanning several functions contributes each of them)"). Not met in one case, final-03.
- AC-S1-4: the repair does not change it. It is still a unit-level check with a fake model, and real behaviour is checked at INTEGRATE (DEC-9).

## Status of earlier findings
- final-01: resolved for the reported triggers. `_hunk_lines` returns every added line (PR snapshot) and every removed line (base snapshot). `_enclosing_functions` maps each line to its innermost function. A hunk that removes from one function and adds to another, or that adds to two functions, now renders each function. The two new tests cover both shapes and would fail against the old `_hunk_anchor` (repair-4 saw them fail first). Inspected.
- final-02: resolved. With `strip_comments`, each rendered definition goes through `sanitize_file_diff`. Base-snapshot definitions go through it too, because the guard applies to every item. The new test asserts the comment marker is gone. The sanitizer's own over-stripping (for example, a triple-quoted SQL string treated as a docstring) predates this change and is shared with the diff path. The header line numbers still refer to the unstripped file, which repair-3 notes. Inspected.

## Findings

### final-03 High (reproduced): a same-named method elsewhere in the file hides the removed-line enclosing function
- Location: src/lgtm/agents/authz_reviewer.py `_enclosing_block`, the lines `pr_names = {(rel, name) ...}` and the filter `if label == "pr" or (rel, name) not in pr_names`. The bare `node.name` comes from `_enclosing_functions`.
- Trigger: one section, one file with `class A: def get(...)` and `class B: def get(...)`. The PR deletes a line in `A.get` and adds or edits a line in `B.get`, in the same hunk or in two hunks of the section. This shape is common in authorization code: Django class-based views with `get`, `post`, `get_queryset`, `dispatch` or `has_permission` in several classes of one views.py.
- Expected: AC-S2-1 (corrected): the input includes the enclosing function of every changed line, including removed lines. That means `A.get` from the base snapshot plus `B.get` from the PR snapshot.
- Actual: only `B.get` is rendered. The base `A.get` is dropped because its bare name `get` matches a PR function in the same file. Reproduced with a throwaway pytest file that used the repo's `snapshots`, `_change_hunk` and `_initial_input` fixtures against the worktree src: the same-name case fails because `AAA_TOP` is missing. The control case (B's method renamed to `post`) passes. Repair-3 lists this as a known limit, but no plan decision accepts it. It is the deletion case final-01 was raised for.
- Smallest correction: dedup on qualified name rather than bare name. In `_enclosing_functions`, record the dotted path of enclosing class and function names (for example, `A.get`). One way is a recursive walk that carries a prefix instead of `ast.walk`. Key `pr_names` and the filter on `(rel, qualname)`. Add a test with two classes that each have `get`: delete from one, add to the other, and assert both appear. The existing test for a modified function shown once keeps passing, because a modified function has the same qualname in both snapshots.

## Medium
None new. Earlier Mediums (unbounded block total, limit_hit for the invalid-input cap, edge-case tests) are unchanged by the repair and not re-raised. Each changed hunk now reads up to two blobs instead of one (bounded by hunk count), which is negligible.

## Plan check
- No contradictions in the repair's reach. AC-S2-1's corrected wording is the right yardstick, and final-03 violates it.
- minor (optional): if the parent prefers to accept the same-name limit rather than fix it, it needs a Decisions entry in the slice plan, because it narrows AC-S2-1. That would be needs-replan for AC-S2-1 in this slice only. I recommend the fix instead.
- No needs-replan items otherwise.

## Coverage
- Axes: correctness (added, removed and mixed hunks; nested functions use the innermost match; dedup by (label, rel, start) and by name; shas None skips PR; KeyError and None sha; failed blob read; syntax error returns []), tests as evidence (3 new tests by inspection), security (strip_comments on both snapshots), performance (blob reads per hunk) and architecture (the local import avoids the sanitizer -> agents.base cycle and matches the existing structure).
- Checks run: one throwaway pytest file (2 tests) in build/reviewer-reach/tmp/final/, run with PYTHONDONTWRITEBYTECODE=1, `-p no:cacheprovider` and the worktree src first on sys.path. Result: 1 failed (the final-03 trigger), 1 passed (the control). Full suite not run; the change-verifier owns it.
- Limits: no live-model runs (DEC-9). I did not run the three new repo tests myself; repair-4 reports them passing.
- Cleanup: the throwaway folder was removed by an exit trap and verified absent. pytest's own tmp_path directories sit under the system temp folder (pytest-of-<user>), which pytest manages. The worktree `git status` is clean and HEAD is 59a878b.
