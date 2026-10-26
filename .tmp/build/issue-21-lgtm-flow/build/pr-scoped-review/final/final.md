# Final review: pr-scoped-review (ebe9dff..f036cc5)

Verdict: CLEAN (accept). Critical 0, High 0, Medium 1. Worktree left clean.

## Acceptance criteria checked
- AC-S3-1 (Unit): met at the tier the slice defines. The rule ("cites a changed or removed line, or explains how the PR newly exposes the code it cites") is in the `[authz_reviewer]` system prompt, the only free-form finding producer in lgtm modes. SAST triage only sees Semgrep hits already passed through `filter_to_diff` (pipeline.py). Plain reviewer (`llm-only`) is a baseline mode that sees only the diff.
- AC-S3-2 (Unit part): met. The "already exists in unchanged code is not reported: return an empty list" clause is in the same prompt. The litellm part is INTEGRATE.
- AC-S3-4 (Unit): met for added, modified and deleted files. Removed-only evidence labelled `base` is grounded, and unlabelled evidence is matched against removed text and added text. `grounded_in_pr` is display-only (report_builder.py:185), so no path downgrades or rejects. Validation and `resolves()` accept `base` items against the base blob. One gap for renamed files: final-01.
- CON-1/2/3: no new dependencies; `FileDiff.removed_text` is additive; no signature changes; report_builder untouched. The model input lock changes in 7 authz entries. Each differs from base only by the exact rule line. Checked by JSON diff (reproduced).

## Rulings on open points
1. Prompt-only scope rule (AC-S3-1/2). This is acceptable at the Unit tier and no code-side check is required in this slice. A code filter cannot test the "explains how the PR newly exposes" alternative of DEC-5. The only machine signal, `grounded_in_pr`, is display-only, and changing report or verdict gating is out of scope (report_builder, kev-judge-measurement). Behavioral proof belongs to INTEGRATE (AC-S3-3 and the litellm part of AC-S3-2). Unit tests only show that the rule is in the prompt. That is a known limit, and a plan clarification below records it.
2. A `pr`-labelled item on unchanged lines is grounded (reproduced: `def view(req):` at `pr` returns True). This behavior predates the slice: the base code returned `item.snapshot == "pr"`, and the diff keeps it. It is a follow-up, not a blocker. Recommend one pinning test or a line-range check in a later slice.
3. The removed text of a renamed file is not keyed by old_path. This is real and reported as final-01.

## Findings
### final-01 Medium, reproduced: removed-line evidence in a renamed-and-edited file cannot be grounded
- Location: src/lgtm/validation/evidence.py `__init__` (keys `_diff_removed` by `fd.path` only) and `_grounds_pr` (guard `item.file not in self._diff_added`).
- Trigger: a diff renames `old_auth.py` to `new_auth.py` and deletes `require_owner(req)`. Evidence is `{file: old_auth.py, snapshot: base, content: "    require_owner(req)"}`. It validates against the base blob, where the file exists under the old path.
- Expected (AC-S3-4): removed-only evidence can be marked grounded.
- Actual: `_grounds_pr` returns False. Citing `new_auth.py` at `base` returns True in isolation, but in a real run it fails base-blob validation (the file does not exist at base), so `issues` is non-empty and the result is also False.
- Smallest correction: in `__init__`, also set `self._diff_removed[fd.old_path] = ...` when `fd.old_path`. In `_grounds_pr`, check `item.file in self._diff_removed` for the removed-text match, and keep the `_diff_added` membership check for added text. Add one rename case to the test_graph_evidence table.
- Recommendation: resolve now if a repair round happens anyway (about 3 lines plus 1 test). Otherwise defer to a follow-up. A rename that drops an auth check is plausible but uncommon. The flag is display-only.

## Plan check
- Contradictions: none found. architecture.md line 27 describes the pre-fix defect ("grounding checks cited code against added text only"). That is accurate as a problem statement.
- Gaps: AC-S3-4 does not mention renamed files (final-01).
- minor (this slice), R/slices/pr-scoped-review.md, Packages table, scope-rule row. Before: `AC-S3-1 (Unit), AC-S3-2 (Unit; litellm part INTEGRATE)`. After: `AC-S3-1 (Unit: rule present in every authz system prompt, policy and no-policy; model adherence INTEGRATE via AC-S3-3), AC-S3-2 (Unit: same; litellm part INTEGRATE)`. Reason: fake models cannot prove adherence, and the current wording reads as if Unit proves the behavior.
- minor (this slice), Scope "Modifies": src/lgtm/agents/authz_reviewer.py and tests/test_agents.py are listed but were not changed. No correction is needed, because Modifies is permissive.
- needs-replan: none.

## Coverage
Axes inspected: correctness (labelled and unlabelled, strict and non-strict, base/pr/None snapshot, deleted, renamed and empty-removed files), tests as evidence (lens mutation results accepted, regex-only prompt tests noted), architecture (additive property, validator-local change), security (prompt rule sits in the system message, not the untrusted section; tested), performance (one extra fuzzy match per item over per-file removed text, bounded like the existing added-text match), dependencies (none).
Checks run: rename and unchanged-line reproduction script (throwaway); targeted pytest of test_diff, test_validation, test_graph_evidence, test_graph_prompts and model_input_lock gave 393 passed; JSON diff of expected.json against base. Full suite taken from checks.md (2745 passed).
Limits: no live-model run (INTEGRATE). Fuzzy 0.75 matching of short snippets against removed text is the same looseness that already exists for added text. Dropped as Low.
Cleanup: tmp/final removed by exit trap. The worktree `git status` is empty. The parent tmp/ folder was left in place and is empty.
