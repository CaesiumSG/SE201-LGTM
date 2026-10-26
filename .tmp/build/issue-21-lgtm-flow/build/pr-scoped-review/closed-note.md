Build closed: accepted
Branch: build/issue-21-lgtm-flow/pr-scoped-review
Head: f036cc545dda8972b2ceb011c289a49bf63cf66f (base ebe9dff9d5970a5678eb5f721230a33d0eee1d0c)
Commits: 14a8e25 Ground evidence on lines the PR removed; f036cc5 Limit authz section-review findings to flaws the change introduces or exposes

Summary: Reviewed vulnerability findings are now limited to problems a PR introduces or exposes: the authz reviewer's system prompt requires each finding to cite a changed or removed line, or explain how the PR newly exposes the code. Evidence quoted from removed lines can now be marked grounded, through an additive FileDiff.removed_text and removed-text matching in the evidence validator. AC-S3-1 and AC-S3-2 (Unit part) prove the prompt rule; model behavior and the litellm part are verified at INTEGRATE.

Evidence: full pytest 2745 passed, 0 failed, 8 skipped (environmental); model input lock regenerated (only the new rule line, 7 entries) and passing. Lens reviews behavior, test quality, common sense and structure: CLEAN. Final review: CLEAN.

Plan correction applied: slices/pr-scoped-review.md Packages scope-rule tier wording (Unit proves the prompt rule; model behavior at INTEGRATE). After: `AC-S3-1 (Unit: rule present in every authz system prompt, policy and no-policy; model adherence INTEGRATE via AC-S3-3), AC-S3-2 (Unit: same; litellm part INTEGRATE)`

needs_replan: none.

Outstanding (not blocking):
- final-01 (Medium): a file renamed and edited in the PR: evidence on its removed lines cited at the old path is never grounded (src/lgtm/validation/evidence.py).
- test-quality Medium: the scope rule is tested only by regex over prompt text; no test shows an unchanged-code weakness is dropped.
- test-quality Medium: a `pr`-labelled item on unchanged lines is grounded with no test pinning it (predates this slice).
- behavior Low: loose fuzzy matching can ground generic base snippets.
- common-sense Low: overlapping scope-rule prompt tests; two low-value tests in tests/test_diff.py; removed-line grounding tested in both tests/test_validation.py and tests/test_graph_evidence.py; the `texts` list in evidence.py could be more direct.
- Pending integration: AC-S3-3, AC-S3-5, AC-S3-6, AC-S3-7, litellm part of AC-S3-2; tests/model_input_lock/expected.json regenerated again by INTEGRATE after the final merge.
