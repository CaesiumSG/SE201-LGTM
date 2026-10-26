Source: LGT-165 (https://linear.app/se201-lgtm/issue/LGT-165/issue-21-address-lgtm-flow-problems-reviewer-reach-pr-scope-benchmark) and slice issues LGT-166 to LGT-171
Retrieved: 2026-10-26 (date only)
Coverage: comments on LGT-165 and on all six slice issues (LGT-166 to LGT-171), first page with limit 100; hasNextPage false for each. Build results and blockers are quoted from the comments named below. Only the first lines of the outstanding lists are quoted where the list is long; the full text is in the source comment.

## reviewer-reach (LGT-166)

Source: comment ff74dab4-8319-49d3-ac93-d078d622030a on LGT-166 (author LEE JIN RAE _, 2026-10-25)

* Build result: "Build closed: accepted". Head ebe9dff9d5970a5678eb5f721230a33d0eee1d0c. Full pytest 2716 passed, 8 skipped, 0 failed.
* needs_replan: "needs_replan: none."
* Pending integration: "Live-model AC-S1-4." / "AC-S1-1, AC-S1-2 and AC-S2-4 (DEC-9)." / "Regenerate `tests/model_input_lock/expected.json` after the final merge."
* Outstanding (Medium and Low), quoted: "The enclosing-definitions block has no total size cap, and each definition is cut silently at the line cap." / "`_enclosing_functions` recurses, so code nested about 2000 levels deep raises RecursionError (final-04)." / "A run record is lost when the LLM raises mid-run." / "The provenance `budgets` omit `read_file_max_lines`." / "`authz_reviewer` uses the toolbox's private `_snapshot_sha`." (Other Low items in the same comment: missing edge-case tests, untested `limit_hit` at the invalid-input cap, renamed and non-Python files get no enclosing definition.)

## pr-scoped-review (LGT-167)

Source: comment c31d329b-069d-459d-9c8b-4e8f4afd8981 on LGT-167 (author LEE JIN RAE _, 2026-10-25)

* Build result: "Build closed: accepted". Head f036cc545dda8972b2ceb011c289a49bf63cf66f. Full pytest 2745 passed, 0 failed, 8 skipped.
* needs_replan: "needs_replan: none."
* Pending integration: "AC-S3-3, AC-S3-5, AC-S3-6, AC-S3-7, litellm part of AC-S3-2; tests/model_input_lock/expected.json regenerated again by INTEGRATE after the final merge."
* Outstanding (Medium and Low), quoted: "final-01 (Medium): a file renamed and edited in the PR: evidence on its removed lines cited at the old path is never grounded (src/lgtm/validation/evidence.py)." / "test-quality Medium: the scope rule is tested only by regex over prompt text; no test shows an unchanged-code weakness is dropped." / "behavior Low: loose fuzzy matching can ground generic base snippets." (Other items in the same comment: test-quality Medium on a `pr`-labelled item on unchanged lines; Low items on duplicate tests.)

## benchmark-scope-trace (LGT-168)

Source: comment 54154404-3521-42d6-89ac-7a9f24514099 on LGT-168 (author LEE JIN RAE _, 2026-10-25). Head efc85996e400c09c124cfa9366f58da9b3298214, which matches the acceptance commit efc8599.

* Build result: "Build closed: accepted". Slice checks: 634 passed, 0 skipped. Related modules: another 470 tests passed. AC-S4-7 ran against the real Semgrep binary.
* needs_replan (two items, both from this comment):
  1. Target kev-judge-measurement. Quoted: "kev-judge-measurement: the regenerated Shoply safe patches (sqli_04/07/11_safe) shift the lines cited by the run6-final candidates it reads."
  2. Target INTEGRATE. Quoted: "INTEGRATE: re-summarizing or resuming older tracked real-world runs (for example gpu-qwen3.8-27b/real_world/lgtm) still counts alerta_sqli_vulnerable, alerta_sqli_safe and postgraas_sqli_safe as "in". This needs a cases.json-based scope on rescore or a fresh run."
* Outstanding (Medium and Low), quoted: "Error rows and real-world error rows have no test asserting `scope`." / "The --rescore test does not cover an old no-sast sqli row." / "Non-headline rates include out-of-scope rows." / "`case_scope` duplicates `scope`."

## kev-judge-measurement (LGT-169)

* No build result, blocker, or acceptance comment found on LGT-169 (comments list empty).
* needs_replan: the item in the LGT-168 comment above (item 1) targets this slice. It is recorded here by source, not by a comment on LGT-169.

## INTEGRATE (LGT-170)

* No build result, blocker, or acceptance comment found on LGT-170 (comments list empty).
* needs_replan: the item in the LGT-168 comment above (item 2) targets this slice. It is recorded here by source, not by a comment on LGT-170.

## REVIEW (LGT-171)

* No build result, blocker, or needs_replan comment found on LGT-171. The only comment on LGT-171 is a replan note (see feature section below), not a review result.

## Feature issue (LGT-165)

Source: comments on LGT-165
* Comment 2e440382-f5ba-4601-82b8-f3a0aad2c0ca (2026-10-25): "Replanned 2026-10-25: added REVIEW slice (LGT-171), a pull-request review after INTEGRATE; slices touched: REVIEW." Not a needs_replan item.
* Comment 21173988-c18d-4f28-a15e-e05091dae28f (2026-10-25): "Plan approved 2026-10-25. Scope: GitHub issue #21 items A1–A8, B1–B4, C1–C7, D1–D5 (A9 out of scope); slices reviewer-reach, pr-scoped-review, benchmark-scope-trace, kev-judge-measurement, INTEGRATE; base PR #20 @ 7f642e1."
* Blockers: none recorded.

Reference: issue-21-lgtm-flow/build-results
