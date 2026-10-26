# Integration intake: pr-scoped-review

Slice branch build/issue-21-lgtm-flow/pr-scoped-review, base ebe9dff (= reviewer-reach head), head f036cc5. Run base_commit 7f642e1. Read-only survey; no tests run.

## Verdict
CLEAN. Critical 0, High 0, Medium 2, Low 3.

## Slice vs. slice file and result.json
Diff base..head: 8 files, +176/-15. Production: prompts.toml (+3, one rule bullet in the authz system prompt), git_diff.py (+8, additive `FileDiff.removed_text` property), evidence.py (+16/-5: `_diff_removed` map; `_grounds_pr` rewritten). Tests: test_diff, test_graph_evidence, test_graph_prompts, test_validation, model_input_lock/expected.json.
- The slice file lists src/lgtm/agents/authz_reviewer.py and tests/test_agents.py under Modifies; the diff does not touch either. The rule lives only in prompts.toml. Not a defect; the scope-rule prompt is tested in tests/test_graph_prompts.py.
- Out-of-scope surfaces confirmed unchanged: report_builder.py (no diff), `validate` and `validate_all` signatures, `EvidenceValidator.__init__` signature, FileDiff fields (only the `removed_text` property is added, no dataclass field). Matches the slice contract.
- result.json: status accepted, no blockers, no needs_replan.

## Expected conflicts
- tests/model_input_lock/expected.json: conflicts with kev-judge-measurement, benchmark-scope-trace and reviewer-reach text (all regenerate it; the slice's own diff changes 14 lines of the authz system prompt entries). Do not merge text; regenerate once after the final merge.
- Trial merge (git merge-tree) of slice head with kev-judge-measurement: clean. With benchmark-scope-trace: clean. With reviewer-reach: clean (it is the slice base). Trial merges did not flag expected.json because those branches changed different lines of it than the slice did; the text will still be stale after merge.
- src/lgtm/agents/prompts.toml: reviewer-reach, benchmark-scope-trace and kev-judge-measurement each carry reviewer-reach's +4 line change; the slice adds a separate hunk. Merge is clean, but the PR-scope bullet and the deletion-evidence bullet should be read together after merge (INTEGRATE risk: behavioural interaction).
- src/lgtm/validation/evidence.py, src/lgtm/diff/git_diff.py: no other slice branch changes them (kev-judge-measurement diff vs base: no change in src/lgtm/validation or src/lgtm/diff). No file overlap.
- Default branch: local main is an ancestor of base_commit (0 commits since base). origin/main has 12 commits not in base (merge base with 7f642e1 is ae5406c; base has 28 commits beyond it). Trial merge of slice head with origin/main conflicts only outside slice-owned files: src/lgtm/agents/base.py, cli.py, config.py, pipeline.py, tests/model_input_lock/expected.json, tests/test_baselines.py, tests/test_graph_pipeline.py, tests/test_graph_tools.py. origin/main touches evidence.py and git_diff.py not at all, and tests/test_graph_prompts.py (auto-merges). These conflicts are a property of base, not of this slice, and matter only if the run merges to origin/main.

## Contract drift (kev-judge-measurement, benchmark/kev_support/runner.py)
runner.py is unchanged by kev-judge-measurement vs base. It uses:
- `EvidenceValidator(repo, "HEAD")` at lines 51 and 189: constructor signature unchanged (`diffs` stays optional).
- `validator._validate_policy_item` and `validator._validate_code_item` (line 54): both exist at slice head with the same names and untouched bodies. The slice changed only `__init__` (adds `_diff_removed`) and `_grounds_pr`. No private method the runner calls is renamed, removed or re-signed.
- Runner builds the validator with no diffs, so `_diff_removed` is empty and `_grounds_pr` is not on its path. No drift.
- report_builder.py `grounded_in_pr` rendering (line 188-189, `(grounded in PR: yes/no)`): present and identical on kev-judge-measurement and the slice; kev changes only SUPPORT_EMOJI, `_support_label`, stats and suggested-fix condition in that file. No semantic overlap.
- `validate(finding)` and `validate_all(findings)`: unchanged in slice; kev does not change evidence.py.
- FileDiff fields: unchanged in both branches (`removed_text` is a property).
Regression targets to run after merge: tests/test_kev_support_bench.py, tests/test_kev_confidence.py, tests/test_pipeline_request_format.py, tests/test_judge.py.

## Artifacts to regenerate
- tests/model_input_lock/expected.json, once, after the final merge (python regeneration entry point under tests/model_input_lock; confirm via its test). Then run `pytest tests/model_input_lock`.

## Pending integration (from result.json and slice file)
- AC-S3-3: Shoply dev run, `python benchmark/evaluate.py --mode lgtm --split dev` (journey 3); run after reviewer-reach and this slice are merged.
- AC-S3-5, AC-S3-7, AC-S3-2 litellm part: real-world held-out run, once, fresh output dir, no --resume or --summarize-only (journey 2); includes the policy-mode comparison and no-tuning rule (DEC-9).
- AC-S3-6: Shoply dev run (journey 3).
- Regenerate expected.json (above).
- Whole-feature checks: full pytest, existing CLI and benchmark commands, no new dependency (diff adds none), README documentation review.
- DEC-10 items pending user approval; criteria may change.

## Outstanding items carried from the slice (not blockers)
- Medium: evidence on removed lines of a renamed-and-edited file cited at the old path is never grounded (`_diff_removed` is keyed by new path `fd.path` only; `_grounds_pr` requires `item.file in self._diff_added`). Confirmed in code.
- Medium: scope rule tested only by regex over prompt text; pr-labelled item on unchanged lines grounded with no pinning test (pre-existing).
- Low: loose fuzzy matching in `_snippet_in_text` can ground generic base snippets; overlapping scope-rule prompt tests; two low-value tests in tests/test_diff.py; duplicated removed-line grounding tests.

## Other notes
- Behavioural change in `_grounds_pr`: an unlabelled item is now grounded if it matches removed text; a `snapshot="base"` labelled item is grounded only if it matches removed text of a file in the diff. A base-labelled item on unchanged lines remains ungrounded, as before.
- Recommended order unchanged: reviewer-reach, then this slice (concurrent with benchmark-scope-trace), then kev-judge-measurement.
- Nothing noticed outside scope. No questions.
