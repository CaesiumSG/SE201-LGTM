# Behavior review: INTEGRATE (84bece6)

Inspection only; no tests run, no throwaway folder created.

## behavior-01 (Medium, inspected): default-on injection finding is scored by the Kev judge, not its own verdict
- Where: src/lgtm/pipeline.py L264 (`findings.extend(detect_prompt_injections(diffs))`) then L276-283 (`judge_candidates` for lgtm and lgtm-no-sast); benchmark/evaluate.py `finding_verdict` (judged rows ignore `verdict`); src/lgtm/cli.py exit-1 test (`f.supported is True or f.verdict == "vulnerable"`).
- Expected: main's injection mitigation (default on) flags reviewer-directed instructions as a finding that counts toward the case verdict (src/lgtm/diff/sanitizer.py sets verdict="vulnerable", category ""). Feature: every candidate is judged and scored by supported and not-not_real.
- Actual: the merge sends the injection finding through the judge. It is a comment-line finding, so Kev can return not_real or unsupported. Then judged scoring (evaluate.py, run_injection_bench.py) reads "safe" and the injection is not counted, while the CLI still treats verdict=="vulnerable" as supported and exits 1. If the judge call fails, the whole case is excluded as not_judged. Benchmark ASR and CLI exit code can disagree on the same finding.
- Evidence: no test covers injection_detector findings with judge_candidates (grep of tests: only tests/test_sanitizer.py). Neither slice nor intake report addresses it. Two slices each correct alone; the interaction is integration-owned.
- Fix: decision needed. Smallest: bypass the judge for `agent == "injection_detector"` (set supported=True, judged=True) or append the injection findings after `judge_candidates`; add one test. Not a live-model criterion; this is deterministic.

## behavior-02 (Low, inspected): dead UNCREDITED/EXCLUDED code left in benchmark/evaluate.py
- `outcome_for_label` (L388) is unused, and `summarize.metrics` still filters EXCLUDED/UNCREDITED. Round-2 rule (outcome_for) is what score_case uses, so behavior matches main; log decision recorded. No behavior impact; stale code only.

## Confirmed kept (no finding)
- Defaults: CLI `--graph/--no-graph`, `--authz-planner`, tri-state strip-comments and detect-prompt-injection (config defaults True/True, graph True, planner "investigator"); `endpoint` planner path keeps checkpoint gating without investigator; judge options present.
- Failed section: authz reviewer returns [] and appends to `errors`; pipeline `_section_result` marks the section failed with the error, `meta.agent_errors` gets it, coverage `sections_failed` counts it, CLI exits 2 (no supported) via agent_errors. Benchmark rows still become scan_failure/error via coverage (`_scan_failed`, `is_done` re-runs sections_failed>0); infra prefix detection skips authz when coverage exists, so removing the pseudo finding loses no error signal. Real-world rows use the same score_case.
- limit_hit: base.py `_close_run`/`fill_record`: budget stop -> "tool_calls", iteration cap -> "steps", invalid-input cap -> null unless over budget, normal answer -> null; `budget_spent` is reset on every run_tool_loop exit, and each section calls reset_budget, so no stale value carries between sections (an exception path does not reach fill_record).
- Round-2 scoring: score_case flags iff a vulnerable finding in category; judged flag passed through predict_case_verdict; grounded label downgrades unsupported vulnerable to possible for non-judged rows in `_relevant_verdicts` and all derive_case_labels branches; judged rows use supported and kev_verdict.
- Lock regeneration: lock-regen.md attributes every change; duplicates collapsed with equal values.

Coverage: read slice, log decisions, repair and lock reports, then merged pipeline.py, base.py, authz_reviewer.py, cli.py, config.py, evaluate.py, judge.py, sanitizer.py. Not checked: tests not rerun; live-model criteria not assessed; README wording for exit codes not reviewed. Cleanup: nothing created.
