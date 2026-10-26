# Pending-integration checks at 84bece67c8708217d1f8f6b0293178fd43ee1466

Checkout worktrees/INTEGRATE, HEAD 84bece67, working tree clean before and after. No live model or Kev server used.
Pytest prefix: .venv/Scripts/python.exe -m pytest -q -p no:cacheprovider (each command run once).

| Source slice | Criterion | Command | Result |
|---|---|---|---|
| INTEGRATE risk | Regression targets for surfaces shared by kev-judge and pr-scoped | pytest tests/test_kev_confidence.py tests/test_pipeline_request_format.py tests/test_judge.py tests/test_kev_support_bench.py | Passed: 255 passed, 0 skipped |
| benchmark-scope-trace | Slice check (AC-S4-1..S4-7 incl. doc statements) | pytest tests/test_evaluate_real.py tests/test_benchmark_cases.py tests/test_real_world_cases.py tests/test_baselines.py tests/test_e2e_benchmark_replay.py | Passed: 637 passed, 0 skipped. Not inspected: whether the AC-S4-7 test ran the real Semgrep binary |
| kev-judge-measurement | AC-S5-1..4, S6-1..5 logic on fixtures; model-input lock | pytest tests/test_judge_eval.py tests/test_cli.py tests/test_report.py tests/test_e2e_judged_bench.py tests/test_e2e_review_judge.py tests/test_graph_benchmarks.py tests/model_input_lock tests/test_agents.py tests/test_diff.py tests/test_graph_export.py (one combined run) | Passed: 694 passed, 2 skipped |
| reviewer-reach / pr-scoped-review | AC-S1-4 no-crash, S2, S3 unit; agents budget cases; render_read clamp (scope addition) | same combined run (test_agents, test_diff, test_graph_export) | Passed. 2 skips at tests/test_graph_export.py:1473: symlink creation denied on this Windows host (WinError 1314); those symlink cases are unexecuted |
| reviewer-reach, pr-scoped-review, kev-judge | Regenerate tests/model_input_lock/expected.json after final merge | tests/model_input_lock in the combined run | Passed without regeneration: lock tests pass at HEAD, so expected.json matches HEAD output |
| reviewer-reach | Live-model AC-S1-4 | n/a | Needs live model. Criterion: reviewer reaches enclosing code in a real run. Not run |
| reviewer-reach | AC-S1-1, AC-S1-2, AC-S2-4 on real-world cases (DEC-9) | n/a | Needs live model (journeys 1, 2). Not run |
| pr-scoped-review | AC-S3-3, AC-S3-6 | n/a | Needs live model (Shoply dev run, journey 3). Not run |
| pr-scoped-review | AC-S3-5, AC-S3-7, AC-S3-2 litellm part | n/a | Needs live model (real-world run, journey 2). Not run |
| reviewer-reach / pr-scoped-review | Shoply dev rerun for deletion-evidence vs PR-scope prompt interaction | n/a | Needs live model. Not run |
| benchmark-scope-trace | Real-world stored-run measurement (DEC-9); AC-S4-3, AC-S4-5 real-world parts | n/a | Needs live model (journey 2). Not run |
| kev-judge-measurement | Real-world parts of AC-S6-1, AC-S6-2; AC-S6-6 | n/a | Needs live model and Kev server (journey 4). Not run |
| kev-judge-measurement | final-01: run6-final records lack mode, so live rejudge skips them | grep of benchmark/judge_eval.py | Still open: gating at judge_eval.py:495,516,535,539,557 uses r.get("mode") in JUDGED_MODES with no default to lgtm. Fix before journey 4 |

## Contract key checks (static read at HEAD plus runtime spot-check)

CT-reviewer-reach-1, persisted vs consumed: match.
* Writer: RunRecord (src/lgtm/agents/base.py:486) has section, tool_calls, raw_answer, limit_hit; ReviewResult.run_records (pipeline.py:98,111,315,383) is filled by section stage, investigator, authz agent.
* Reader: benchmark/evaluate.py run_record_fields (:134) does asdict over review.run_records, so persisted keys are exactly those four; written at evaluate.py:603 and evaluate_real.py:298. Nothing in benchmark/ parses them back; persist-only.

CT-benchmark-scope-trace-1: writers and summary reader match; one gap.
* scope_fields (evaluate.py:104) adds scope and off_category via score_case and the error rows. evaluate_real.py writes case_scope (:225,:251), read at evaluate.py:109. Summary reads scope at :664 (default "in"), writes out_of_scope_cases :747, off_category :748, alarm rate :770-773; evaluate_real.py:329 writes sql_cases_semgrep_warns_on.
* Gap: benchmark/judge_eval.py never reads scope, case_scope, off_category or run_records (grep: only mode and findings). The kev-judge intake asks to confirm it does; the slice contract only names it as consumer of scope labels and per-case results. Parent decides whether it must.
* Known issue unchanged: older stored results without scope read as "in".

## benchmark/kev_support/runner.py vs src/lgtm/validation/evidence.py: match at HEAD
* runner.py:51,189 EvidenceValidator(repo, "HEAD") vs __init__(self, repo, base_ref, diffs=None, config=None, *, shas=None) (evidence.py:77).
* _validate_policy_item(item) (:266) and _validate_code_item(item) (:204) take one EvidenceItem and return list[str]; runner.py:54 uses them so.
* read_cited_code(item) -> str (:301); runner.py:197 passes the bound method. validate (:320) and validate_all (:327) present. tests/test_kev_support_bench.py passes.

## Supported-but-not_real rule by site (evaluate.py at HEAD)
Rule: finding_verdict (evaluate.py:324-327), judged rows are "vulnerable" only if supported and kev_verdict != "not_real". Spot-check with a supported, not_real, sqli finding: finding_verdict = safe, scope_fields off_category = [], predict_case_verdict(require_grounded, judged) = safe, raw grounded count = 1.

| Site | Behavior | Required by slice or AC? |
|---|---|---|
| finding_verdict :324 | Applies | Yes: AC-S5-3; kev-judge slice Owns "counting rule"; INTEGRATE.md risk 3 |
| predict_case_verdict :331 (predicted and predicted_grounded) | Applies via finding_verdict; grounded downgrade skipped for judged rows | Yes, AC-S5-3 |
| _relevant_verdicts / derive_case_labels :401, :462-485 | Applies | Yes, AC-S5-3 |
| scope_fields off_category :113-118 | Applies (not listed off-category) | Consistent with AC-S5-3 |
| per-case verdicts (evaluate.py:595, evaluate_real.py:293) | Applies | Yes, AC-S5-3 |
| grounded counts: per-case grounded and grounding_rate (evaluate.py:590,598), summary :731, evaluate_real.py:284 | Counts supported only; rule NOT applied | Not required: AC-S5-3 covers reported vulnerability and false alarm; AC-S5-1 keeps supported separate from verdict; slice file has no text applying it to grounding. grounded_only metrics (:757) do apply it through predicted_grounded |
| judge_eval.safe_case_acceptance :197 | Counts Kev supported answers on safe cases; ignores verdict | Not required: AC-S6-2 asks the share Kev accepted. Unresolved expectation whether supported-but-not_real counts as accepted; tests/test_judge_eval.py:1908-2001 pin supported-only |
| CLI exit code cli.py:141, report_builder.py:22 | Applies | Yes, AC-S5-4 |

Conclusion: the intake claim is partly right. Everything verdict-derived goes through finding_verdict and is consistent. Grounded counts and safe_case_acceptance measure supported by design; no AC requires the rule there. Decision to record: grounded includes supported-but-not_real.

## Totals and gaps
* Executed: 3 pytest invocations (255, 637, 694 passed + 2 skipped), 0 failures.
* Not run: all live-model and Kev-server journeys above; full suite (another check); lgtm CLI and evaluate.py mode commands.
* Open: final-01, symlink skips, judge_eval does not consume scope keys.
* Cleanup: tmp/pending removed; no processes started; no tracked files edited. Live-model verification remains incomplete.
