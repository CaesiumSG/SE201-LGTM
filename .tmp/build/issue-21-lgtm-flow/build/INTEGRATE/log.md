# INTEGRATE build log

Prerequisite results from Linear (LGT-166..LGT-169 closed notes): all accepted; Linear workflow states lag the notes.

## Merge order
reviewer-reach, pr-scoped-review, benchmark-scope-trace, kev-judge-measurement (slices/INTEGRATE.md order). Integration base origin/main bad831d; the feature base 7f642e1 sits on the origin/kev-validation line (28 commits not in main), which these merges bring in. Expected conflicts with main commits 4597a3c and 55445e7 (intake reports).

## Decisions

- UNCREDITED vs round-2 scoring: no plan criterion requires UNCREDITED (introduced by pre-feature commit 22a3b0f); main's round-2 rule kept; tests/test_baselines.py safe-side expectations set to TN. Source: plan/stories.md search, final/repair-1-tests.md.
- Failed section shape: reviewer returns [] and records the agent error (feature contract, AC-S2-4 'a failure is reported'); main's pseudo failure-finding removed; tests/test_graph_tools.py run_agent authz fixture adapted. Source: final/repair-3.md (developer report in handback), final/repair-3-tests.md.
- Removed tests: none. Changed expectations: tests/test_baselines.py (judged-mode rows for possible/insufficient_evidence removed from TestOutcomeTable.test_outcome_by_label_and_expectation; UNCREDITED->TN), tests/test_graph_tools.py (FORCED_MARK from prompt registry; authz run_agent fixture), tests/test_mitigation_defaults.py (agent_errors = [] on mocked pipeline).
- Lock regeneration: no repository command exists; follow_ups values recomputed via the test's code path, duplicate keys left by the first merge collapsed, text_tool_call_result restored; every change attributed in final/lock-regen.md.
- Live resources (2026-10-26): Ollama localhost:11434, GPU tunnel 127.0.0.1:11435 and Kev judge 127.0.0.1:8008 not listening; starting them needs the remote GPU cluster (model/deploy/*.sh over ssh), outside <repo-root>, so not started. Semgrep 1.182.1 and github.com reachable. E2E journeys 1-4 (live model; journey 4 also Kev) cannot run in this environment. The journeys are measurement runs of existing CLI commands, so no new E2E test files are written.
- Lens repairs: structure-01, common-sense-02/03 (repair-5), test-quality-01..04 (repair-6). Outstanding: behavior-01 (default-on injection finding judged by Kev vs CLI exit code), common-sense-01/behavior-02 (dead EXCLUDED/UNCREDITED code, pre-existing on main), structure-02, test-quality-05..07, fill_record getattr kept for a SimpleNamespace double.
- meta.endpoints_reviewed: kept as on main (the feature removed it); endpoint-count test follows merged code. Pending final review.
- Final review repairs (repair-7): final-01 applied to evidence.read_cited_code only; benchmark/citation_export.py unchanged, since a null-snapshot citation cannot be told from a PR-head citation there and tests/test_judge_eval.py requires no base fallback for null snapshots (export side outstanding). final-02 cli.py exit code; final-03 README exit 4. final-04: meta.endpoints_reviewed kept as on main (final review: no slice criterion requires its removal).
- Final checks: full suite at bf63915+repair-7 (before the export revert) 2 failed / 2937 passed; both failures were the export fallback, now reverted; targeted rerun 215 passed (final/checks-final-repair-2.md).
- Re-review repairs (repair-8): rereview-01 evidence.read_cited_code prefers the snapshot holding the content at the cited lines; rereview-02 citation_export reads base for a null-snapshot citation only when its content is absent from the PR and present at base's cited lines. Full suite 2941 passed, 0 failed (final/checks-repair-8.md). Export side resolved in repair-8.
- Squash deferred: the slice finishes blocked (live journeys not run), so the integration branch stays unsquashed for the resume; squash runs after the live journeys and a final review accept.
- Final review: final.md ACTION -> repair-7 -> rereview.md ACTION -> repair-8 -> rereview-2.md CLEAN.

## Removed tests

- None removed; tests the merge dropped were restored or rewritten to the logged decisions (final/repair-6.md). The stats.by_verdict and evidence_valid/evidence_issues cap-exemption assertions were not restored: neither key nor field exists in the merged code.
- Two cases added in this batch and removed before commit (never on the branch): TestCitationExportRemovedLines::test_unlabelled_removed_line_citation_exports_removed_code[pr-lines-exist, pr-lines-past-end] — export behavior not implemented. tests/test_cli.py: case [baseline-vulnerable, baseline-safe] -> 1 under default lgtm mode moved to the baseline-mode test (README exit-code rule).

## Resume 2026-10-26

Previous result renamed to result-1.json; plan mirror refreshed from Linear LGT-170 on 2026-10-26.

Resume 2026-10-26: endpoints 11434, 11435, 8008 refused connections; finished blocked (environment); closed note posted on LGT-170 (comment 1fc3baa8-42e5-4fe9-9c6a-ad18b70a7fb7) with endpoint addresses replaced by placeholders.

Resume 2026-10-26 (2): owner authorized starting the model endpoint and Kev judge server in this session; Slurm job 338762 started via model/deploy/judged-up.sh with tunnels on 11435 and 8008 (see final/servers.md); model/.env copied from the primary checkout into the worktree, gitignored, removed at shutdown. Previous result renamed to result-2.json.

Repair investigator-context: live journey 1 showed the investigator failing with HTTP 500 'no user query found in messages' once its history exceeded the served 32768-token context (reviewer-reach raised investigator budgets in 012fe4b). Added llm_context_tokens (default 32768), passed as num_ctx, and a run_tool_loop guard that requests the final answer before a request would exceed the window (3 chars/token estimate). Budgets unchanged. Journeys 2 and 3 were stopped before completion and are re-run on the repaired head; journey 1 is re-run too. Check: packages/investigator-context/check.md (full suite 2946 passed before the test fixture fix; new tests 6 passed after).

Shutdown: step 1 down.sh 338762 failed, exit 255 (ssh: connect to host 10.193.104.102 port 22: Connection timed out); job not cancelled. Step 2 model/.env deleted; git status --porcelain empty. Step 3 probes: 11435 -> 000, 8008 -> 000; netstat shows no listener on 11435 or 8008.
Journey 2 stopped and its output removed before completion; journey 3 output kept at tmp/journey-3 as evidence of the outage (not valid measurements).
Finish 2026-10-26: blocked (environment) at 6d00729; closed note on LGT-170 comment 83604c6b-fec9-4c2e-8b26-cb6502d8e758.
2026-10-26T04:58:27Z Attempt 4 resumed from 6d00729. Linear refresh: no human edits; plan/objective.md lost a local-only approval line. Cluster login node unreachable at first server start.

2026-10-26T05:20:18Z Lens review r3 of 6d00729 (final/review-*-r3.md): no Critical or High. Repair 1 (tests only, final/repair-1-r3.md, checks final/checks-repair-1-r3.md) committed as b22978ec716419791343945e73d5a6f0f2c06834. Outstanding: behavior M1 context-full stop not visible in coverage; behavior M2 num_ctx 32768 now sent to default local Ollama; tests L2 edge cases (initial prompt over window, precedence over budget exits); structure L2 num_ctx test placement; common-sense trivial default test and duplicated char-count helper.

2026-10-26T05:49:12Z Attempt 5 resumed from b22978e. Cluster login node unreachable (ssh port 22 timeout); journeys 2-4 not run. Closed note posted on LGT-170 (comment 5493f3d4-ea89-482d-9005-18882e483309). Auto mode denied cancelling earlier job 338762; its state is unknown.

2026-10-26T06:58:04Z Attempt 6: diagnosed cluster outage as a stale GlobalProtect data plane (route present, no packets enter the PANGP adapter); see final/servers.md Attempt 6. Journeys 2-4 not run.
