# INTEGRATE journey 3 and journey-4 candidates

Checkout: worktrees/INTEGRATE HEAD 6d00729, working tree clean (run pins code_dirty=false). Worktree .venv python.
Judge: evaluate.py has no judge flag; default config judge_endpoint is http://127.0.0.1:8008 (used).

## Commands
1. `.venv/Scripts/python benchmark/evaluate.py --mode lgtm --split dev --gpu-cluster --output <tmp>/journey-3/dev` -> exit 0 (log journey-3/dev.log, started 10:59, finished ~11:58). 26 per-case JSON + run.json + summary.json written (journey-3/dev/).
2. `... --mode lgtm --split eval --cases sqli_04_safe sqli_11_safe --gpu-cluster --output <tmp>/journey-3/eval-candidates` -> exit 0 (eval.log). Per-case JSON + summary.json written, but both cases are ERROR with 0 findings.
Run script: journey-3/run.sh. Both runs sequential.

## Outcome: BLOCKED (model endpoint went down mid-run)
- Model tunnel/server became unreachable at 11:49:23 (dev.log line 230: ReadError 10054, then ConnectError WinError 10061 "actively refused" for the rest of the run). ssh.exe tunnels no longer exist; at 12:03 both http://127.0.0.1:11435 and :8008 return no response. I did not restart them (shared resource, forbidden).
- HTTP 500 responses from the model endpoint in logs: 0 (grep "500" in dev.log, eval.log). The failure mode was connection refused/reset: 87 x WinError 10061 and 1 x 10054 in dev.log (88 lines matching 10054|10061 counted together elsewhere), all of eval.log.
- The summary reports errors=0 / 26 scored although 10 dev cases ran with failed sections: infra failures are scored as FN/TN silently (coverage.complete=false, sections_failed=1, investigator_status=failed; infra_failures counter stays 0). Product/harness observation: evaluate summary does not surface failed review sections as ERROR.
- Dev summary as written (invalid): TP 8 FP 0 FN 5 TN 13, authz recall 2/7, sqli 6/6 TP and 6/6 TN.

Valid dev cases (coverage.complete=true): all 12 sqli cases, authz_01 safe+vulnerable, authz_02_vulnerable.
Contaminated (model unreachable, coverage.complete=false): authz_02_safe, authz_03 (both), authz_07 (both), authz_08 (both), authz_09 (both), authz_13 (both).

## AC-S3-3 (authz_06_safe, authz_09_safe not FP): NOT MET / not demonstrated (Blocked)
- authz_06_safe is split=eval, not in the dev run; no result.
- authz_09_safe (dev) shows TN but its sections_failed=1 with connection refused, so the TN is infra failure, not a review. No evidence.

## AC-S3-6 (no base-commit-7f642e1 TP becomes FN): NOT MET / not demonstrated (Blocked)
- No stored lgtm dev run at 7f642e1 exists in the run dir; run6-final (model different, predates Shoply regeneration) is not that baseline. A base-commit run was not made (about 60 min per dev run, no model endpoint now).
- Current-run FNs (authz_03/07/08/09/13_vulnerable, 5) are all infra-failed sections, so they say nothing about regression. Valid vulnerable results: 6/6 sqli TP, authz_01 TP, authz_02 TP.
- To close: restart the model endpoint (owner), rerun dev into a fresh directory, and run the same dev command at 7f642e1 (or locate a stored one) to compare TP sets.

## Journey-4 candidate result paths
- sqli_07_safe (dev, valid): journey-3/dev/sqli_07_safe.json  outcome TN, 2 findings (off-category authz:orders-export-endpoint), coverage complete.
- sqli_04_safe (eval): journey-3/eval-candidates/sqli_04_safe.json  ERROR, 0 findings, model unreachable. UNUSABLE; needs rerun.
- sqli_11_safe (eval): journey-3/eval-candidates/sqli_11_safe.json  ERROR, 0 findings, model unreachable. UNUSABLE; needs rerun.
(all under C:/JR Cache/se201-lgtm/.tmp/build/issue-21-lgtm-flow/build/INTEGRATE/tmp/journey-3/)

## Cleanup
Nothing started that needs teardown; background run finished. Artifacts remain in journey-3/. No code or tests changed.
