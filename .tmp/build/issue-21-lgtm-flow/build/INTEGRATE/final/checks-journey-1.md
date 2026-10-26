# INTEGRATE E2E journey 1 (live): lgtm review on aegra_authz_vulnerable

Checkout: worktrees/INTEGRATE at acfb780 (git status clean, unchanged during run). Held-out case (DEC-9): nothing tuned.
Scratch: build/INTEGRATE/tmp/journey-1/ (cache/ clone, fetch.log, review.log, review-output/, review-attempt0-cmdnotfound.log)

## Commands
1. `.venv/Scripts/python.exe benchmark/real_world/fetch.py --cases aegra_authz_vulnerable --cache <journey-1>/cache` -> exit 0.
   "ok aegra_authz_vulnerable: 59abec70..d9d89ca8  1 file changed, 19 deletions(-)" (matches AC-S1-1's 19 deleted, none added; branches rw/aegra_authz_vulnerable/{base,pr}).
2. Attempt 0: `lgtm review ...` with bare `lgtm` -> exit 127 (command not on Git Bash PATH). Environment error, no review ran; log kept as review-attempt0-cmdnotfound.log.
3. `.venv/Scripts/lgtm.exe review --repo <journey-1>/cache/aegra --base rw/aegra_authz_vulnerable/base --pr rw/aegra_authz_vulnerable/pr --gpu-cluster --judge-endpoint http://127.0.0.1:8008 --output <journey-1>/review-output -v` -> exit 1 (documented: at least one supported, not-not_real candidate). 501.3s.
   Output: "Findings: 1 (supported: 1, not judged: 0)"

Review output: build/INTEGRATE/tmp/journey-1/review-output/report.md and report.json

## AC-S1-1: MET
Finding (CWE-639, authz_reviewer, SUPPORTED, `libs/aegra-api/src/aegra_api/api/runs.py:73`):
"The PR removes the thread-ownership check from create_run, create_and_stream_run, and wait_for_run. Previously each endpoint fetched the ThreadORM by the user-controlled thread_id and raised 404 if existing_thread.user_id != user.identity. ... Removing the check lets any authenticated user create/stream/wait a run on another user's thread_id."
Suggested fix: restore the ownership verification. Diff confirms the removed code is exactly that check (`if existing_thread and existing_thread.user_id != user.identity: raise HTTPException(404 ...)` x3, plus the ThreadORM import).

## Observations (not criteria)
- Semgrep: 0 findings, so the finding came from the LLM path; judge (Kev, 8008) labelled it supported.
- Investigator step failed: model server returned HTTP 500 "no user query found in messages" on 4 attempts (10:33:19-35); pipeline logged "Investigator failed" and fell back to `Authz section review: fallback:libs/...runs.py`. The finding id is `authz:fallback:...`. Possible product/server defect worth a look (shared server was concurrently loaded). The investigator path itself was not exercised successfully to the end.
- Warning: RAG index not found (lgtm index not run); agent hit read_file budget (5) and was asked for final answer.
- Evidence snippets: one cites runs.py:95 (_prepare_run call, "grounded in PR: no") and threads.py:266; neither is the deleted check, but the explanation names it.
- Single run, so no variance information.

## Cleanup
No servers touched. Scratch dir left in place for the caller. Code and tests unchanged.
