Source: LGT-165 https://linear.app/se201-lgtm/issue/LGT-165/issue-21-address-lgtm-flow-problems-reviewer-reach-pr-scope-benchmark
Retrieved: 2026-10-26 (time of day not captured)

# Decisions

* DEC-1: Which problem groups of GitHub issue #21 does this plan cover? — A1–A4 (reviewer reach), A5–A8 (PR-scoped review), B1–B4 (benchmark and documented scope), C1–C7 (Kev judge), D1–D5 (measurement gaps). Source: user.
* DEC-2: Is A9 (run-to-run variance at temperature 0) in scope? — No. Source: user.
* DEC-3: What does the plan build on? — The head of PR #20 "Kev-4B judge and validation bench" (branch `kev-validation`, commit 7f642e1). Source: user.
* DEC-4: Which Linear project holds the feature issue? — SE201-LGTM (team LGT). Source: user.
* DEC-5 (OD-1): When is a finding about the PR? — It must cite a line the PR changed or removed, or explain how the PR newly exposes existing code; other findings are not reported as PR findings. Source: user.
* DEC-6 (OD-3): How do reviewer budgets and context change? — Raise the investigator tool-call and step budgets and the read_file line cap, include the enclosing function of every change (deletions included), and report when a limit is hit. New values are the build's to choose within the existing config. Source: user.
* DEC-7 (OD-7): Kev rates evidence supported but the verdict is not real — the result is not a vulnerability; the verdict decides, which can change the review exit code. Source: user.
* DEC-8 (OD-8): Where do Kev judge labels come from? — A stronger model (Claude Opus 5.5, run by the build agent) labels the cases against the documented criteria; labels are stored with the benchmark. Source: user.
* DEC-9 (OD-11): Real-world benchmark cases are held out: never used to tune prompts, budgets, or judge criteria; used only to measure. Source: user.
* DEC-10: Non-blocking open decisions OD-2, OD-4, OD-5, OD-6, OD-9, OD-10 take the recommendation in `plan/reports/story-planner-stories.md`. Source: planner recommendation, approved by user at plan approval.
* DEC-11: Keep AC-S4-7 (Shoply safe cases sqli_04/07/11 changed so Semgrep warns on them)? — Yes, keep it. Source: user.
* DEC-12: Does the scope statement also go in `docs/project-proposal.md`? — Yes: README and project proposal. Source: user.
* DEC-13: The regenerated Shoply safe patches shifted the run6-final citations for sqli_04_safe, sqli_07_safe and sqli_11_safe. How does kev-judge-measurement treat these three candidates? — They are left out of kev scoring and reported as stale with the reason. INTEGRATE labels them in journey 4. kev-judge-measurement writes nothing outside its Scope. Source: orchestrator, replan 1 (R-1).
* DEC-14: Re-summarizing or resuming older stored real-world runs still counts alerta_sqli_vulnerable, alerta_sqli_safe and postgraas_sqli_safe as in scope. How does INTEGRATE handle this? — INTEGRATE journey 2 writes to a fresh output directory. CT-benchmark-scope-trace-1 and the accepted benchmark-scope-trace slice are unchanged. The --resume and --summarize-only limitation on stored runs is recorded in INTEGRATE's known issues. Source: orchestrator, replan 1 (R-2).
