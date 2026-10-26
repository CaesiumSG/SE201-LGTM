# story-planner: stories for issue-21-lgtm-flow

Written: `plan/stories.md` (7 stories, 33 criteria).

## Intake mapping

| Item | Home |
|---|---|
| A1 | S1, S2, S3 (symptom; headline F1 is the outcome measure). No own criterion: the gap on 12 cases (Fisher p about 0.45) is not a requirement |
| A2 | S1 |
| A3 | S2 (AC-S2-3, S2-4) |
| A4 | S2 (AC-S2-1, S2-2) |
| A5 | S3 (AC-S3-1, S3-4) |
| A6 | S3 (AC-S3-2), merged with A5 |
| A7 | S3 (AC-S3-3) |
| A8 | S3 (AC-S3-5) |
| B1 | S4 (AC-S4-3) |
| B2 | S4 (AC-S4-4) |
| B3 | S4 (AC-S4-1, S4-2) |
| B4 | S4 (AC-S4-5), merged with B1 |
| C1 | S5 |
| C2 | S6 (AC-S6-1) |
| C3 | S6 (AC-S6-2 measures it). Dropped: improving Kev on live_shaped (model/prompt work; the issue lists only the measurement problem) |
| C4 | S6 (AC-S6-4 measures it). Dropped: stabilizing severity (speculative; OD-9) |
| C5 | S6 (AC-S6-2, accepted-share on safe cases) |
| C6 | S6 (AC-S6-3) |
| C7 | S5 (AC-S5-2 agreement metric) |
| D1 | dropped: adding cases is expansion and conflicts with D5 (OD-11) |
| D2 | dropped: meaningful only given A9, out of scope (DEC-2) |
| D3 | S7 (AC-S7-1) |
| D4 | S7 (AC-S7-2) |
| D5 | not a story; constrains how S1-S3 are validated (OD-11) |

Dropped as speculative: new real-world cases, repeated-run variance, Kev retraining, severity stabilization, agent-side auto-labeling of candidates.

## Observed vs assumed
- Observed: `grounded_in_pr` exists at base 7f642e1 on `EvidenceItem` (`src/lgtm/agents/base.py`) and is rendered in `src/lgtm/reporting/report_builder.py`. The intake saw no such field only because it read the checked-out branch.
- Not verified: all cluster numbers (job 337363 outputs are not in the repo). Case-named criteria (AC-S1-1, S1-2, S3-2, S3-3, S3-5) assume the cited outcomes reproduce at the base; the build confirms.
- Case-named criteria need Integration-tier runs (Ollama, Semgrep). Structural criteria (S2-3, S4-1, S5-1, S7-1..3) are provable at lower tiers.

## Open decisions

OD-1 What does "PR-scoped" exclude? Blocks S3.
- (a) A finding must cite a changed or removed line, or explain how the change newly exposes the code. (b) Changed lines only. (c) Anything in the repo allowed, but unchanged-code findings capped at `possible`.
- Recommend (a): (b) loses deletion bugs, (c) keeps A6 alarms as warnings.

OD-2 Is `alerta_sqli_vulnerable` an S1 target? Semgrep gives no warning on it (B1), yet it is the A2 example. (a) Keep as an S1 behavior target but outside headline metrics. (b) Use only `aegra_authz_vulnerable`. Recommend (a). Does not block S2-S7.

OD-3 Budget and context sizes. Blocks the numeric parts of S2.
- (a) Raise tool calls 5 to 10, steps 8 to 16, read cap 200 to 400, plus enclosing function. (b) Keep limits; add enclosing function and report limit hits. (c) Only make them configurable.
- Recommend (b), then (a) only if AC-S2-4 still fails. Avoids cost growth without evidence.

OD-4 How is the policy-mode check (A8) run without tuning on the held-out set? (a) One check run on real-world, not a tuning target. (b) Shoply policy cases only. Recommend (a), under OD-11 (a).

OD-5 Which cases count as out of LGTM scope? (a) SQLi cases with no in-diff Semgrep warning on either side (the B1 list). (b) Also vulnerable cases Semgrep misses (the other 4 of B4). (c) Change the 3 Shoply safe cases so Semgrep warns, as the README says they do. Recommend (a) for real-world and (c) for Shoply. Does not block S1-S3.

OD-6 `lgtm-no-sast` handling. (a) Report SQLi rows as out of scope, keep authz rows. (b) Remove the mode. (c) Document only. Recommend (a); (b) breaks CON-3.

OD-7 How to count a candidate Kev rates supported but `not_real`. (a) Not a reported vulnerability; verdict governs score and exit code. (b) Keep current behavior and report verdict separately. Recommend (a). Blocks AC-S5-3 and S5-4; changes `lgtm review` exit codes, to be documented in the README (CON-3).

OD-8 Where do candidate labels come from? (a) Human labels by the team in the existing labels file. (b) Derive from case ground truth (safe case means not_real), partial. (c) Model draft, human confirmed. Recommend (b) for safe-case candidates plus (a) for real-world vulnerable ones. Needs human time. Blocks S6.

OD-9 Severity (C4): measure only, or also reduce option-order sensitivity? Recommend measure only; stabilizing is a later slice.

OD-10 Off-category findings (D4): (a) report only, no scoring change. (b) Count as FP. Recommend (a).

OD-11 D5: may S1-S3 be tuned against the held-out real-world set? (a) No: tune on Shoply dev, run real-world once as a check. (b) Retire the held-out label. (c) Build a new held-out set (D1 expansion). Recommend (a). The aegra, alerta and litellm criteria then act as checks, not tuning targets. User confirmation needed.

## Hand-offs
- Architecture: S5 and S6 depend only on Kev judge code present at the base (`src/lgtm/validation/judge.py`, `benchmark/judge_eval.py`). S1-S3 touch reviewer and pipeline. S4 and S7 both touch `benchmark/evaluate.py`, so they are not separable without a cut decision.
- Not verified: the current per-case result schema and whether `call_log` reaches it (intake D3 left this open).

Skipped: reading code beyond the base-commit checks above. Risk: case-named criteria depend on unverified cluster numbers.
