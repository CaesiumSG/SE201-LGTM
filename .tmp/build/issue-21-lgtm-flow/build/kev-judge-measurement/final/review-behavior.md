# Behavior review: kev-judge-measurement (efc85996..f18272b7)

## Findings

### B-1 (High, inspected) Verdict labels are the case ground truth, so verdict accuracy and verdict-vs-agent numbers are circular
- File: benchmark/kev_model_labels.json (all 73 units); docs/kev-labeling-criteria.md.
- Source: DEC-8 and S6 rule ("labels come from a stronger model against documented criteria"); AC-S6-5. edit.md states labels came "from the claim, the cited quote and the case's known vulnerable/safe status".
- Actual: every unit in a `*_safe` case is `verdict: not_real`, and every `real` unit is in a `*_vulnerable` case. Severity is a case-level default ("high elsewhere", critical/medium for two cases). `supports` was set from the claim and case status, not from a documented-criteria read of each cited item. Multi-item findings share the finding's label, so items were not judged individually (criteria define a unit as one cited code item). Three units (sqli_05_safe/1.0, sqli_06_safe/0.0, sqli_08_safe/0.0) were labeled without reading the quote in full.
- Consequence: `kev_accuracy.verdict` is just "does Kev agree with the case label", and `safe_case_acceptance` and `kev_agreement.verdict_vs_agent` are not independent of it. The criteria document defines `not_real` as "supported but guarded or not a vulnerability", yet no label shows that judgment. It is not evidence Kev was measured under the criteria, and AC-S6-1/AC-S6-2 numbers (labeled-example count, supported accuracy by kind) would be reported as model-labeled when they are really ground-truth-derived.
- Correction: relabel each unit from the cited code and claim alone, blind to case status, then compare. Or report the labels as case-derived and drop the "model-labeled" claim. Needs a decision from the orchestrator.

### B-2 (Medium, inspected) Labeling model differs from the decision
- `labeling_model` is `claude-sonnet-5-5`; DEC-8 and S6 name Claude Opus 5.5 ("a stronger model"). The report would state the wrong model relative to the agreed intent. Either confirm the substitution as a decision or relabel with the agreed model. Not invented here: the decision belongs to the user.

### B-3 (Medium, inspected) AC-S6-3 cannot be demonstrated by this slice's data; quote_absence logic is untested on real input
- authz_10_vulnerable and authz_12_vulnerable are absent from run6-final, so `quote_absence` returns `[]`. The report would not state absence or cause. This is an acknowledged limitation (INTEGRATE); an empty list should be distinguishable from "checked, nothing absent" (no "case not in run" row). Also, the quote check is an exact substring match (`content in text`), so whitespace or indentation differences classify as `agent_quote`. This is a low-confidence classification risk.

### B-4 (Low, inspected) Housekeeping
- edit.md reports a stray `benchmark/README_append.tmp` created by the editor; `git status` in the worktree showed no untracked file at review time, so it appears already removed. The README lines in benchmark/README.md for the gating sentence are on one long line (cosmetic).

## Checked and fine
- Exit code (src/lgtm/cli.py): supported-and-not_real no longer counts; baseline modes (kev_verdict None) unchanged; an unsupported finding with agent verdict vulnerable and kev_verdict not_real also stops counting, consistent with DEC-7. README and CLI help match (AC-S5-4, CON-3 documented in-place; approved README scope additions are in place).
- Report builder: supported+not_real labeled "not real", counted in new additive `stats.not_real`, excluded from `stats.supported`, no suggested fix. Existing keys keep names (CON-3).
- evaluate.finding_verdict: not_real maps to safe, so authz_09_safe-type candidates are not false alarms; derive/predict paths go through it. `grounded` metrics still count `supported` only, a deliberate separate support measure.
- judge_eval metrics: supported accuracy, verdict accuracy, severity accuracy as separate tallies (AC-S5-1, AC-S6-4); disagreement and agent-equality rates (AC-S5-2); empty agent verdicts excluded.
- DEC-13 stale handling: sqli_04/07/11_safe are excluded from kev_accuracy, kev_agreement, supported_by_kind and safe_case_acceptance via `_labelled_judged`/`kev_agreement`; they have no labels (the `labels.n` count excludes them); `stale` lists them with the reason only when present in the outcomes; benchmark scoring (`evaluate.py`, `kev_report`) keeps them (AC-S4-7, DEC-11). Note `sqli_*_vulnerable` labels for sqli_04/07/11 do exist and are included; correct per DEC-13 (only the safe candidates are stale).
- Real-world parts: `labels.origins`, `safe_case_acceptance.real_world` return `n=0`, share None (no divide-by-zero); INTEGRATE-owned.

## Coverage
Inspected the diff, labels, criteria doc, edit.md, stories, and decisions, plus evaluate.py consumers of `supported`. Tests could not run: the environment lacks `langchain_core` (collection errors in test_cli.py and test_e2e_review_judge.py; 120 errors, 96 passed in test_judge_eval/test_report). No tmp resources created; the `tmp/behavior/` folder was not made.
