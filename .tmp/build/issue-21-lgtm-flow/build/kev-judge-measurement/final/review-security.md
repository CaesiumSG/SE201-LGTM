# Security review: kev-judge-measurement (efc85996..f18272b7)

Result: no Critical or High. 1 Medium, 1 Low. Static review only; no code run.

## Findings

### SEC-1 Medium: PR-controlled text can steer Kev to `not_real` and now suppresses the CI gate
- Location: src/lgtm/cli.py (supported count, exit code 1 rule), src/lgtm/reporting/report_builder.py (_support_label), via src/lgtm/validation/judge.py build_judge_request.
- Scenario: the judge state contains the cited code read from the PR (attacker-controlled) and the agent's claim. A PR author can add a comment or string next to a vulnerable line that instructs the judge to answer `not_real`. Before this change a supported candidate always exited 1. Now a `not_real` verdict alone drops the exit code to 0 (or 2), and the report relabels the finding "not real" (yellow) and omits the suggested fix.
- Existing protections: DEC-7 makes this an approved business rule. The candidate is still listed in report.md and report.json (stats.not_real), and the console summary is computed separately. No input sanitisation or injection guard exists in the judge request. Kev accuracy on real candidates is not yet measured (S6 real-world parts are INTEGRATE-only).
- Impact: a gating finding can be silenced by judge error or injection. Integrity of the CI gate, limited to candidates the agents already raised.
- Smallest fix: keep the rule, but make the suppression visible to CI: print and log the count of suppressed `not_real` candidates, and write `kev_verdict` into report.json (the field is `exclude=True`, so a reader cannot audit why a supported finding did not gate). Optional: an opt-in strict flag to ignore `not_real`. Decision needed: whether to accept the injection residual risk until INTEGRATE measures Kev.

### SEC-2 Low: `verdict == "vulnerable"` baseline findings are also suppressed by `kev_verdict`
- cli.py: the `kev_verdict != "not_real"` guard wraps the OR, so a baseline-mode finding (`verdict == "vulnerable"`, supported None) with a stored `not_real` is dropped too. In practice kev_verdict is only set by the judge on judged findings, so reachability is probably narrow. Scope the guard to the `supported is True` branch if the baseline gate must be unaffected by the judge.

## Checked, no defect
- benchmark/evaluate.py finding_verdict: scoring-only change; no security boundary.
- judge.py: verdict only compared to the literal "not_real"; unknown strings do not suppress. Invalid answers raise and leave the finding not judged (exit 2 path kept). Not-judged failures do not suppress.
- README and CLI help document the exit code change (CON-3). No new dependencies (CON-2). No secrets or personal data in kev_model_labels.json or docs (skimmed by diffstat/names only; contents not read line by line).

## Limitations
Did not read the package reports or the label file contents in depth; no tests run. Throwaway dir tmp/security not created, nothing to clean.
