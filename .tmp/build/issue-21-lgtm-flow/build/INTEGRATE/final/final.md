# Final review: INTEGRATE (bad831d..bf63915)

Verdict: ACTION. 1 High, 3 Medium (two extend items already in review reports), plan corrections below.

Acceptance criteria checked (static or by unit evidence): AC-S2-1/2/3/5, AC-S3-1 (prompt rule), AC-S3-4, AC-S4-1..7 (logic), AC-S5-1..4, AC-S6-1..5 (logic), AC-S7-1..3, CT-reviewer-reach-1, CT-benchmark-scope-trace-1, CON-1..3. Live-model criteria (slices/INTEGRATE.md "Criteria proved here only") not run, per assignment; reviewed only for code that would make those journeys fail or mis-measure.

## Findings

### final-01 High (reproduced): removed-line evidence reaches Kev as PR-snapshot code
- Location: src/lgtm/validation/evidence.py read_cited_code (unlabelled item: tries "pr" then "base", and stops at the first file that exists); same rule in benchmark/citation_export.py export_run/_read_lines (null snapshot reads PR head). Input to src/lgtm/validation/judge.py build_judge_request, which sends only code read by location, never the quoted content from the agent.
- Trigger: a deletion finding whose code evidence quotes removed lines with base line numbers and no snapshot label. The authz evidence schema in src/lgtm/agents/prompts.toml has no snapshot field, and read_file defaults to "base", so this is the normal shape of a deletion citation. Repro (throwaway repo; base has the owner check "if thread.owner_id != user.id: raise Forbidden()" at lines 3-4, PR deletes it; finding cites app.py lines 3-4 unlabelled):
  - resolves: True; grounded_in_pr: True (AC-S3-4 holds at validation)
  - read_cited_code returns the PR line "    return thread" plus a blank line
  - Judge state: "Cited item: app.py:3-4 at unlabelled snapshot" followed by "return thread"
- Expected: S1 business rule "Removed lines are valid evidence for a finding about removed behavior", and AC-S3-4 says removed-line evidence is not rejected. Kev should see the removed check.
- Actual: Kev is shown unrelated PR code (or nothing, when the base lines fall past the end of the PR file). In lgtm/lgtm-no-sast, scoring (finding_verdict) and the CLI exit code rest on the supported answer from Kev. So a correct deletion finding is likely to score unsupported. Journeys 1 and 2 (AC-S1-1 aegra, AC-S2-4) and the journey 4 labels (export uses the same PR-first rule) would mis-measure the reviewer changes. Unchanged code cited with base line numbers after PR line shifts is hit the same way. The code predates the feature base (7f642e1), but this branch brings it to main, and this is the deletion-evidence interaction named in the INTEGRATE risks.
- Smallest correction: for an unlabelled item, read from the first snapshot (pr, then base) where _validate_code_item on a copy labelled with that snapshot has no issues, the same test resolves() uses. Fall back to the current behavior. Apply the same choice in citation_export, or record the chosen label on the item at validation. Add one unit test built from the repro above. Alternative: add a snapshot field (base or pr) to the evidence schemas, which changes the model-input lock and still depends on the model.

### final-02 Medium (inspected; extends outstanding behavior-01): injection finding vs README exit-code rule
- src/lgtm/cli.py:139-141 counts f.verdict == "vulnerable" in every mode. The injection_detector finding (sanitizer.py:183) carries verdict "vulnerable", so in lgtm mode it sets exit 1 even when Kev rules it unsupported. README.md:114-119 says exit 1 in a judged mode needs a supported candidate; the baseline-verdict clause is for baseline modes only. evaluate.py and run_injection_bench score the same finding as safe. I agree with behavior-01 and add that the merged code contradicts the documented exit-code rule (CON-3).
- Recommend: resolve before merge. Either append injection findings after judge_candidates and mark them supported, or limit the verdict clause in cli.py to baseline modes and update the README. Add one test.

### final-03 Medium (inspected; from checks-hygiene, not in log.md outstanding): evaluate_real exit code 4 undocumented
- benchmark/real_world/evaluate_real.py:522/538 "return 4 if aborted else 0". It comes from the kev-validation line (3cfb6f5) and is new to main through this branch. No README mentions it (CON-3).
- Recommend: resolve by adding one line to benchmark/real_world/README.md.

### final-04 Medium (inspected): meta.endpoints_reviewed decision (open item)
- No acceptance criterion or slice outcome requires removing it. The reviewer-reach Outcome and the AC-S2 criteria do not mention endpoint counts, and CON-3 favors keeping existing outputs. Keeping the field as on main is correct.
- Recommend: resolve by recording a log.md Decision: meta.endpoints_reviewed kept as on main; no criterion removes it. No code change.

## Cross-slice checks with no defect found
- Prompt rules: the enclosing-definitions block (with comment stripping when strip_comments is on) and the PR-scope rule (cites a changed or removed line) agree. Removed-line grounding in _grounds_pr covers labelled-base and unlabelled items, and answer_until_resolved accepts removed-line items because they resolve at base. The judge read path is the gap (final-01).
- kev runner vs evidence.py: signatures match (checks-pending), and pr-scoped-review changed only _grounds_pr.
- evaluate.py scope/off-category/not_real: the writers (evaluate_case, evaluate_real run_unit/error_result) all go through score_case/scope_fields. finding_verdict applies not_real. summarize applies headline filtering to overall, grounded_only, per_category and per_split, and drops not-judged rows. Real-world rows carry pin and mode, so they read as judged.
- DEC-14: in a fresh --output, every row is written by score_case with case_scope from cases.json (alerta pair and postgraas_sqli_safe are out). write_run_manifest checks only under --resume. Fresh journey 2 output will carry the right scope.
- Journey 4 inputs: fresh runs from journeys 2 and 3 record mode, so the run6-final mode gap (kev final-01) does not affect them. One run dir and labels file per invocation, because unit ids collide across the lgtm and lgtm-policy dirs.
- Behavior lost from main: the PR-graph grounding cap from main (PR_GROUNDING_CAP_MARKER) was already removed on the feature base 7f642e1, so the merge did not drop it. No other main behavior found lost beyond the logged decisions.
- README coherence: scope section, mitigation flags and exit-code text agree with the code, apart from final-02. benchmark README UNCREDITED/EXCLUDED rows are stale (common-sense-01, outstanding).
- CON-1 ok; CON-2 ok (no dependency diff); CON-3 ok apart from final-02 and final-03.

## Plan check
- Contradiction (needs-replan, INTEGRATE only): AC-S1-2 asks lgtm mode to yield a finding about string-built SQL on alerta_sqli_vulnerable. In lgtm mode, SQL findings come only from Semgrep triage (pipeline.py:483). The authz reviewer forces category authz with authz CWEs (authz_reviewer.py:324; prompt schema). S4 marks the alerta pair out of scope because Semgrep does not warn on either side. So AC-S1-2 cannot pass by design, and any authz-category SQL finding would count as off-category. Change: restate AC-S1-2 as "alerta_sqli_vulnerable is reviewed (deletion-dominated diff, sections not empty) and its outcome is reported as an out-of-scope measurement", or drop it. Touches INTEGRATE journey 2 only.
- Gap (minor): stories.md S1 business rules, after "Removed lines are valid evidence for a finding about removed behavior". Add "and the judge is shown the removed code they cite". Without it, AC-S3-4 can pass while the judge sees other code (final-01).
- minor: slices/INTEGRATE.md Whole-feature checks. Add "README documents every changed exit code, including evaluate_real exit 4" (final-03).
- External claims: the intake claim that Semgrep raises no warning on either alerta side is unverified here.

## Coverage
Axes: correctness (judge input path, scope and scoring writers and readers, CLI exit rule), architecture (shared rules), compatibility (CON-1..3), lost main behavior. Ran one throwaway reproduction (final-01) with the worktree venv in a temp repo under tmp/final. Not run: full pytest (checks-full-suite and checks-repair passed before the final repair commit), live journeys, Semgrep. Limits: the time budget allowed only static reading of judge_eval and the real-world writers. Cleanup: tmp/final removed and verified absent. Worktree status clean.
