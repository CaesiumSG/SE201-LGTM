# repair-1-tests (Unit tier)

Note: triage-merge-2.md did not exist; G3/G5/G6 identified from the assignment and failing tests.

## Changes
- G3 (tests/test_baselines.py): removed rows ("possible_vulnerability","FN","TN") and ("insufficient_evidence","FN","TN") from TestOutcomeTable.test_outcome_by_label_and_expectation (judged modes only; labels cannot occur there; 4 cases failed with duplicate `mode` kwarg). Vulnerable-side FN still asserted by test_baseline_only_labels_score_as_before.
- G5 (tests/test_graph_tools.py): FORCED_MARK = registry.entry("shared.forced_final") (import `from lgtm.agents import registry`); was the stale literal "final JSON verdict NOW".
- G6 (tests/test_mitigation_defaults.py): _invoke sets run.return_value.meta.agent_errors = []; the CLI exits 2 on truthy meta.agent_errors, so the MagicMock attribute forced exit 2.
- Follow-up decision (round-2 rule: every non-error row scored; possible/insufficient_evidence on safe rows = TN; no plan criterion requires UNCREDITED, which came from 22a3b0f): test_baseline_only_labels_score_as_before safe-side UNCREDITED -> TN for both labels (vulnerable side stays FN). tests/test_baselines.py lines 1601-1602. No other UNCREDITED in the file.

## Results
- tests/test_baselines.py: 253 passed.
- Earlier three-file run (before the UNCREDITED update): 5 failed, 573 passed; the 2 baselines failures were the UNCREDITED ones, now fixed.
- Remaining, not touched (developer investigating): tests/test_graph_tools.py
  - TestFailedCallsSpendSlots::test_five_failed_text_calls_then_the_loop_stops_without_backend[authz_reviewer]
  - TestRejectedAttemptAfterBudgetIsSpent::test_text_sixth_attempt_is_never_taken[authz_reviewer-unknown_name]
  - TestRejectedAttemptAfterBudgetIsSpent::test_text_sixth_attempt_is_never_taken[authz_reviewer-missing_argument]
  Cause: forced-final prompt matches, but llm.channels is [bound x5, unbound, bound]; the scripted forced-final reply is a text tool call (invalid JSON), so request_valid_answer re-asks on the bound LLM and `"bound" not in channels[n:]` fails.

## Not run
Lint, format, type checks, full suite. No production changes. No assertion weakened.
