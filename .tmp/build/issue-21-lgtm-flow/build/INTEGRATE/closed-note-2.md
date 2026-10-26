Build closed: INTEGRATE - blocked (environment)

Branch: build/issue-21-lgtm-flow/INTEGRATE
Head: acfb780225ebbdd1f59dc40d3e01f4a0cad3b3c2 (unsquashed; unchanged since the previous attempt)
Integration base: bad831d99fbf91dcbed703625ce4ef4e81cef791 (origin/main, 0 new upstream commits)

Blocker: no model endpoint (Ollama localhost:11434 or GPU tunnel 127.0.0.1:11435) and no Kev judge server (127.0.0.1:8008) answered on resume (connection refused on all three). Starting them needs the remote GPU cluster, outside the repository, so E2E journeys 1-4 did not run and the branch was not squashed.

Evidence: all four feature slices accepted at their published heads and merged. The previous attempt's full pytest suite, existing-command checks, hygiene check, lens reviews and final review (with re-reviews) are recorded on the slice build; the final review accepted. Unproven until the live journeys run: AC-S1-1, AC-S1-2, AC-S2-4, AC-S3-2 (litellm), AC-S3-3, AC-S3-5, AC-S3-6, AC-S3-7, AC-S4-3, AC-S4-5, AC-S6-1, AC-S6-2, AC-S6-6.

Needs replan:
- AC-S1-2: restate as "alerta_sqli_vulnerable is reviewed (deletion-dominated diff, sections not empty) and its outcome is reported as an out-of-scope measurement", or drop it. Touches INTEGRATE journey 2 only.
- Story S1 business rules: after "Removed lines are valid evidence for a finding about removed behavior" add "and the judge and the judge-eval export are shown the removed code they cite".
- INTEGRATE whole-feature checks: add "README documents every changed exit code, including evaluate_real exit 4" (already done on the branch).
- INTEGRATE journey 4: add "citation_export reads null-snapshot citations by the same content-at-cited-lines rule as the production judge read."

Summary: the integrated feature is merged, reviewed and passing its offline checks, but its live-model criteria remain unproven. Start the model endpoint and the Kev judge server, then rebuild INTEGRATE to run journeys 1-4 and squash.

Reference: issue-21-lgtm-flow/INTEGRATE-build-closed-2
