# solution-architect: assessment fixes

1. stories-02: AC-S1-1, S1-2, S2-4, S3-3, S3-5, S3-6, S3-7, S4-1, S4-2, S6-6 are cited only by INTEGRATE; removed from all slice citation lines. Split criteria AC-S3-2, S4-3, S4-5, S6-1, S6-2 stay in their slice for the part a package proves; INTEGRATE names only their real-world part. Journeys 1 to 4 now cite only INTEGRATE-only criteria (S2-3, S2-5, S4-6, S4-7, S5-x, S6-5, S7-x citations removed; no duplicate of journey 3).
2. AC-S1-3 removed from every citation line and scope text.
3. ready-03 / ready-06: AC-S3-3 and AC-S3-6 are INTEGRATE journey 3; benchmark-scope-trace live check is now INTEGRATE observation. Technical planner must delete the live Shoply dev check in pr-scoped-review Checks and the live 3-case check in benchmark-scope-trace Checks (or list them as pending integration), and drop AC-S3-3/S3-6 from the scope-rule package row.
4. sep-02 / sep-03: smallest form is a stability statement. pr-scoped-review Out of scope: report_builder.py, EvidenceValidator validate/validate_all signatures, and FileDiff fields (beyond additive removed-text access) stay as at base. kev-judge-measurement Consumes names the same surfaces at base. INTEGRATE lists test_kev_confidence.py and test_pipeline_request_format.py as regression targets.
5. sep-05: expected.json moved to Regenerated in reviewer-reach, pr-scoped-review, and kev-judge-measurement.
6. sep-04: architecture.md Resources table has a Slices column. sep-06: INTEGRATE risk reworded as behavioral; lease wait stated as one bounded wait then ACTION. sep-01 applied to Scope only: kev Resources drops the model endpoint and Consumes names the stored run6-final lgtm run.

## Hand-offs to the technical planner
- kev-judge-measurement Setup still describes a live lgtm run under the llm-endpoint lease; it contradicts the Scope and must be replaced by the stored run. Remove the model-endpoint use.
- benchmark-scope-trace package docs now has no criterion (AC-S4-1, S4-2 are INTEGRATE review). Its files stay in the slice; the technical planner decides how to present them (a package needs criteria, so possibly remove the docs package and keep the files in the benchmark package Production files with no criterion).
- Packages rows: remove AC-S1-3 where still present, and AC-S3-3/S3-6 from scope-rule; remove the parentheticals in pr-scoped-review Modifies (ready-04).
- Not changed by me: stories-01 (Definition of Done vs held-out rule) needs user confirmation.

Resource to slices: model endpoint = reviewer-reach, pr-scoped-review, INTEGRATE; Kev server (simulate) = kev-judge-measurement, INTEGRATE; Kev server (live, defer) = INTEGRATE; Semgrep = benchmark-scope-trace, reviewer-reach, pr-scoped-review, INTEGRATE; CodeGraph = all; benchmark/runs = reviewer-reach, pr-scoped-review, benchmark-scope-trace, INTEGRATE; real-world repos = INTEGRATE; expected.json = reviewer-reach, pr-scoped-review, kev-judge-measurement, INTEGRATE; git refs = none.
