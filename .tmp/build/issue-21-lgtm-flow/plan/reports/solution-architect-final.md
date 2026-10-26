# solution-architect: final Scope fixes

- ready-01 and ready-04: parentheticals deleted from reviewer-reach Modifies (provenance.py) and pr-scoped-review Modifies (evidence.py, git_diff.py).
- benchmark-scope-trace Resources: model-endpoint entry removed; Semgrep (isolate) named for AC-S4-7.
- kev-judge-measurement Creates: now "a labeling-criteria document under docs/; the stored label file under benchmark/" (the builder names the files). Resources rewritten to Kev server (simulate) and the stored run6-final lgtm run (read only); the duplicate held-out text stays in Out of scope only.
- Model endpoint re-derived: with all live-model checks INTEGRATE-only, no feature slice uses it. Strategy changed from serialize to defer, slices = INTEGRATE. reviewer-reach and pr-scoped-review Resources now say tests use fake models. Semgrep: benchmark-scope-trace, INTEGRATE. benchmark/runs: benchmark-scope-trace, INTEGRATE. INTEGRATE.md lease-wait risk replaced with "only INTEGRATE runs live models".
- Left for the technical planner: Checks or Setup that still name a live Shoply run or the llm-endpoint lease in reviewer-reach, pr-scoped-review, benchmark-scope-trace.
