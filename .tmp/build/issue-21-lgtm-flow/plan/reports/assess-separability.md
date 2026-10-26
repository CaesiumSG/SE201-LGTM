# Assess: separability (issue-21-lgtm-flow, base 7f642e1)

Verdict: CLEAN. 0 Critical, 0 High, 3 Medium, 3 Low.

## Concurrent pairs
Prerequisite graph: reviewer-reach -> {pr-scoped-review, benchmark-scope-trace}; benchmark-scope-trace -> kev-judge-measurement.
Concurrent pairs (no path): pr-scoped-review x benchmark-scope-trace; pr-scoped-review x kev-judge-measurement. All other pairs are on a path.

| Pair | Owns/Creates/Modifies/Deletes | Appends | Result |
| --- | --- | --- | --- |
| pr-scoped-review x benchmark-scope-trace | Disjoint (src/lgtm/validation/evidence.py, diff/git_diff.py, agents/ and 5 tests vs benchmark/, docs, READMEs and 5 tests) | expected.json only in pr-scoped-review | Pass |
| pr-scoped-review x kev-judge-measurement | Disjoint by file (evidence.py, git_diff.py, authz_reviewer.py, prompts.toml vs judge.py, cli.py, report_builder.py, benchmark/*); kev Creates are new files | expected.json in both (allowed) | Pass with notes (sep-02, sep-03) |

Symbol-level impact (CodeGraph):
- EvidenceValidator (src/lgtm/validation/evidence.py) callers: src/lgtm/pipeline.py, benchmark/kev_support/runner.py (kev Modifies); tests test_validation, test_graph_evidence, test_graph_pipeline, test_judge, test_kev_confidence, test_pipeline_request_format, test_dedup.
- judge.py imports only agents/base.py, config.py, cwe_criteria.py, judge_examples.py; it does not import evidence.py or git_diff.py.
- report_builder.py renders ev.grounded_in_pr (base line ~185); the field is declared in src/lgtm/agents/base.py at base. reviewer-reach modifies base.py and is a prerequisite of both.

## Consumes check (base 7f642e1 or prerequisite Provides)
All present. CT-reviewer-reach-1 is in reviewer-reach Provides; CT-benchmark-scope-trace-1 is in benchmark-scope-trace Provides. At base (git ls-tree): cwe_criteria.py, judge_examples.py (tracked at base, untracked only in the checkout), pipeline.py, report_builder.py, EvidenceItem and AgentFinding in base.py, grounded_in_pr on EvidenceItem, and every Modifies/Regenerated file listed in the slices. No missing Consumes entry.

## Resource mapping (real mapping, replacing the recorder default of all resources on all slices)

| Resource | Strategy | Real slices |
| --- | --- | --- |
| Model endpoint | serialize (llm-endpoint) | reviewer-reach (Shoply dev), pr-scoped-review (evaluate.py --split dev), benchmark-scope-trace (3-case Shoply replay), kev-judge-measurement (Setup live run; dropped if sep-01 accepted), INTEGRATE |
| Kev judge HTTP server (tests) | simulate | kev-judge-measurement, INTEGRATE |
| Kev judge server (live) | defer | INTEGRATE |
| Semgrep binary | isolate | benchmark-scope-trace (AC-S4-7) and any slice running evaluate.py --mode lgtm live: reviewer-reach, pr-scoped-review, INTEGRATE (kev only via the live Setup run) |
| CodeGraph index | isolate | all slices (default Setup) |
| benchmark/runs/ and results output | isolate | reviewer-reach, pr-scoped-review, benchmark-scope-trace, INTEGRATE (kev only via live Setup run or judge-eval output) |
| Real-world repositories | defer | INTEGRATE |
| tests/model_input_lock/expected.json | isolate | reviewer-reach, pr-scoped-review, kev-judge-measurement, INTEGRATE (not benchmark-scope-trace) |
| Git refs main, kev-validation | forbid | no feature slice touches them |

Contention: the model endpoint is the only non-isolate resource used by concurrent slices (pr-scoped-review with benchmark-scope-trace, pr-scoped-review with kev-judge-measurement). It is serialize with a lease, so the rules hold; see sep-01 and sep-06.

## Findings

### sep-01 Medium: kev-judge-measurement Setup live lgtm run is not needed
Base already holds Shoply candidates: benchmark/runs/run6-final/lgtm/ (36 per-case JSONs; each finding has verdict, evidence, evidence_valid). It is the only Shoply lgtm run at base (gpu-qwen3.8-27b/ holds real-world only). judge_eval.py and citation_export.py take a run directory plus a labels file, so a stored run feeds labeling directly. Real-world stored runs (gpu-qwen3.8-27b/real_world/lgtm*, real_world/) exist but are held out (DEC-9), and INTEGRATE journey 4 relabels integrated-reviewer output anyway. The live run adds a third lease user, a Semgrep and results-directory use, and a lease-held failure mode, and its output is superseded in INTEGRATE.
Fix: replace Setup with: Shoply candidates come from the stored lgtm run under benchmark/runs/ (run6-final/lgtm); no live model run. Remove the Model endpoint line from kev Resources and run.json; reword the INTEGRATE pre-merge reviewer labeling risk to stored run6-final output. State that run6-final predates the reviewer changes, so label counts reflect older reviewer output.

### sep-02 Medium: pr-scoped-review Consumes report_builder.py unchanged while kev-judge-measurement Modifies it
Concurrent slices; the Consumes entry names a file the other edits, and the plan does not say the grounded_in_pr rendering is left alone.
Fix: add to kev-judge-measurement Out of scope or Consumes: the grounded_in_pr evidence-location rendering in report_builder.py stays as at base.

### sep-03 Medium: kev-judge-measurement depends on EvidenceValidator and FileDiff surfaces that pr-scoped-review changes concurrently
benchmark/kev_support/runner.py (kev Modifies) and tests test_judge.py, test_kev_support_bench.py use EvidenceValidator; pr-scoped-review changes grounding in evidence.py and FileDiff in git_diff.py. No file overlap, but no statement that the call surface stays stable.
Fix: add to kev-judge-measurement Consumes: EvidenceValidator.validate/validate_all signatures and FileDiff fields at base. Add to pr-scoped-review Scope: validator and FileDiff signatures keep their base shape (additive removed-text access only). Name tests/test_kev_confidence.py and tests/test_pipeline_request_format.py (use EvidenceValidator, in no slice Modifies) as INTEGRATE regression targets.

### sep-04 Low: run.json resources mapping is wrong
The recorder put every non-defer resource on all slices, including benchmark-scope-trace for expected.json, reviewer-reach, pr-scoped-review and benchmark-scope-trace for the Kev judge server (tests), and the forbid refs on every slice.
Fix: set slices per the table above. Add a Slices column to the architecture.md Resources table so the recorder does not guess.

### sep-05 Low: expected.json is a generated snapshot listed under Appends
Three slices touch it (pr-scoped-review and kev concurrently); INTEGRATE regenerates it once, so keep-both merging is meaningless.
Fix: list it under Regenerated in reviewer-reach, pr-scoped-review and kev-judge-measurement; keep the INTEGRATE regenerate-once note.

### sep-06 Low: INTEGRATE.md risk wording and lease wait
It lists reviewer-reach and pr-scoped-review editing prompts.toml, authz_reviewer.py and git_diff.py as an integration risk, but pr-scoped-review builds on the reviewer-reach branch, so these are sequential edits, not merge conflicts. Separately, the pr-scoped-review long --split dev run and the benchmark-scope-trace 3-case run share llm-endpoint; one bounded wait, then ACTION lease held.
Fix: reword the risk as behavioral interaction (re-run Shoply dev); give the pr-scoped-review dev run an explicit time budget so lease expiry is predictable.

## Other checks passed
- No slice exists only for parallelism: pr-scoped-review is split from reviewer-reach by outcome and evidence.py ownership; benchmark-scope-trace and kev-judge-measurement are separate outcomes with a real data dependence (CT-benchmark-scope-trace-1, evaluate.py).
- No Owns/Creates/Modifies/Deletes overlap between concurrent slices; no Modifies hits another slice Creates.

Not checked: code bodies (whether the kev report_builder.py edit touches the grounded_in_pr line; whether run6-final findings carry every field judge_eval needs).
