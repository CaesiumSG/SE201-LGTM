# Technical planner report: kev-judge-measurement

## Result
Packages, Checks, Setup written. One package (judge-measurement): the metrics, counting rule, exit-code rule, and judge-eval report share judge.py and the same rule, so the files are not independent.

## Tiers
All nine in-slice criteria are Unit (stored labels, fixtures, and fakes; Kev server simulated). AC-S6-6 and the real-world parts of AC-S6-1/AC-S6-2 are INTEGRATE-only per architecture and stay out of packages.

## Open decisions
None.

## Resource notes
- Architecture lists the model endpoint (serialize, lease llm-endpoint) and Kev server (simulate). A live Kev run to produce the Shoply judge-eval report is not listed. Recommendation: run it under the llm-endpoint lease in this slice, or defer to INTEGRATE. Consequence: deferring leaves AC-S6-1 Shoply number to INTEGRATE; running it adds one serialized live run.

## Scope corrections (hand-offs to solution architect)
- Scope Owns lists "the held-out rule for judge criteria" (AC-S6-6), which architecture assigns to INTEGRATE; consider moving it to the criteria document as text only, or dropping it from Owns.
- Scope "Appends" lists README.md and benchmark/README.md, also modified by benchmark-scope-trace; Appends may overlap, so no conflict.
- Provides of benchmark-scope-trace holds no contract; Consumes "scope labels and per-case results" has no CT- id.
