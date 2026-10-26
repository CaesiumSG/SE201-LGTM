# Assess stories: replan 1 (kev-judge-measurement, INTEGRATE)

Scope: slices/kev-judge-measurement.md, slices/INTEGRATE.md against plan/objective.md, plan/stories.md, DEC-13, DEC-14, replan-1.md. Read-only; no plan files edited.

## Verdict

Coverage of objective outcomes holds except one gap (assess-stories-01). One ambiguity can contradict AC-S4-7 (assess-stories-02). No scope beyond the objective. DEC-14 and INTEGRATE agree. Findings: 1 High, 1 Medium, 3 Low.

## Check 1: objective outcomes still covered

* Kev judge (C1-C7): S5 (AC-S5-1..4) stays whole in kev-judge-measurement; not affected by the exclusion (metrics are label-based, counting rule applies to every candidate).
* Measurement of Kev on real output (S6, D-items): AC-S6-1/S6-2 Shoply part now proven on remaining stored candidates plus fixtures; the three excluded candidates move to INTEGRATE journey 4. This is where the gap is (01).
* Benchmark honesty (B-items) via DEC-14: journey 2 fresh output dir delivers AC-S4-3 and AC-S4-5 real-world parts. Covered.

## Findings

### assess-stories-01 (High, owner: slices/INTEGRATE.md)
Journey 4 does not reach two of the three excluded candidates. Journey 4 labels "candidates from journeys 2 and 3"; journey 3 runs `evaluate.py --mode lgtm --split dev`. In benchmark/labels.json `sqli_07_safe` is split "dev", but `sqli_04_safe` and `sqli_11_safe` are split "eval". Their candidates are produced by neither journey, so DEC-13's "INTEGRATE labels them in journey 4" cannot happen as written, and the Shoply safe-case Kev acceptance share (AC-S6-2) would lack the SQL-injection safe cases it matters most for.
Recommend: journey 4 (or journey 3) also runs lgtm on `sqli_04_safe` and `sqli_11_safe` (for example `--cases` or `--split all`), as a measurement after the final Shoply change. Minor plan edit inside INTEGRATE.

### assess-stories-02 (Medium, owner: slices/kev-judge-measurement.md)
"Not labeled and not scored" (Rules) and DEC-13 "left out of kev scoring" are not bounded. A reader can take "scored" to mean removed from benchmark scoring, which contradicts AC-S4-7 and DEC-11 (sqli_04/07/11_safe stay in headline metrics) and the AC-S5-3 counting rule. Replan-1 R-1 concerns only the stale citations.
Recommend: say the exclusion applies to labeling and the judge-eval accuracy/agreement numbers only, and the cases stay in benchmark scoring and headline metrics.

### assess-stories-03 (Low, owner: slices/INTEGRATE.md)
Journey 4's criteria line lists only "real-world parts of AC-S6-1 and AC-S6-2", and "Criteria proved here only" has the same wording. The Shoply remainder (labels for the three excluded cases) is now INTEGRATE's, stated only in the risks bullet. Add it to journey 4 so the obligation is cited by a journey, not just a risk.

### assess-stories-04 (Low, owner: slices/kev-judge-measurement.md)
Rules says the report "lists them as excluded"; DEC-13 says "reported as stale with the reason". Align the wording (state the reason: citations predate regenerated patches). Also "(CT-benchmark-scope-trace-1 slice, Regenerated)" mixes a contract id with the slice's Regenerated field; the three patches are not in the contract. Cite the slice benchmark-scope-trace, Regenerated.

### assess-stories-05 (Low, owner: slices/INTEGRATE.md and plan/stories.md)
(a) Journey 2 forbids `--resume` "on stored runs"; a crash retry inside the fresh directory is unaddressed against "run once" (DEC-9). State that resume inside the fresh directory is allowed, or not.
(b) plan/stories.md header cites DEC-1..DEC-12 and S6 says nothing of the stale exclusion. No criterion changes, so a one-line note or a plan/changes.md entry suffices; DEC-13/DEC-14 are the record.

## Check 2: beyond the objective

None found. The exclusion rule and DEC-14 known issue trace to objective items C1-C7/D and B1-B4 and add no new story, criterion or file. The Rules obligation (not editing run6-final, benchmark/cases) restates Scope; keep or drop, no scope growth.

## Check 3: contradictions

* Slice Scope (Consumes, Resources: run6-final read only), Rules, DEC-13 and replan-1 agree on no writes outside Scope.
* INTEGRATE journey 2, known-issue bullet, DEC-14 and CT-benchmark-scope-trace-1 agree: contract unchanged, stored runs not used for AC-S4-3/S4-5.
* Contradictions found: 01 (journey reach vs DEC-13 promise), 02 (possible reading vs AC-S4-7).

Skipped: did not re-verify benchmark-scope-trace code or other slices; did not open the live run files.
