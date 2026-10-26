# Structure review: kev-judge-measurement (efc85996..f18272b7)

Result: no High or Critical. 1 Medium, 2 Low.

## Medium

M1. The "supported but not_real is not a vulnerability" rule is written three times with different shapes.
- src/lgtm/cli.py (exit count): `f.kev_verdict != "not_real" and (f.supported is True or f.verdict == "vulnerable")`
- src/lgtm/reporting/report_builder.py `_support_label`: `supported and kev_verdict == "not_real"` gives "not real"
- benchmark/evaluate.py `finding_verdict`: `supported and kev_verdict != "not_real"` on dict findings
Consequence: the CLI exit code, the report counts, and benchmark scoring each own the rule. A change to it (for example a new verdict value) needs three coordinated edits and can drift, with the exit code disagreeing with the report. The CLI also applies the not_real exclusion to baseline `verdict == "vulnerable"` findings, which the report label path does not.
Smallest fix: a single predicate (for example a property on AgentFinding next to `kev_verdict`, e.g. `is_vulnerability`) used by cli.py and report_builder.py. benchmark/evaluate.py works on dicts, so it can keep its one-liner, but the README exit-code text should name one owner.

## Low

L1. Stale-case list repeated in code, label docs and READMEs.
- benchmark/judge_eval.py `STALE_CASES`, docs/kev-labeling-criteria.md "Stale candidates", benchmark/README.md `stale` bullet name the same three cases.
- The docs file is described as labeling criteria, but the stale list is a run-specific fact, not a criterion. Two copies of the list can drift from `STALE_CASES`.
- Fix: drop the stale section from docs/kev-labeling-criteria.md, or keep it only in benchmark/README.md.

L2. Placement and formatting nits.
- benchmark/kev_model_labels.json sits at the benchmark/ top level beside labels.json (the Shoply case labels). Both are named "labels"; the name `kev_model_labels.json` keeps them apart. Acceptable; the README documents it. No move needed.
- benchmark/README.md: the edited sentence in the gating paragraph is one overlong line while the surrounding paragraph is wrapped.
- judge_eval.py `report()` now has two code paths for quote absence (injected reader vs tempdir-built repos with `_pr_file_reader`), and `_pr_file_reader` reads BENCH/labels.json inside the report path. This is cohesive within judge_eval.py but it makes the module's report() harder to follow. Not a boundary violation.

## Checked, no problem
- Scope contract: changed files are all inside Owns/Creates/Modifies/Appends. docs/kev-labeling-criteria.md and benchmark/kev_model_labels.json are the declared Creates. benchmark/kev_support/*, citation_export.py and judge.py are listed under Modifies but unchanged; that is harmless. tests/model_input_lock/expected.json is unchanged (Regenerated, no change needed).
- Dependencies: judge_eval.py already imports evaluate and citation_export; `citation_export._git` is a private-name use across modules (pre-existing style in benchmark/). No cycles introduced. `src/lgtm` does not import from benchmark/.
- File hygiene: no scratch, log, credential or symlink files in the diff. Untracked src/lgtm/validation/judge_examples.py in the main checkout is outside this diff. The labels file records a labeling model and is intended content.
- Report keys are additive in judge_eval.report(); the new `not_real` stats key in report.json is additive.

## Limits
Read the diff for README.md, benchmark/README.md, evaluate.py, judge_eval.py, cli.py, report_builder.py and docs; skimmed the labels file head and did not read test diffs or the package reports. CodeGraph not used.
