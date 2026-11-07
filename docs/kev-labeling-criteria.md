# Kev labeling criteria

Labels for judge candidates. Each unit is one cited code item
of a candidate finding.

Claude Opus 5.5 writes the labels under these criteria. Kev, the judge being measured, is not the
labeller.

Labelers are given the claim, the quoted code, and the enclosing function with its decorators from
the reviewed code. A unit whose quote is not present in the reviewed code is `undetermined` and
excluded from accuracy.

## supported

`yes` when the cited code, read alone, shows the behavior the candidate's claim describes.
`no` when the code is unrelated to the claim, shows something else, or does not contain what the
claim quotes.

## verdict

`real` when the claim is supported and the described behavior is an exploitable vulnerability in the
reviewed change. `not_real` when the claim is unsupported, or supported but the behavior is
guarded, unreachable, or not a vulnerability. A supported claim can be `not_real`.

## severity

Set only on `real` units. The levels and their wording are `SEVERITY_DESCRIPTIONS` in
`src/lgtm/validation/judge.py`, the text Kev is given.

## acceptable answers

`verdict` and `severity` hold the single best answer. When the cited code supports more than one
reading, `acceptable` lists every verdict and severity a careful reviewer could justify from the
claim and the quoted code, and `rationale` gives the reason. An answer outside the set is wrong.

## kind

The candidate's origin shape, for example `live_shaped` (a candidate as the live reviewer
produces it) or `safe_twin`.

## origin

`shoply` for synthetic benchmark cases, `real_world` for real-world cases.

## Stale candidates

Candidates of `sqli_04_safe`, `sqli_07_safe` and `sqli_11_safe` in the stored
`benchmark/runs/archive/run6-final/lgtm` run are not labelled. The labels file covers the regenerated runs, where candidates of these cases
are labelled and scored.
