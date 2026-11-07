# Investigator split rubric

Rate one result file, `investigator/<case_id>.json`: the PR diff and the sections the investigator proposed for it. Give one rating from 0.00 to 1.00 for how logical the split of the diff into sections is.

## Criteria

- Cohesion: the hunks in a section belong together, serving one change or one concern.
- Separation: unrelated changes sit in different sections. A section does not mix concerns.
- Coverage: every substantive hunk is in some section; hunks are not dropped or repeated without reason.
- Titles and rationales: each describes what its hunks do and why they are grouped.
- Granularity: sections are neither one catch-all group nor one section per hunk without cause.

Judge the split only. Do not rate the code quality of the PR, and do not look for vulnerabilities.

## Scale

| Rating | Anchor |
| --- | --- |
| 0.00 | No logical split: sections are arbitrary or mix unrelated changes, titles and rationales do not match the hunks, or most substantive hunks are missing. |
| 0.50 | Partly logical: some sections are cohesive, but others mix concerns, important hunks are missing or misplaced, or granularity is clearly off. |
| 1.00 | Fully logical: every section is cohesive and separate from the others, all substantive hunks are covered, and titles and rationales are accurate. |

Use intermediate values (for example 0.25 or 0.75) between anchors.

## Rating record

Write `investigator/ratings/<case_id>.json` in the results directory:

```json
{"case_id": "<case_id>", "rating": 0.75, "reason": "one or two sentences"}
```

`rating` is a number from 0.00 to 1.00. Rate each case once.
