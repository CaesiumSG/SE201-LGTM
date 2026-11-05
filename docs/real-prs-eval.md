# Real pull requests that introduced published vulnerabilities

This benchmark asks the question the project exists for: given the pull
request that introduced a real, published vulnerability, does LGTM flag it,
and does it stay quiet on the commit that fixed it?

Every case is a GitHub Security Advisory (GHSA) in an open-source Python web
application. For each one we review two diffs:

- **vulnerable**: the commit or PR that introduced the flaw, against its parent.
  A flag here is a true positive (TP); silence is a false negative (FN).
- **fixed**: the commit that fixed it, against its parent. A flag here is a
  false positive (FP); silence is a true negative (TN).

A TP is **on target** when a flagged finding is in a file the advisory names
(`vulnerable_files`), and **exact** when, in addition, its CWE matches the
advisory's category: CWE-89 for SQL injection; an access-control CWE (CWE-862,
863, 639, 284, 285, 200, 269, 732, 266) for authorization.

## Two sets, scored separately

| Set | File | Advisories | Use |
|---|---|---|---|
| Development | `benchmark/real_prs/cases.json` | 13 (4 SQLi, 9 authz) | Found the SQLi blind spot; the SQLi reviewer was built and checked on it |
| Held-out | `benchmark/real_prs/heldout.json` | 17 (8 SQLi, 9 authz) | Chosen after the reviewer was written, run once, not tuned on |

Three held-out cases are weaker evidence and are reported with and without
them: `piccolo-savepoint-name-sqli` (2023; the injectable argument is a
savepoint name a developer passes, not request data),
`openedx-support-manage-course-team-authz` (the impact is an account-existence
oracle plus role disclosure, and the introducing PR's tests show the behaviour
was intended) and `django-orderby-dotted-column-sqli` (2021, so the most
exposed to training data).

## Setup

- Reviewer model `qwen3.8:27b` on the SCIS GPU cluster (Ollama), judge
  `jaredpalmer/kev-4b`, both served by `model/deploy/judged-up.sh`.
- `lgtm` mode: Semgrep, SAST triage, investigator, per-section authorization
  review, the SQLi reviewer (v2.1 only), evidence validation, Kev judge.
- **v2.0** is `lgtm --no-sqli-review`: the pipeline as on `main` at 66839a2.
  **v2.1** adds the section SQLi reviewer (`docs/agents.md`, `sqli_reviewer`).
- **Plain LLM** is `llm-only`: the same model reads the diff once, no tools.
- Semgrep alone (`sast-only`) flagged nothing on any development case (0/13),
  so it was not re-run on the held-out set.

## Results

### Held-out set (17 advisories)

| | v2.1 | v2.0 | Plain LLM |
|---|---|---|---|
| Caught (TP) | **15/17** | 12/17 | 7/17 |
| On target | 14 | 11 | 7 |
| Exact | **14** | 10 | 7 |
| SQL injection, exact | **7/8** | 3/8 | 4/8 |
| Authorization, exact | 7/9 | 7/9 | 3/9 |
| False alarms on fixes | 1/17 | 0/17 | 2/17 |
| Median seconds per diff | 191 | 167 | 10 |
| Without the 3 weak cases: caught / exact | 13/14 / 12 | 10/14 / 8 | 6/14 / 6 |

Per advisory ("+FP" = also flagged the fix):

| Advisory | Category | v2.1 | v2.0 | Plain LLM |
|---|---|---|---|---|
| `alerta-query-string-parser-sqli` | sqli | exact +FP | miss | exact |
| `django-orderby-dotted-column-sqli` (weak) | sqli | miss | miss | miss |
| `django-raster-band-index-sqli` | sqli | exact | miss | miss |
| `ormar-aggregate-minmax-sqli` | sqli | exact | exact | miss |
| `piccolo-savepoint-name-sqli` (weak) | sqli | exact | exact | exact |
| `rucio-oracle-json-meta-filter-sqli` | sqli | exact | exact | miss +FP |
| `rucio-postgres-meta-filter-sqli` | sqli | exact | miss | exact +FP |
| `taiga-epic-order-sqli` | sqli | exact | on target, as authz | exact |
| `authentik-ssf-stream-authz` | authz | exact | exact | miss |
| `django-cms-structure-endpoint-authz` | authz | exact | exact | miss |
| `khoj-subscription-email-idor` | authz | exact | exact | miss |
| `openedx-support-manage-course-team-authz` (weak) | authz | exact | exact | miss |
| `paperless-ngx-global-search-mail-authz` | authz | caught, other file | caught, other file | miss |
| `plane-bulk-issue-dates-idor` | authz | exact | exact | exact |
| `readthedocs-team-access-filter-authz` | authz | miss | miss | miss |
| `sentry-notification-option-delete-idor` | authz | exact | exact | exact |
| `sentry-rule-snooze-idor` | authz | exact | exact | exact |

### Development set (13 advisories)

v2.1 was run on the 4 SQLi advisories only; its authorization path is the
same code as v2.0, and the held-out set confirms the authorization results do
not change (identical on all 9).

| | v2.1 (SQLi only) | v2.0 | Plain LLM |
|---|---|---|---|
| SQL injection: caught / exact | **4/4 / 4** | 2/4 / 0 | 3/4 / 3 |
| Authorization: caught / exact | (as v2.0) | 7/9 / 7 | 4/9 / 3 |
| False alarms on fixes | 1/4 (redash) | 2/13 (redash, pretix) | 0/13 |
| Median seconds per diff | 184 | 138 | 11 |

## What the numbers say

- **v2.0 could not see SQL injection on real PRs.** Its only SQLi path triages
  Semgrep hits, and Semgrep matched nothing in any of these diffs: the SQL is
  built in helpers, template filters and `str.format` calls its rules do not
  cover. v2.0's SQLi "catches" were mostly authorization findings that
  happened to sit in the right file (taiga here; litellm and redash on the
  development set).
- **The SQLi reviewer closes most of that gap without hurting the rest.** On
  held-out data it found 7 of 8 SQLi advisories with the right CWE in the
  right file, against 3 for v2.0, and the authorization results were
  identical. The cost is one false alarm (alerta's fix; on the development
  set, redash's) and about 25 seconds per diff.
- **On authorization the agent pipeline beats the plain LLM** (7/9 exact
  against 3/9, and 7/9 against 3/9 on the development set). The plain LLM sees
  only the diff; the agents can open the views, permission classes and
  querysets the diff relies on.
- **Two advisories were missed by every mode.** In django order_by the
  change removes a regex check inside `Query.add_ordering()`, deep in the ORM.
  In readthedocs two chained `.filter()` calls on a many-valued relation make
  separate joins, so team membership and access level can match different
  teams: a 15-line diff whose flaw is in Django query semantics, not in any
  missing check.

## Threats to validity

- **Small sets.** 17 held-out advisories; one case moves a rate by 6 points.
- **Selection.** The advisories were picked by us (with AI-assisted search) for
  having an identifiable introducing commit in a Python web app. Advisories
  whose introducing change is spread over many commits are under-represented.
- **Training-data exposure.** Advisories published before the reviewer
  model's training cutoff may be known to it. The plain LLM's low recall
  suggests this is not what drives the results, but it cannot be ruled out.
- **"Fixed" is not "safe".** A flag on the fix commit counts as a false alarm
  even if the fixed code has a different real flaw; we did not check.
- **Infrastructure.** A VPN drop during the first held-out run killed the GPU
  tunnels; the records written after the drop (5 diffs) were set aside and
  re-run on a fresh job. Every reported record completed with no error.

## Live hunt (no answer key)

`benchmark/live_hunt/` reviews 20 PRs merged May–Nov 2026 in active Python
web applications, with Claude Sonnet 4.6 on Amazon Bedrock as the reviewer
(the Kev judge unchanged). Each flagged lead was checked against the
project's source by separate AI agents, and the verdicts were reviewed by us.
Of 55 leads, 2 were real; both had since been published by others as
advisories, which we confirmed against the advisory text:

- wagtail PR #14488 (draft page content readable through the v3 pages API),
  published as [GHSA-jrgm-fhgv-hmj9](https://github.com/advisories/GHSA-jrgm-fhgv-hmj9).
- wagtail PR #14490 (documents in descendant collections), published as
  [GHSA-c2xx-cjmh-9q8f](https://github.com/advisories/GHSA-c2xx-cjmh-9q8f).

Two further leads are being checked privately; their details are withheld
until the maintainers have been told. Most of the remaining leads were false
alarms, and the Kev judge passed almost all of them, so the hunt's precision
is low: it is a lead generator for a human reviewer, not an alarm.

Results stay in `benchmark/results/live_hunt*` (gitignored).

## Reproduce

```bash
model/deploy/judged-up.sh 4:00:00 && model/deploy/connect.sh <job> && model/deploy/kev-connect.sh <job>
python benchmark/real_prs/run_real_prs.py --gpu-model qwen3.8-27b --modes lgtm llm-only
python benchmark/real_prs/run_real_prs.py --cases-file benchmark/real_prs/heldout.json \
    --gpu-model qwen3.8-27b --modes lgtm llm-only --output benchmark/results/heldout_v21
python benchmark/real_prs/run_real_prs.py --cases-file benchmark/real_prs/heldout.json \
    --gpu-model qwen3.8-27b --modes lgtm --no-sqli-review --output benchmark/results/heldout_v20
```
