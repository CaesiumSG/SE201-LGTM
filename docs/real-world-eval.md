# Real-world evaluation: LGTM on published CVEs

Everything we had measured so far came from Shoply, a small Flask app the
team wrote for this project. The instructor's feedback was to stop proving
LGTM only on our own toy app and to apply it to real-world projects, noting
that failures are fine if they are documented. This page is that
evaluation: 6 published vulnerabilities in open-source Python web projects,
12 cases, every LGTM mode, and what went wrong.

**It is a held-out test.** No prompt, rule or config was tuned on these
cases, and every experiment flag is off.

- **Data:** [`benchmark/real_world/cases.json`](../benchmark/real_world/cases.json)
  (how the cases are built: [`benchmark/real_world/README.md`](../benchmark/real_world/README.md)).
- **Runs:** [`benchmark/runs/real_world/`](../benchmark/runs/real_world/),
  one JSON per case and a `summary.json` per mode.
- **Code:** [`benchmark/real_world/evaluate_real.py`](../benchmark/real_world/evaluate_real.py)
  reuses the scoring functions of `benchmark/evaluate.py`, so the metrics are
  computed exactly as for the synthetic benchmark.

## Headline

On 12 cases, LGTM did **not** reproduce its Shoply result. The bare LLM
baseline scored best.

| Mode (own docs) | F1 on 12 real-world cases | F1 on 36 Shoply cases |
|---|---|---|
| sast-only | 0.444 | 0.615 |
| **llm-only** | **0.800** | 0.750 |
| lgtm | 0.444 | **0.944** |
| lgtm-no-sast | 0.444 | 0.919 |

- **SQL injection mostly carries over.** LGTM's triage removed the one
  Semgrep false alarm, and the four SQLi cases that have a recognisable
  `execute()` sink (pyload, postgraas) were all handled correctly (SQLi F1
  0.800 vs sast-only 0.667). The fifth, alerta, was missed by every mode.
- **Authorization does not.** LGTM's authz F1 is 0.000 on real projects
  (0.923 on Shoply). Four of the six authz cases never reach the authz agent
  at all, and the pair that does gets both of its verdicts wrong with the
  repository's own docs.
- **The policy "fix" is not what it looks like.** With a project policy the
  langflow vulnerable case flips to a correct verdict, but for a wrong
  reason, and the safe twin gets the same verdict (see below).
- With 12 cases, one flipped case moves recall by 0.083 to 0.167. These
  numbers show failure modes; they are not a precise score.

## Setup

| | |
|---|---|
| Model | `qwen2.5-coder:7b` via Ollama 0.40.4, temperature 0, default context (4096) |
| Pipeline | `src/lgtm` defaults, **all experiment flags off**; bundled Semgrep rules, Semgrep 1.180.0 |
| Machine | Windows 11, Ryzen 7 170, 16 GB RAM, RTX 3050 Laptop (4 GB); the model ran 55% CPU / 45% GPU |
| Runtime | Python 3.14.5, run with `PYTHONUTF8=1` (see "Bugs found") |
| Date | 15 Oct 2026 |
| Code | run from a frozen detached copy of the tree; see provenance below |

**Latency caveat.** All latencies in this page are from one laptop with a
4 GB GPU, a 7B model split across CPU and GPU, and Semgrep starting up on
Windows. They are **not comparable to the team's 21 s/case** figure for
Shoply. Decoding ran at about 5 tokens/s. Use them only to compare modes
with each other on this run.

**Provenance.** The frozen copy was at `683e2a2` when `sast-only`,
`llm-only` and 7 of the 12 `lgtm` cases were run (the cases that run no
agent: alerta ×2, aegra ×2, litellm ×2, postgraas safe). Two bugs were then
fixed in their own commits (`4fff124`, `fef5a75`) and the frozen copy moved
to `fef5a75` for the remaining 5 `lgtm` cases (pyload ×2, postgraas
vulnerable, langflow ×2), `lgtm-policy`, `lgtm-no-sast` and
`lgtm-no-sast-policy`. The six `summary.json` files were rebuilt at
`0f8f527`. The code differences between these commits are an indexer change
that is a no-op below Chroma's batch limit and harness handling of
`--index-only`/`--summarize-only`; none touches `sast-only` or `llm-only`.
Three small indexes (pyload ×2, postgraas vulnerable) were built at
`683e2a2` and reused.

## Cases

| Case pair | Project (framework) | Advisory | CWE | Diff (vuln / safe) | Endpoints detected | Semgrep in diff |
|---|---|---|---|---|---|---|
| `pyload_sqli` | pyload (Flask) | GHSA-pwh4-6r3m-j2rf, CVE-2025-55156 | 89 | 1 file +5/-5 / same | 0 / 0 | 1 / 1 |
| `postgraas_sqli` | postgraas_server (Flask, flask-restful) | GHSA-vghm-8cjp-hjw6, CVE-2018-25088 | 89 | 1 file +13/-20 / 3 files +22/-13 | 0 / 0 | 2 / 0 |
| `alerta_sqli` | alerta (Flask) | GHSA-8prr-286p-4w7j, CVE-2026-34400 | 89 | 2 files +7/-114 / 3 files +247/-87 | 0 / 0 | 0 / 0 |
| `aegra_authz` | aegra (FastAPI) | GHSA-m98r-6667-4wq7, CVE-2026-44504 | 639 | 1 file +0/-19 / 6 files +320/-18 | 0 / 0 | 0 / 0 |
| `langflow_authz` | langflow (FastAPI) | GHSA-rf6x-r45m-xv3w, CVE-2026-33053 | 639 | 3 files +5/-9 / 4 files +72/-5 | 1 / 1 | 0 / 0 |
| `litellm_authz` | litellm (FastAPI) | GHSA-wpfp-gwwc-vwq6, CVE-2026-47102 | 863 | 2 files +22/-54 / 2 files +54/-22 | 0 / 0 | 0 / 0 |

- **Safe** cases are the real fix commit (parent of the fix → fix).
  **Vulnerable** cases are a synthetic revert: the fix commit as base, and a
  PR that puts back the pre-fix content of the non-test source files the fix
  touched. Safe diffs therefore include the fix's test files, and vulnerable
  diffs do not (aegra's safe diff is 22.5k characters of Python against
  2.5k for its vulnerable twin).
- The endpoint detector recognises only `@x.route/get/post/put/patch/delete("...")`
  decorators on a single line, and only when one appears inside a changed
  hunk. It does not see Flask-RESTful `Resource` classes (postgraas),
  `add_url_rule` or Django views.
- litellm's fix is two commits (PR #25541); its third commit is not in the
  advisory and is excluded. alerta uses the 2026 fix `fdd52cd`, not the 2018
  commit the advisory also links.

### What `vulnerable_lines` means

`vulnerable_lines` in `cases.json` are line numbers in the file as it
appears in the vulnerable PR. The convention depends on the flaw:

- **A sink** (pyload, postgraas, alerta): the lines are where untrusted data
  is interpolated into SQL (for alerta, the `return repr(...)` line the
  revert re-adds, since the interpolating f-strings in `__repr__` are
  unchanged context).
- **A missing check** (aegra, litellm): there is no sink. The lines mark
  **where the check is missing**, which is the spot where the fix inserts
  the guard (aegra: the three thread-ownership guards; litellm: the single
  and bulk `user_update` paths). langflow is mixed: the `DELETE` decorator and
  the call that omits the caller.

Scoring is case-level (did the tool flag the PR), so these lines document
the ground truth and did not influence any score.

## Results

Review latency excludes one-time indexing and downloads; see
[Cost](#cost) for those.

| Mode | Variant | Cases | TP | FP | FN | TN | Precision | Recall | F1 | SQLi F1 | Authz F1 | FP rate (safe) | Grounding | Grounded F1 | Median review latency |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sast-only | own docs | 12 | 2 | 1 | 4 | 5 | 0.667 | 0.333 | 0.444 | 0.667 | 0.000 | 0.167 | 1.000 | 0.444 | 12.1 s |
| llm-only | own docs | 12 | 4 | 0 | 2 | 6 | 1.000 | 0.667 | 0.800 | 0.800 | 0.800 | 0.000 | 0.583 | 0.800 | 68.73 s |
| lgtm | own docs | 12 | 2 | 1 | 4 | 5 | 0.667 | 0.333 | 0.444 | 0.800 | 0.000 | 0.167 | 0.833 | 0.500 | 16.55 s |
| lgtm | policy | 6 | 1 | 1 | 2 | 2 | 0.500 | 0.333 | 0.400 | – | 0.400 | 0.333 | 0.500 | 0.500 | 17.02 s |
| lgtm-no-sast | own docs | 12 | 2 | 1 | 4 | 5 | 0.667 | 0.333 | 0.444 | 0.800 | 0.000 | 0.167 | 0.750 | 0.444 | 39.64 s |
| lgtm-no-sast | policy | 6 | 1 | 1 | 2 | 2 | 0.500 | 0.333 | 0.400 | – | 0.400 | 0.333 | 0.833 | 0.500 | 38.59 s |

The `policy` rows cover the 6 authorization cases only, so compare them with
the authz-only breakdown, not with the 12-case rows:

| Mode | Variant (6 authz cases) | TP | FP | FN | TN |
|---|---|---|---|---|---|
| lgtm | own docs | 0 | 1 | 3 | 2 |
| lgtm | policy | 1 | 1 | 2 | 2 |
| lgtm-no-sast | own docs | 0 | 1 | 3 | 2 |
| lgtm-no-sast | policy | 1 | 1 | 2 | 2 |

### Beside the synthetic Shoply results (36 cases)

| Mode | Source run | Precision | Recall | F1 | SQLi F1 | Authz F1 | FP rate (safe) | Grounding | Median latency |
|---|---|---|---|---|---|---|---|---|---|
| sast-only | `run3-bugfixes` | 0.571 | 0.667 | 0.615 | 0.727 | 0.000 | 0.500 | 1.000 | 1.82 s |
| llm-only | `run3-bugfixes` | 0.857 | 0.667 | 0.750 | 0.923 | 0.000 | 0.111 | 0.778 | 11.88 s |
| lgtm | `run6-final` | 0.944 | 0.944 | 0.944 | 0.957 | 0.923 | 0.056 | 0.925 | 21.29 s |
| lgtm-no-sast | `run3-bugfixes` | 0.895 | 0.944 | 0.919 | 0.917 | 0.923 | 0.111 | 0.900 | 20.46 s |

### Per case

Own-docs outcome, with the policy-variant outcome in brackets where there is one.

| Case | Expected | sast-only | llm-only | lgtm | lgtm-no-sast |
|---|---|---|---|---|---|
| `pyload_sqli_vulnerable` | vulnerable | TP | TP | TP | TP |
| `pyload_sqli_safe` | safe | **FP** | TN | TN | TN |
| `postgraas_sqli_vulnerable` | vulnerable | TP | TP | TP | TP |
| `postgraas_sqli_safe` | safe | TN | TN | TN | TN |
| `alerta_sqli_vulnerable` | vulnerable | **FN** | **FN** | **FN** | **FN** |
| `alerta_sqli_safe` | safe | TN | TN | TN | TN |
| `aegra_authz_vulnerable` | vulnerable | **FN** | TP | **FN** (FN) | **FN** (FN) |
| `aegra_authz_safe` | safe | TN | TN | TN (TN) | TN (TN) |
| `langflow_authz_vulnerable` | vulnerable | **FN** | TP | **FN** (TP) | **FN** (TP) |
| `langflow_authz_safe` | safe | TN | TN | **FP** (**FP**) | **FP** (**FP**) |
| `litellm_authz_vulnerable` | vulnerable | **FN** | **FN** | **FN** (FN) | **FN** (FN) |
| `litellm_authz_safe` | safe | TN | TN | TN (TN) | TN (TN) |

`lgtm` and `lgtm-no-sast` produced the same outcome on all 12 cases. The
ablation used twice as many agent items (12 against 6) for the same verdicts.

## Every miss and false alarm

File paths below are under `benchmark/runs/real_world/`.

### `alerta_sqli_vulnerable`: missed by all four modes

- **sast-only, lgtm, lgtm-no-sast: the detectors found nothing.**
  `semgrep_findings_in_diff` is 0 and the heuristic found no sink, so no
  agent ran (`lgtm/alerta_sqli_vulnerable.json`: `index_skipped: true`,
  reason "no agent can run"). The diff's added lines are
  `return repr(query_expr.parseString(query)[0])...` and `qvars = dict()`:
  no `execute(` call. The interpolating f-strings are in `__repr__` methods
  that the revert does not change, and the SQL is executed elsewhere.
- **llm-only: it read the diff backwards.** It said `safe`, confidence 1.0
  (`llm-only/alerta_sqli_vulnerable.json`), explaining "The code no longer
  constructs SQL queries directly from user input". What the diff shows is the
  parameterized `to_sql` code being *removed* (`-114` lines). That is
  consistent with reading the `-` lines as the PR's behaviour. I cannot see
  the model's internal reading, only that the explanation describes the
  code the PR deletes.

### `aegra_authz_vulnerable`: missed by sast-only, lgtm, lgtm-no-sast

The authz agent never ran. `endpoints_detected` is empty: the endpoint's
`@router.post("/threads/{thread_id}/runs", ...)` decorator is 14 or more
lines above the line where the fix inserts the guard, outside the diff's
hunk, and the detector only looks inside changed hunks. No Semgrep finding
and no heuristic sink either, so every LGTM mode reports no findings
(`lgtm/aegra_authz_vulnerable.json`: `n_findings: 0`). The policy variant
made no difference by construction: with no agent, the policy index is not
even consulted (`lgtm-policy/aegra_authz_vulnerable.json` is also
`index_skipped: true`).

**Note the contrast:** `llm-only` caught it (TP): "The code removes a check
that ensures the user has permission to access the thread."
(`llm-only/aegra_authz_vulnerable.json`). The diff literally shows the
deleted guard (`+0/-19`). See "Why the numbers drop".

### `litellm_authz_vulnerable`: missed by every mode, both variants

- **LGTM modes:** same structure as aegra. The role guard sits in
  `_update_single_user_helper` and `bulk_user_update`, below a multi-line
  `@router.post(` decorator that is outside the hunks (and a multi-line
  decorator would not match the single-line pattern even if it were
  inside). `endpoints_detected` is empty, so no agent ran.
- **llm-only:** `safe`, confidence 1.0, with the self-contradictory
  explanation "No authorization checks are present in this file."
  (`llm-only/litellm_authz_vulnerable.json`). Its evidence did not validate.
  Its diff was 5,699 characters, below the 12,000-character cap, so this is
  not truncation.

### `langflow_authz_vulnerable` and `langflow_authz_safe`: the one authz pair an agent reaches

This is the only authz project where a route decorator falls inside a
changed hunk (the fix edits the `@router.delete(...)` line itself), so it is
the only one the authz agent reviews. Both of its verdicts are wrong with the
repository's own docs.

| | Own docs | Policy |
|---|---|---|
| vulnerable PR | **safe** (FN) | **vulnerable** (TP) |
| safe PR | **vulnerable** (FP) | **vulnerable** (FP) |

- **Own docs, vulnerable PR → `safe`** (`lgtm/langflow_authz_vulnerable.json`).
  The vulnerable route still has
  `dependencies=[Depends(auth_utils.get_current_active_user)]`. The agent
  wrote "uses a dependency injection to ensure that the current user is
  authenticated … This satisfies the documented access-control rule."
  Authentication was treated as authorization, which is the IDOR itself. The
  "documented rule" it cited is `SECURITY.md:110-142`, quoting only the link
  sentence "For more information, see [API keys and authentication](…)". The
  validator accepted it (the text exists), but it is not a rule: retrieval
  from the repo's own docs returned nothing that states one.
- **Own docs, safe PR → `vulnerable`** (`lgtm/langflow_authz_safe.json`).
  The agent said "does not verify that the user is the owner of the API
  key". The ownership check in the fix is in `crud.py`
  (`delete_api_key(..., user_id)`), but the authz prompt contains only the
  endpoint file's diff (`api_key.py`), so the check is not in front of the
  model. `tool_calls_used` is 0: it never tried to look. Its code snippet
  also failed validation (`evidence_valid: false`).
- **Policy, vulnerable PR → `vulnerable` (TP), but for a wrong reason**
  (`lgtm-policy/langflow_authz_vulnerable.json`). The explanation is "The
  policy requires that only superusers can delete API keys", citing the
  policy line "delete user require a superuser when authentication is
  enabled". That line is the Users API rule about deleting *user accounts*.
  The policy has no such rule for API keys, and the project's actual rule
  (ownership) is not what the model cited.
- **Policy, safe PR → `vulnerable`** (`lgtm-policy/langflow_authz_safe.json`)
  by the same misapplied rule: "This violates the policy that 'delete user
  require a superuser when authentication is enabled.'"

So the policy changed the verdict on the vulnerable PR from wrong to right,
but the model returns `vulnerable` for *both* twins. It did not discriminate
between them. **The "policy gap" on this pair is 0 → 1 true positive, and I
do not read it as a genuine improvement.**

### `pyload_sqli_safe`: false alarm for sast-only only

Semgrep flags the fixed code (`execute(f"SELECT id FROM links WHERE url IN
({placeholders})", urls)`) as "SQL query built with an f-string"
(`sast-only/pyload_sqli_safe.json`). The f-string builds only `?`
placeholders. The triage agent dismissed it (`lgtm/pyload_sqli_safe.json`:
"uses parameterized placeholders and passes the user-controlled input as a
separate argument"), which is the behaviour the synthetic benchmark claimed.

### Other observations from the outputs

- **No tool was ever called:** `tool_calls_used` is 0 on all 54 findings.
- **Ungrounded findings:** 16 of 54 findings did not validate their
  evidence. The grounded-only F1 of `lgtm` rises from 0.444 to 0.500 only
  because its false alarm was ungrounded.
- **Twin asymmetry shows up in agent work.** `lgtm-no-sast` triaged a
  `select(User).where(...)` line in the fix's test file
  (`langflow_authz_safe`, `test_api_key.py:95`) and the fix's three
  `select(ThreadORM).where(...)` lookups in `aegra_authz_safe`: items that
  exist only because the safe twin carries the fix and its tests. All were
  dismissed.
- **Crashes recorded as results: none.** Three environment/product crashes
  occurred before the final run and were fixed or worked around; see below.

## Policy variant: what the gap shows

`policies/{aegra,langflow,litellm}.md` were written only from each
project's public documentation, covering the whole API access model, and
committed (`ddbe127`) before any model ran on these projects.

- For **aegra and litellm** the policy had no effect, because no agent runs.
  That is a property of the detector, not of the policy.
- For **langflow** it flipped one verdict to a correct answer for the wrong
  reason (above), and left the false alarm in place.
- The documentation itself was thin where it mattered: the Langflow
  pages on flows and API keys state no ownership rules, and the policy says
  so ("Not specified in the documentation").

## Why the numbers drop

Only causes visible in the outputs above:

1. **The agent runs only where a detector fires.** 7 of 12 `lgtm` cases ran
   no agent (`index_skipped: true`). For authz, 4 of 6 cases have no detected
   endpoint. Shoply's route handlers keep decorator and check together; here
   the check is far from the decorator (aegra, litellm) or the decorator is a
   multi-line call (litellm).
2. **The agent sees only the endpoint file's diff.** The langflow ownership
   check lives in `crud.py`, so the safe fix looks unprotected. The model
   never used tools to look.
3. **Authentication is accepted as authorization** when the retrieved text
   is not an access rule (langflow, own docs).
4. **Retrieval and validation cannot tell a rule from a sentence.** A link
   sentence and a rule about user accounts both passed validation and were
   presented as the governing policy.
5. **The sink pattern is narrow.** alerta's injection is not an `execute()`
   in the diff, so Semgrep and the heuristic both find nothing.
6. **The baseline benefited from the synthetic revert.** In aegra and
   langflow the vulnerable PR's diff visibly *deletes* the guard, and
   `llm-only`'s explanations say so ("removes a check", "no longer checks if
   the user is the owner"). A real vulnerable PR that never had the check
   would show no such deletion. This is why `llm-only` scores higher here
   than on Shoply (authz F1 0.800 vs 0.000), and I would not expect that to
   hold on genuine vulnerable PRs.

What did **not** drop: the SQLi triage still removes the SAST false alarm,
and the SQLi cases with a real `execute()` sink were caught by every mode
that can see one.

## Cost

| | |
|---|---|
| Review latency, median | sast-only 12.1 s · llm-only 68.7 s · lgtm 16.6 s · lgtm-no-sast 39.6 s |
| Slowest single review | 139.1 s (`lgtm-no-sast`) |
| Index builds (not skipped) | langflow ×4: 243–269 s each (6,081–6,084 chunks, ~25 chunks/s); aegra 45 s ×2; pyload 60–65 s ×2; postgraas 6–8 s |
| Index skipped | `lgtm`: alerta ×2, aegra ×2, litellm ×2, postgraas safe. `lgtm-no-sast`: alerta ×2, aegra vulnerable, litellm ×2 |
| Total model time | about 42 min of review plus about 20 min of indexing |

Decoding ran at about 5 tokens/s, so a single agent call took 37–139 s.
These figures are specific to this laptop; see the latency caveat above.
Indexes are skipped only when the pipeline's own functions show that no
agent can run (`index_skipped` and `index_skip_reason` are in every JSON);
the output is then determined without the index.

## Bugs found while running

These are documented because the instructor asked for failures. None is an
LGTM judgement, but each would have silently corrupted or blocked a
real-world run.

1. **Semgrep silently skipped on Windows** (fixed, `b13e8f4`).
   `_semgrep_executable()` looked for a file named `semgrep` and missed
   `semgrep.exe`; it fell back to `python -m semgrep`, which Semgrep ≥ 1.38
   rejects, and the pipeline reported "continuing without SAST" with zero
   findings. Every Semgrep result would have been wrong. The test that
   asserts path-free rule ids had been *skipped* on this machine for the
   same reason.
2. **Chroma batch limit crash on large repos** (fixed, `4fff124`). Indexing
   langflow failed with `ValueError: Batch size of 6011 is greater than max
   batch size of 5461`; `_replace_collection` passed all chunks to one
   `add()`. The limit comes from the local SQLite build, so Mac/Linux hit it
   at about 41k chunks and this machine at 5,461. This was a **crash of the
   product on a real-world repository**.
3. **git output decoded as cp1252 on Windows** (not fixed here; owner:
   `src/lgtm/diff/`). Reported below.

### Report for the owner of `src/lgtm/diff/`

> **`src/lgtm/diff/git_diff.py` — `_run_git` decodes git output with the
> Windows locale code page**
>
> **Symptom:** On Windows (default cp1252), a diff containing non-ASCII bytes
> makes `subprocess.run(..., text=True)` fail in its reader thread
> (`UnicodeDecodeError: 'charmap' codec can't decode byte 0x8f`).
> `result.stdout` becomes `None`, then `parse_unified_diff(None)` raises
> `AttributeError: 'NoneType' object has no attribute 'splitlines'`. The
> pipeline crashes in every mode.
>
> **Repro:** `get_pr_diff(repo, "rw/aegra_authz_safe/base",
> "rw/aegra_authz_safe/pr")` on the real-world benchmark (aegra fix
> `e1b2042` adds a test file containing non-ASCII).
>
> **Not an LGTM judgement:** a Windows-locale artifact; Mac/Linux default to
> UTF-8 and are unaffected. Running with `PYTHONUTF8=1` avoids it (verified).
> `evaluate_real.py` refuses to start on Windows without UTF-8 mode, so it
> cannot fail silently.
>
> **Suggested fix:** pass `encoding="utf-8", errors="replace"` to
> `subprocess.run` in `_run_git`, and raise `GitError` rather than let `None`
> through. The same `text=True` pattern is in `semgrep_runner.run_semgrep`
> and `benchmark/evaluate.py:run`. Add a regression test with a non-ASCII
> added line.

## Threats to validity

- **Tiny n.** 12 cases from 6 advisories. One case is 0.083 of recall.
- **Synthetic vulnerable PRs.** A revert is not a PR anyone wrote, and its
  diff shows the deleted guard (see cause 6). Safe PRs are real, so the two
  twins also differ in size and in carrying test files.
- **The policies were written by someone who had seen the fixes.** I
  mitigated this by covering each project's whole access model from the docs
  and citing the pages, but the author was not blind. The docs are as
  published on 15 Oct 2026, after the fixes. A search summary also surfaced
  a third-party write-up of an issue similar to litellm's; it was excluded and
  the policy comes only from the official pages.
- **Order of work.** Before writing the policies I ran the deterministic
  stages (endpoint extraction, Semgrep, heuristic sinks) on all 12 cases to
  size the run. No model output for these projects had been seen, and the
  policies were not edited afterwards.
- **Possible memorisation.** postgraas's CVE dates from 2018. All modes that
  can see its sink caught it, and I cannot separate memorisation from the
  fact that string-built SQL is easy to spot.
- **One model, one run, temperature 0.** Earlier rounds showed verdicts can
  flip on irrelevant prompt changes. Run-to-run variance was not measured.
- **Platform.** Windows, Python 3.14, a 4 GB GPU. The Chroma and encoding
  failures are platform-dependent; model behaviour should not be.
- **Prompt caps.** The llm-only prompt truncates the diff at 12,000
  characters and the authz prompt at 6,000 per file. `alerta_sqli_safe`
  (25,347 characters of Python diff) and `aegra_authz_safe` (22,516)
  exceeded the llm-only cap, and both were scored TN, so I cannot show an
  effect. alerta's largest file (17,588) is over the authz cap but no authz
  agent ran there. Ollama's log recorded `truncated = 0` for every request.

## Next steps

Not done, and not tuned for here:

1. Detector coverage: multi-line decorators, `add_url_rule`, Flask-RESTful
   `Resource` classes, Django views, and checks that sit in a callee.
2. Give the authz agent the callee or the other changed files for the same
   endpoint, and measure it on the dev split first.
3. Make the validator check that a cited policy line is *about* the
   operation under review, not only that it exists.
4. Re-run the policy experiment with policies written by someone who has not
   seen the fixes, and for more projects.
5. Grow the set: more CVEs, and real vulnerable PRs rather than reverts.
6. Fix the Windows decoding bug in `src/lgtm/diff/`.

## Reproduce

```bash
# build the 12 cases and the policy variants (clones into benchmark/real_world/.cache)
python benchmark/real_world/fetch.py --policies

# run in foreground chunks; on Windows set PYTHONUTF8=1
PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes sast-only --variants own
PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes llm-only --variants own --resume --budget 300
PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes lgtm lgtm-no-sast --variants both --resume --budget 240
# large indexes can be built separately
PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes lgtm --cases langflow_authz_safe --index-only
```
