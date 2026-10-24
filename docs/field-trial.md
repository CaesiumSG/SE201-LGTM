# Field trial: LGTM on ordinary merged PRs

The Shoply and real-world CVE benchmarks ask whether LGTM finds flaws in
PRs we *know* are vulnerable or safe. This page asks what a developer would
see if they pointed LGTM at everyday traffic: does it run, how long does it
take, and how much noise does it make on PRs that the projects' own
maintainers reviewed and merged.

- **Data:** [`benchmark/field_trial/cases.json`](../benchmark/field_trial/cases.json),
  12 merged PRs from three open-source Python web apps.
- **Harness:** [`benchmark/field_trial/run_field_trial.py`](../benchmark/field_trial/run_field_trial.py);
  per-PR JSON and a `summary.json` per mode in
  [`benchmark/runs/field_trial/`](../benchmark/runs/field_trial/).
- **Protocol:** nothing was tuned on these PRs. Every PR was merged by the
  project, so a `vulnerable` verdict is a probable false alarm unless a human
  reading the finding says otherwise; the "judgement" column below is that
  reading.

## PRs

| Case | Project (framework) | PR | What it changes | Files / Python files | Added lines | Security-related |
|---|---|---|---|---|---|---|
| `mealie-8811` | mealie (FastAPI) | [#8811](https://github.com/mealie-recipes/mealie/pull/8811) | validators route accepts the signed-in user's own name/email | 2 / 2 | 34 | no |
| `mealie-8809` | mealie (FastAPI) | [#8809](https://github.com/mealie-recipes/mealie/pull/8809) | error on rejected recipe asset upload (route) | 2 / 2 | 5 | no |
| `mealie-8808` | mealie (FastAPI) | [#8808](https://github.com/mealie-recipes/mealie/pull/8808) | error when a user lacks permission (permissions helper) | 2 / 2 | 16 | yes (permissions) |
| `mealie-8783` | mealie (FastAPI) | [#8783](https://github.com/mealie-recipes/mealie/pull/8783) | require `can_organize` on units/tools/labels routes | 11 / 8 | 43 | yes (authz hardening) |
| `mealie-8814` | mealie (FastAPI) | [#8814](https://github.com/mealie-recipes/mealie/pull/8814) | repository `filter_by` → explicit SQLAlchemy expressions | 4 / 4 | 35 | no (DB layer) |
| `alerta-2049` | alerta (Flask) | [#2049](https://github.com/alerta/alerta/pull/2049) | counters for rejected/rate-limited/blackout alerts (view + model) | 3 / 3 | 38 | no |
| `alerta-2029` | alerta (Flask) | [#2029](https://github.com/alerta/alerta/pull/2029) | pagination for the environments endpoint (view + both DB backends) | 6 / 6 | 141 | no |
| `alerta-2047` | alerta (Flask) | [#2047](https://github.com/alerta/alerta/pull/2047) | restrict the self-update endpoint to allowlisted fields | 2 / 2 | 77 | yes (authz fix) |
| `alerta-2050` | alerta (Flask) | [#2050](https://github.com/alerta/alerta/pull/2050) | blackout matching with NULL service/tags (both DB backends) | 4 / 4 | 128 | no (DB layer) |
| `redash-7819` | redash (Flask) | [#7819](https://github.com/getredash/redash/pull/7819) | sqlparse upgrade and query handler changes | 8 / 6 | 119 | yes (security upgrade) |
| `redash-7749` | redash (Flask) | [#7749](https://github.com/getredash/redash/pull/7749) | configurable number separators (auth handler + org settings) | 8 / 3 | 30 | no |
| `redash-7759` | redash (Flask) | [#7759](https://github.com/getredash/redash/pull/7759) | enforce permissions in the Python query runner helpers | 2 / 2 | 154 | yes (authz hardening) |

The PR is the diff `merge_commit^1..merge_commit`; clones are shallow
(`git fetch --depth 2`), so the cache is 29 MB for all three projects.

## What reaches an agent

Before any model runs, LGTM's deterministic stages decide which parts of a
PR get reviewed at all. On these 12 PRs:

| Case | Semgrep findings in diff | Endpoints detected (authz agent runs) | Regex SQL sinks (`lgtm-no-sast` only) | Injection detector hits |
|---|---|---|---|---|
| `mealie-8811` | 0 | 3 | 0 | 0 |
| `mealie-8809` | 0 | 0 | 0 | 0 |
| `mealie-8808` | 0 | 0 | 0 | 0 |
| `mealie-8783` | 0 | 11 | 0 | 0 |
| `mealie-8814` | 0 | 0 | 1 | 0 |
| `alerta-2049` | 0 | 0 | 0 | 0 |
| `alerta-2029` | 0 | 0 | 2 | 0 |
| `alerta-2047` | 0 | 0 | 0 | 0 |
| `alerta-2050` | 0 | 0 | 1 | 0 |
| `redash-7819` | 0 | 0 | 3 | 0 |
| `redash-7749` | 0 | 0 | 0 | 0 |
| `redash-7759` | 0 | 0 | 0 | 0 |
| **Total** | **0** | **14 (2 of 12 PRs)** | **7 (4 of 12 PRs)** | **0** |

- **Semgrep is silent on all 12 PRs.** The bundled rules match string-built
  SQL passed to `execute()`/`text()`; none of these PRs does that. Good for
  noise (no SAST false alarms), but it also means the SAST-triage agent never
  runs here. The project's real queries go through SQLAlchemy expressions,
  Mongo query builders, or a query-runner layer the rules do not know.
- **The authz agent runs on 2 of 12 PRs.** Route decorators appear inside a
  changed hunk only in `mealie-8811` and `mealie-8783`. Three of the four
  security-related PRs (`mealie-8808`, `alerta-2047`, `redash-7759`) change an
  authorization check **without** touching a route decorator, so LGTM's
  default mode never looks at them. This is the same coverage gap the
  real-world CVE evaluation found; on everyday PRs it is the normal case, not
  the exception.
- **The prompt-injection detector raised no false alarms** on 820 added
  lines of real code and docstrings, so turning it on by default costs
  nothing on this traffic.

## Results

Setup: `qwen2.5-coder:7b` via Ollama, temperature 0, all defaults (no
experiment flags, mitigations as on `main`), MacBook, frozen copy of the
tree at `ff110c3` with the harness from this PR. Review latency is the
pipeline only; the index is built once per base commit and reported
separately. Runs: [`benchmark/runs/field_trial/`](../benchmark/runs/field_trial/).

| Mode | Crashes | PRs with a `vulnerable` verdict | Findings (verdicts) | Median review latency | Max | Index time, sum |
|---|---|---|---|---|---|---|
| sast-only | 0 / 12 | 0 | 0 | 4.8 s | 17.4 s | – |
| **lgtm** | **0 / 12** | **0** | 14 (14 `safe`) | 2.5 s | 144.0 s | 335 s |
| llm-only | 0 / 12 | 0 | 23 (22 `safe`, 1 `possible`) | 14.1 s | 76.1 s | – |

Per PR:

| Case | sast-only | Index | lgtm review | Endpoints reviewed | lgtm findings | llm-only | llm-only verdicts |
|---|---|---|---|---|---|---|---|
| `mealie-8811` | 3.7 s | 32.5 s | 69.9 s | 3 | 3 (safe 3) | 25.1 s | safe 2 |
| `mealie-8809` | 5.2 s | 55.4 s | 11.2 s | 0 | 0 | 6.8 s | safe 2 |
| `mealie-8808` | 9.0 s | 95.6 s | 4.6 s | 0 | 0 | 7.5 s | safe 2 |
| `mealie-8783` | 1.7 s | 46.7 s | 144.0 s | 11 | 11 (safe 11) | 13.9 s | safe 2 |
| `mealie-8814` | 2.0 s | 27.1 s | 2.5 s | 0 | 0 | 13.4 s | safe 2 |
| `alerta-2049` | 10.8 s | 8.7 s | 2.1 s | 0 | 0 | 9.5 s | safe 2 |
| `alerta-2029` | 8.8 s | 11.3 s | 2.9 s | 0 | 0 | 15.3 s | safe 2 |
| `alerta-2047` | 4.3 s | 9.1 s | 2.0 s | 0 | 0 | 14.2 s | safe 2 |
| `alerta-2050` | 17.4 s | 10.0 s | 2.5 s | 0 | 0 | 26.4 s | safe 1, possible 1 |
| `redash-7819` | 2.3 s | 13.0 s | 2.5 s | 0 | 0 | 14.7 s | safe 2 |
| `redash-7749` | 1.8 s | 13.7 s | 2.4 s | 0 | 0 | 9.2 s | safe 2 |
| `redash-7759` | 8.4 s | 12.4 s | 2.3 s | 0 | 0 | 76.1 s | safe 1 |

### Reading every finding

All 14 LGTM findings and the one `possible` from the baseline were read by
hand (`benchmark/runs/field_trial/<mode>/<case>.json`).

- **`mealie-8783`, 11 endpoints, all `safe`, all grounded, 13 s each.** The
  PR adds `Depends(require(Perm.GROUP_ORGANIZE))` to the unit, tool, label
  and recipe-action routes. The agent cited Mealie's own documentation for
  the rule ("Users need **Organize group data** to add new foods, tags, or
  categories", `docs/docs/documentation/getting-started/…`) and the
  decorator in the diff, and called each endpoint correctly protected. This
  is the behaviour the design promises, on a project we did not write and
  without a `security-policy.md`: the retrieved page *is* the access-control
  documentation. Judgement: 11 correct `safe` verdicts.
- **`mealie-8811`, 3 endpoints, all `safe`, none grounded.** The validator
  routes now accept the signed-in user's own name and email. The agent
  described the new `_is_current_user` check correctly for `/user/name` and
  `/user/email`, but its quoted snippets span the function signature plus
  context lines, which match neither the base file (the function changed)
  nor the diff's added lines alone, so all three are `evidence_valid:
  false`. For `/group` it wrote "checks if the current user is the owner of
  the group", which the diff does not show (the group validator was
  reformatted, not changed). Judgement: 2 correct `safe` verdicts with
  citation issues, 1 `safe` verdict with a made-up reason. None is a false
  alarm, but a reviewer trusting the explanation would be misled on the
  third.
- **`alerta-2050`, llm-only, `possible` (authz).** The bare model hedged on
  the blackout-matching query: "constructs a query that includes
  user-controlled inputs … there is still a possibility". The query is built
  with bound parameters in both backends, and the inputs are alert fields,
  not request parameters, so this is noise. Judgement: false alarm at the
  `possible` level (it would not fail CI).
- **Everything else is `safe` or no finding.** The baseline's `safe`
  verdicts are mostly "no SQL in this diff"; 9 of its 23 findings carry no
  evidence at all and are marked ungrounded.

### Latency and cost

- A review that reaches no agent costs 2–3 s (git diff + Semgrep).
  One that does costs about **13 s per endpoint** with the 7B model on this
  laptop, so `mealie-8783` took 144 s.
- **Indexing dominates.** Building the ChromaDB index for one Mealie base
  commit took 27–96 s (58 doc files plus the source tree), five times for
  five PRs: 335 s of indexing for 250 s of review. A user reviewing several
  PRs on one repo would index once, and the index only needs rebuilding
  when the base moves; the harness keys the index by base SHA for that
  reason. Mealie's spread (27 s to 96 s for near-identical trees) is the
  embedding model competing with Ollama for the same GPU.
- No run hit the LLM timeout or the output cap; no tool calls were made
  (0 on all 14 findings, as in every other 7B run).

## What the trial says

1. **False-alarm rate on everyday traffic: 0 of 12 PRs** at the `vulnerable`
   level for LGTM, and 0 of 12 for the baseline (one `possible`). The
   off-category ownership alarms that plague the Shoply SQLi cases (22 of
   24 endpoints) did not appear on 14 real endpoints. The Shoply alarms are
   tied to SQL in the same handler ("category bleed", evaluation log round
   5); these handlers have none.
2. **Coverage is the real problem, not noise.** 10 of 12 PRs got no LLM
   review in `lgtm` mode, including three of the four PRs that change an
   authorization check. The deterministic gates (Semgrep rules for
   string-built SQL, route decorators inside a hunk) were built for Shoply's
   shape and rarely fire on real diffs. The same finding came out of the
   real-world CVE evaluation; here it is the common case. PR #14's
   section-based review (every hunk reviewed, no endpoint gating) is the
   fix in flight.
3. **Policy retrieval works on real documentation.** On Mealie the agent
   found and cited the project's permission documentation without any
   hand-written policy, and judged 11 endpoints correctly against it. On
   Shoply the same mechanism needs `security-policy.md`; this is the first
   evidence that ordinary project docs are enough when they describe
   permissions.
4. **Grounding is where the quality risk is.** All 3 ungrounded findings
   were on the one PR whose check is new code; the validator's
   snippet-matching does not handle quotes that straddle changed and
   unchanged lines, and one explanation described a check that is not in the
   diff. A `safe` verdict with a wrong reason is the automation-bias risk
   from the checkpoint's Responsible-AI table, observed in the field.
5. **It runs.** No crashes on three real repositories, including one with
   58 documentation files and non-trivial route layouts; nothing from the
   diff reader hardening (17 Oct) regressed.

## Limitations

- 12 PRs, 3 projects, one model, one run each. The 7B model never calls
  tools, so this measures the pre-retrieved-context design, not the agentic
  one. The 27B runs in PR #10 would be the next thing to try here.
- All PRs were merged, so the trial can only count false alarms, not
  misses. Four PRs fix a security bug; LGTM did not review three of them,
  and on the fourth (`mealie-8783`) it only confirmed the fix is in place.
- Selection: PRs that touch route or database code, under 400 added lines,
  from the most recent 40 merged PRs per project. Larger PRs would stress
  the 6,000-character per-file prompt cap, which no PR here reached.
- The judgement column is one reader's.

## Reproduce

```bash
python benchmark/field_trial/run_field_trial.py --fetch                 # shallow clones (29 MB)
python benchmark/field_trial/run_field_trial.py --modes sast-only lgtm llm-only --model qwen2.5-coder:7b
python benchmark/field_trial/run_field_trial.py --modes lgtm --cases mealie-8783 --resume
```

Results go to `benchmark/results/field_trial/<mode>/` (git-ignored); the
runs reported here are copied to `benchmark/runs/field_trial/`.

