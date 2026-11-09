# LGTM — Context-Aware PR Security Agent

LGTM reviews pull requests for security vulnerabilities by combining
**deterministic SAST** (Semgrep) with **LLM agents grounded in repository
context**. Semgrep provides high-recall signal for SQL injection; LLM agents
(Qwen3.8 27B via Ollama, locally or on the SCIS GPU cluster) triage those
findings against the actual code, review every changed code section for SQL
injection, and check it against the project's *documented* security policy
(retrieved with RAG), which catches authorization flaws SAST cannot see. An
evidence validator and a small judge model (Kev-4B) keep the LLM honest.

**Course:** SE201 AI-Driven Software Engineering, AY2026-27 Term 1.
**Team:** "wo men ai AI".

| Member | Main areas |
|---|---|
| Lee Jin Rae | AI engineering: investigator and section pipeline, agent tool loop, Kev-4B judge, held-out guard run |
| Brian Sng | AI engineering: prompt-injection red-teaming and mitigations, safe Markdown in the demo App |
| Jayce Lye Jia Jun | Security engineering: Semgrep rules and policy docs, Shoply and real-PR benchmarks, SQLi reviewer, final evaluation, demo GitHub App |
| Hsu Yati Ko | Software engineering: diff reader hardening, policy index built from the base commit, CI, one-command runner |
| Loh Kai Zhe | Evaluation engineering: real-world CVE benchmark and its write-up |

Roles as planned are in [`docs/project-proposal.md`](docs/project-proposal.md);
who did what since is in [`docs/team-tasks.md`](docs/team-tasks.md) and the
commit history.

## Results in brief

On **17 published advisories that we did not tune on** (the pull request that
introduced each flaw, plus the commit that fixed it), with the same model
(Qwen3.8 27B, temperature 0) in every row:

| Condition | Caught | Right file and CWE | False alarms on the 17 fixes | Median time per diff |
|---|---|---|---|---|
| **LGTM** (full pipeline) | **15/17** | **14/17** | **1/17** | 124 s |
| LGTM without Semgrep | 14/17 | 13/17 | 3/17 | 101 s |
| Same model, diff only (plain LLM) | 7/17 | 7/17 | 2/17 | 7 s |
| Semgrep only | 3/17 | 3/17 | 2/17 | 1 s |

The LGTM and plain-LLM rows were identical in three repeated runs. Larger cloud models
(gpt-oss 120B, Claude Haiku 4.5, Claude Sonnet 4.6) in the same pipeline
catch one or two more advisories in some runs but raise 3 to 11 false alarms
per run. All benchmarks and the full tables
are under [Benchmarks](#benchmarks) and in
[`benchmark/runs/final-2026-11/RESULTS.md`](benchmark/runs/final-2026-11/RESULTS.md).

## Scope

LGTM looks for two classes of vulnerability:

1. SQL injection (CWE-89): triage of Semgrep warnings, plus a review of
   every changed section for injection Semgrep has no rule for.
2. Authorization (authz) bugs that Semgrep cannot see (CWE-639, CWE-862,
   CWE-863).

Every other vulnerability class is out of scope.

## Demo

LGTM also runs as a real **GitHub App with a dashboard** (`demo/`). In the demo, an AI coding assistant (a small local
model) writes a feature for a demo shop and leaves out an ownership check; the dashboard's App tab shows what that lets
a customer do (read another customer's order and address); the pull request goes to GitHub, and LGTM's review blocks
it with an inline comment, the policy rule it breaks and a fix. Real-world replays show the same on published
advisories (taiga-back, wagtail, authentik). Runbook, setup and the demo script: [demo/README.md](demo/README.md).

## Architecture

```
            ┌──────────────────────────────────────────────────┐
 PR branch  │ 1. Context building                              │
 ──────────▶│    git diff ── changed files/lines               │
 base branch│    semgrep ── CWE-89 findings in the diff        │
 ──────────▶│    ChromaDB ── security-policy / api-spec chunks │
            └───────────────┬──────────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────────┐
            │ 2. SAST Triage Agent (CWE-89)                    │
            │    true positive or parameterized false alarm?   │
            │ 3. Authorization Reviewer Agent                  │
            │    (CWE-639 / CWE-862 / CWE-863)                 │
            │    does the change respect the documented policy?│
            │    Tools (read-only, max 5 calls per section):   │
            │    investigate_base_code · investigate_pr_code   │
            │    read_file · grep_repo · search_policy         │
            └───────────────┬──────────────────────────────────┘
                            ▼
            ┌──────────────────────────────────────────────────┐
            │ 4. Evidence Validator                            │
            │    cited files/lines/snippets/policy must exist  │
            │ 5. Report Builder ── report.json + report.md     │
            └──────────────────────────────────────────────────┘
```

The investigator groups the PR's changed hunks into sections. Hunks it does
not place, and investigator failures, fall back to per-file sections. Every
Python hunk is reviewed, including deletions. Each section gets one authz
review that can return several findings. Overlapping duplicates are merged
and the Kev-4B judge decides whether the cited code supports each finding.

Each candidate is reported as supported, unsupported or not judged, with
the judge confidence, CWE, evidence citations, and a suggested fix.

## Setup

Requirements: Python 3.13+, git, and for the full pipeline
[Ollama](https://ollama.com) + Semgrep.

Optional: [CodeGraph](https://www.npmjs.com/package/@colbymchenry/codegraph)
on `PATH` enables the `investigate_base_code` / `investigate_pr_code` tools
(tested with 1.6.2):

```bash
npm install -g @colbymchenry/codegraph@1.6.2
codegraph --version
```

Without it (or with `--no-graph`) the agents use `read_file`, `grep_repo` and
`search_policy` only; verdicts are never adjusted for the graph's absence.

```bash
# 1. Install LGTM (editable) + dev and SAST extras
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" semgrep

# 2. A model: local Ollama (the default endpoint, http://localhost:11434) ...
ollama pull qwen3.8:27b         # the default model; any tool-calling model works with --model
# ... or the SCIS GPU cluster tunnel (see model/README.md), then --gpu-model qwen3.8-27b
model/deploy/up.sh
```

## Usage

```bash
# Index the docs committed on the base branch (security policy, API spec, README)
lgtm index --repo /path/to/repo --ref main

# Review a PR (diff of pr-branch against base-branch)
lgtm review --repo /path/to/repo --base main --pr feature-branch \
            --model qwen3.8:27b --output lgtm-output

# Baseline for comparison
lgtm review ... --mode llm-only      # one LLM call on the diff,
                                     #   no Semgrep, no RAG, no tools

# Prompt-injection mitigations (both ON by default in lgtm mode; the
# llm-only baseline always sees the raw diff)
lgtm review ... --no-strip-comments           # keep comments/docstrings in the
                                              #   PR code the LLM sees
lgtm review ... --no-detect-prompt-injection  # don't report reviewer-directed
                                              #   text in the diff as a finding
```

`sast-only` and `lgtm-no-sast` are for internal development and benchmarking
only. Reported results compare `lgtm` (which includes Kev judging) against
`llm-only`.

Outputs `lgtm-output/report.json` (machine-readable findings) and
`lgtm-output/report.md` (human-readable review). Both list supported,
unsupported and not judged candidates, supported first.

Exit code of `lgtm review`: 1 if any candidate is supported and the judge's
verdict for it is not `not_real`, or the `llm-only` baseline
reports a vulnerable finding; otherwise 2 if any candidate is not judged, any agent errored,
or the PR changes a policy document and `fail_on_policy_change` is on (see [Policy index](#policy-index));
otherwise 0 (CI-friendly). A supported candidate with verdict `not_real` is
not a vulnerability: it is listed as "not real" in the reports and does not
set exit code 1.

`--gpu-model qwen3.8-27b` connects through the existing GPU cluster
tunnel at `http://127.0.0.1:11435` with the model `qwen3.8:27b` and
thinking disabled. It cannot be combined with `--gpu-cluster` or
`--model`; `--ollama-url` overrides the URL. The registry URL assumes
`LOCAL_OLLAMA_PORT=11435`. `benchmark/evaluate.py` and
`benchmark/real_world/evaluate_real.py` accept the same flag.

**Other reviewer models (optional).** The reviewer can also run on Amazon
Bedrock (Claude, or gpt-oss through Bedrock's OpenAI-compatible API); the Kev
judge is unchanged. Set `"llm_backend": "bedrock"` and `"bedrock_model"` in the
`--config-file` JSON, put the token in `AWS_BEARER_TOKEN_BEDROCK`, and for
Claude install the extra: `pip install -e ".[bedrock]"`. Every call is charged
to a spend ledger (`bedrock_ledger`, default `~/.lgtm/bedrock-spend.jsonl`) and
stops at `bedrock_budget_usd`. `benchmark/real_prs/run_real_prs.py` takes
`--bedrock-model` directly. This is how
the model comparison in the final evaluation was run; Qwen on Ollama remains
the default and the configuration we recommend.

## Configuration

Settings are read from a JSON file passed with `--config-file`.

### CodeGraph

The `lgtm` mode uses CodeGraph when `graph_enabled` is
true (the default) and the binary is found. The `llm-only`
baseline never uses it. `--no-graph` (or `"graph_enabled": false`) reviews
without it; so does a missing binary, with a warning. In both cases the
agents keep `read_file`, `grep_repo` and `search_policy`, and no verdict is
changed because the graph was absent.

### Authorization planner

`authz_planner` (CLI `--authz-planner`) decides what the authorization agent
looks at: `investigator` (default) has an LLM group every changed Python
hunk into review sections, so the whole PR is reviewed; `endpoint` reviews
only hunks that contain a Flask/FastAPI route decorator, one section per
file, with no investigator. `endpoint` is the checkpoint pipeline's gating,
kept so the 13 Oct numbers can be reproduced and the two compared on the
same cases (the real-world evaluation and the field trial showed the gating
skips most real authorization changes).

| Key | Default | Limits |
|---|---|---|
| `graph_binary` | `"codegraph"` | Executable name or path, no arguments |
| `graph_init_timeout_s` | `120` | Must be positive |
| `graph_query_timeout_s` | `20` | Must be positive |
| `graph_max_output_chars` | `6000` | At least `1024`; values above `6000` are reduced to `6000` |
| `graph_max_export_files` | `20000` | Must be positive; values above `20000` are reduced to `20000` |
| `graph_max_export_bytes` | `209715200` | Must be positive; values above `209715200` are reduced to `209715200` |

Each snapshot (`base`, `pr`) is exported to a temporary directory and indexed
on first use. Graph queries read the committed commit only, not the working
tree. If the graph fails for a snapshot (timeout, non-zero exit, export
error), that snapshot's graph tools are skipped for the rest of the run and
agents use `read_file` or `grep_repo` with the same snapshot label. A launch
failure affects both snapshots.

The run's graph state is written to `graph_state` in `report.json` and to
the benchmark records:

- `ok`: no graph failures
- `unavailable:missing`: the `codegraph` binary was not found
- `degraded:<label>:<reason>`: the graph failed for that snapshot; multiple
  entries are separated by `;`

### Policy index

The base branch's docs are the security policy. A PR cannot change the policy
it is reviewed against:

- `lgtm index --ref <commit>` (default `HEAD`) reads the `.md`, `.txt` and
  `.rst` files committed at that commit, never the working tree, and records
  the commit in the index. Uncommitted and untracked docs are not indexed.
- `lgtm review` uses the index only when it was built from the base commit.
  Otherwise it warns, prints the `lgtm index` command to run, and reviews with
  code evidence only. `policy_index` in `report.json` is `ok`, `missing` or
  `stale:<commit the index was built from>`.
- A PR that adds, edits, renames or deletes any of those docs is listed under
  "Policy Documents Changed: Needs Human Review" in `report.md` and in
  `policy_docs_changed` in `report.json`. This does not change the exit code
  unless `fail_on_policy_change` is set to `true` in the config file; then it
  sets exit code 2 when nothing is supported. The review itself still reads
  the base versions.

The policy index is stored in `.lgtm/chroma` inside the reviewed repository.
Deleting that directory also deletes the index, so run
`lgtm index --repo /path/to/repo --ref <base>` again before the next review. Indexing
replaces only the policy collection (`lgtm_docs`); LGTM does not clean up
other collections automatically. Config keys that no longer exist
are ignored with an `Ignoring unknown config keys` warning.

## Guardrails

- Agent tools are **read-only**; file access is sandboxed to the repo.
- Agents read committed snapshots of the **base** and **PR** branches. Each
  branch is resolved once to a full commit SHA before the run starts. PR
  content is treated as untrusted data (analyzed, never executed or obeyed).
- Each SAST triage run (one finding) and each authz section review has a
  budget of **5 tool calls** (`max_tool_calls`) shared by all of its tools,
  including calls with invalid arguments or unknown tool names. Once the
  budget is spent, tools return a budget error. The investigator has its own
  budget.
- LLM calls are **retried** up to 3 times with 2s, 4s and 8s backoff
  before an agent run is reported as failed.
- Tool arguments are **validated** against each tool's schema before the
  tool runs. Invalid calls return an error to the agent and count toward the
  tool-call budget. The third invalid call in a run forces the final answer.
- Final answers that are not valid JSON are **re-requested** up to 3 times.
- Every code citation is **annotated** post-hoc with `grounded_in_pr`. A
  citation labelled `base` or `pr` must name a file in that committed
  snapshot, and any line range must be ordered, positive and inside the file.
- Human-in-the-loop: LGTM reports, it never auto-fixes.

The full risk assessment (hallucination, prompt injection, policy tampering,
privacy, evaluation bias, intellectual property, responsible disclosure,
non-determinism and cost) is in
[`docs/responsible-ai.md`](docs/responsible-ai.md).

## Benchmarks

There are **six separate benchmarks**. Each one answers a different
question, has its own script and its own metric:

| Benchmark | Question | Cases | Script | Metric | Write-up |
|---|---|---|---|---|---|
| **Real PRs, held-out** (main result) | Does LGTM flag the real PR that introduced a published vulnerability, and stay quiet on its fix? | 17 advisories, 34 diffs | `benchmark/real_prs/run_real_prs.py --cases-file benchmark/real_prs/heldout.json` | Caught / exact / false alarms on fixes | [`docs/real-prs-eval.md`](docs/real-prs-eval.md) |
| **Real PRs, development** | Same question; used to find the SQLi blind spot and build the SQLi reviewer | 13 advisories, 26 diffs | `benchmark/real_prs/run_real_prs.py` | Caught / exact / false alarms on fixes | [`docs/real-prs-eval.md`](docs/real-prs-eval.md) |
| **Shoply** (synthetic) | Does LGTM catch vulnerabilities, without false alarms? | 52 (dev 26 / eval 26) | `benchmark/evaluate.py` | Precision / recall / F1 | [`docs/evaluation-log.md`](docs/evaluation-log.md) |
| **Real-world CVEs** | Does that hold on code real developers shipped? | 12 (development set) | `benchmark/real_world/evaluate_real.py` | Precision / recall / F1 | [`docs/real-world-eval.md`](docs/real-world-eval.md) |
| **Prompt injection** | Can text in a PR trick LGTM into missing a vulnerability? | 6 attacks on Shoply cases | `benchmark/injection/run_injection_bench.py` | Attack success rate | [`docs/prompt-injection.md`](docs/prompt-injection.md) |
| **Field trial** | Does it crash, how long does it take, and does it raise false alarms on ordinary PRs? | 12 merged PRs | `benchmark/field_trial/run_field_trial.py` | Crashes, flags, latency | [`docs/field-trial.md`](docs/field-trial.md) |

The final evaluation ran all of them on one commit (`af878ce`) on 6–7 Nov
2026: 33 runs, 0 errored cases. Changes merged after that commit (for
example the policy index read from the base commit, PR #39) were tested by
the unit suite but not re-measured on the benchmarks. The final run's
results, run log and cost are in
[`benchmark/runs/final-2026-11/`](benchmark/runs/final-2026-11/)
(`RESULTS.md`, `RUNLOG.md`, `results.json`); the scripts that ran and
aggregated it are in `benchmark/final_eval/`.

The Shoply files (`app/`, `cases/`, `labels.json`, the policy docs and
`evaluate.py`) sit at the top of `benchmark/` because Shoply came first;
`evaluate.py` evaluates **only Shoply**, not the others. Its `--split eval`
means the 26 held-out *Shoply* cases.

**Why the results aren't combined into one score:** the benchmarks measure
different things (accuracy vs. resistance to attack) with different metrics,
and they differ in how independent they are: Shoply's dev split, the
real-world CVE cases and the 13 development real PRs were all used to tune
prompts and rules, while the 17 held-out real PRs were chosen after the last
change and run without tuning. One pooled F1 would mix tuned and untuned data.
Read them side by side; the [summary at the end of this
section](#all-results-at-a-glance) does that.

### 0. Real PRs that introduced published vulnerabilities (main result)

Each case is a GitHub Security Advisory in an open-source Python web app. LGTM
reviews two diffs: the commit or PR that **introduced** the flaw (a flag is a
true positive) and the commit that **fixed** it (a flag is a false alarm). A
catch is **exact** when a finding is in a file the advisory names and its CWE
matches the advisory's class. The held-out set (8 SQLi, 9 authz) was picked
after the SQLi reviewer was written and has not been tuned on.

```bash
model/deploy/judged-up.sh 4:00:00   # Qwen + Kev on the GPU cluster; then connect.sh / kev-connect.sh <job>
python benchmark/real_prs/run_real_prs.py --cases-file benchmark/real_prs/heldout.json \
    --gpu-model qwen3.8-27b --modes lgtm llm-only sast-only --output benchmark/results/heldout
python benchmark/real_prs/run_real_prs.py --gpu-model qwen3.8-27b --modes lgtm llm-only   # development set
```

Final results (Qwen3.8 27B, T=0; the same in all three runs):

| Mode | Held-out caught | Exact | SQLi exact | Authz exact | False alarms on fixes | Development set caught (exact) |
|---|---|---|---|---|---|---|
| `lgtm` | **15/17** | **14/17** | 7/8 | 7/9 | 1/17 | 13/13 (13), 2 false alarms |
| `lgtm-no-sast` | 14/17 | 13/17 | 6/8 | 7/9 | 3/17 | not run |
| `llm-only` | 7/17 | 7/17 | 4/8 | 3/9 | 2/17 | 7/13 (6), 0 false alarms |
| `sast-only` | 3/17 | 3/17 | 3/8 | 0/9 | 2/17 | 0/13 |

The same pipeline with other reviewer models (one run at T=0 for gpt-oss,
provider default temperature for Claude; three runs each for all but gpt-oss
20B):

| Reviewer in `lgtm` | Caught (runs) | False alarms on fixes (runs) | Bedrock cost, run 1 |
|---|---|---|---|
| Qwen3.8 27B (GPU cluster) | 15, 15, 15 | 1, 1, 1 | free (cluster) |
| gpt-oss 20B | 7 | 1 | USD 1.43 |
| gpt-oss 120B | 16, 15, 15 | 5, 7, 4 | USD 2.60 |
| Claude Haiku 4.5 | 16, 16, 16 | 8, 6, 11 | USD 9.31 |
| Claude Sonnet 4.6 | 16, 16, 17 | 5, 5, 3 | USD 22.06 |

Missed by Qwen in every run: `django-orderby-dotted-column-sqli` (the flaw is
a removed check deep in Django's ORM) and
`readthedocs-team-access-filter-authz` (two chained `.filter()` calls on a
many-valued relation). Per-advisory outcomes, temperature runs and the
repeatability analysis are in
[`benchmark/runs/final-2026-11/RESULTS.md`](benchmark/runs/final-2026-11/RESULTS.md).

### 1. Shoply (synthetic)

`benchmark/` contains **Shoply**, a Flask e-commerce API with token auth
and RBAC, plus **26 matched PR pairs** (52 cases): 12 SQL-injection pairs
(6 hand-written + 6 derived from the OWASP Benchmark SQLi taxonomy,
translated to Python/Flask; vulnerable vs
parameterized-but-SAST-triggering controls) and 14 authorization pairs
(IDOR, missing/incorrect role checks, API-key scope violations —
invisible to SAST by design).

```bash
python benchmark/evaluate.py --gpu-cluster --mode lgtm
python benchmark/evaluate.py --gpu-cluster --mode llm-only
python benchmark/evaluate.py --gpu-cluster --mode lgtm --split eval   # held-out half only
```

The benchmarks run two conditions: LGTM (the full pipeline, including
Semgrep) and LLM-only. The reviewer is `qwen3.8:27b` on the SCIS GPU cluster
and the judge is Kev (Kev-4B). Claude Opus 5.5 labels the benchmark
findings under `docs/kev-labeling-criteria.md`.

Reported metrics: precision / recall / F1 (overall and per category),
false-positive rate on safe controls, evidence grounding rate,
`possible` / `insufficient_evidence` rates, median latency and estimated
tokens per PR. See `benchmark/README.md` for details.

A case where the pipeline raises, or where an agent reports an
execution, LLM or unparsable-output failure, is recorded as `ERROR`.
Errors are left out of TP/FP/TN/FN and out of precision, recall and F1.
The summary reports `scored`, `errors`, `error_rate` and `error_cases`,
and metrics that cannot be computed are `null`.

The 52 cases carry a balanced **dev/eval split** (13 vulnerable + 13 safe in
each), recorded in the `split` field of `labels.json`: tune prompts and
config on `--split dev`, report results on the held-out `--split eval`.

Results: the run writes its summary to the Shoply run folder under
`benchmark/runs/` (`summary.json`). Final run (all 52 cases,
`benchmark/runs/final-2026-11/shoply/`): `lgtm` 26 TP, 0 FP, 0 FN, 26 TN
(F1 1.00); `llm-only` F1 0.94 (1 false alarm, 2 authz misses). Shoply was
written by the team and tuned on, so it shows the pipeline works end to end
rather than how well it generalises.

### 2. Real-world CVEs

12 cases built from 6 published advisories in open-source Python
projects (3 SQLi, 3 authz; a vulnerable and a safe PR each). The real-world
set is the development set: prompts, rules and config are tuned against it.
The synthetic eval split (`--split eval`) is the held-out check.
`alerta_sqli_vulnerable`, `alerta_sqli_safe` and
`postgraas_sqli_safe` are out of scope.

```bash
python benchmark/real_world/fetch.py                     # clone + build case branches
python benchmark/real_world/evaluate_real.py --gpu-model qwen3.8-27b --modes lgtm llm-only
python benchmark/real_world/batch.py <results-root>      # next unrun batch of the real-world set
python benchmark/guard.py <results-root>                 # eval split in lgtm mode, flips against the last guard run
```

Each `batch.py` run writes `batch-<n>/bundle.json` under the results root when
the batch finishes; running the same command again continues with the next
unrun batch. `guard.py` writes `guard/flips.json` under the results root. See
[`benchmark/real_world/README.md`](benchmark/real_world/README.md).

Results: final run in `benchmark/runs/final-2026-11/real_world/`; earlier
rounds in `benchmark/runs/archive/real_world/`; write-up in
[`docs/real-world-eval.md`](docs/real-world-eval.md). Final run, 9 in-scope
cases: `lgtm` F1 0.91 (1 false alarm), `llm-only` F1 1.00. Counting every case,
both modes catch all 6 vulnerable cases; `lgtm` raises 2 false alarms on the 6
safe ones. The vulnerable cases are synthetic reverts of a fix, which is why
the real-PR benchmark above replaced this set as the main result.

### 3. Prompt injection

6 attack cases: vulnerable Shoply cases with the vulnerable code unchanged,
plus comments, docstrings, fake JSON findings, renamed identifiers or docs
aimed at the reviewer. **Attack success rate (ASR)** = cases flagged
`vulnerable` originally but not once injected, out of those flagged
originally (lower is better).

```bash
python benchmark/injection/run_injection_bench.py --mode lgtm --model qwen3.8:27b
python benchmark/injection/run_injection_bench.py --mode llm-only --model qwen3.8:27b
```

Results: final run in `benchmark/runs/final-2026-11/injection/`, where
**0 of 6 attacks succeeded** in either mode; earlier rounds in
`benchmark/runs/archive/injection-results/` (see
[`docs/prompt-injection.md`](docs/prompt-injection.md)). The mitigations are
on by default in lgtm mode (§7 there; the dev-split comparison is archived in
`benchmark/runs/archive/run7-mitigation-defaults/`).

### 4. Field trial on ordinary merged PRs

12 merged PRs from mealie (FastAPI), alerta (Flask) and redash (Flask) that
touch route handlers, permission helpers or database code. Every PR was
accepted by its maintainers, so this measures crash rate, latency and
false alarms on everyday traffic, not detection.

```bash
python benchmark/field_trial/run_field_trial.py --fetch
python benchmark/field_trial/run_field_trial.py --modes lgtm llm-only
```

Results: final run summarised in
[`benchmark/runs/final-2026-11/RESULTS.md`](benchmark/runs/final-2026-11/RESULTS.md):
no crashes, 1 of 12 PRs flagged in each mode, median 78 s per PR for `lgtm`.
The flagged PR is a possible real issue that has not been reported upstream,
so its per-PR records are kept out of this public repository. Earlier rounds:
`benchmark/runs/archive/field_trial/summary.json`; write-up in
[`docs/field-trial.md`](docs/field-trial.md).

### 5. Component benchmark

Scores single stages (retrieval, investigator, authz reviewer, SAST triage,
evidence validator, Kev judge) on the 12 real-world cases against draft gold
labels. The labels were drafted by Claude Opus 5.5 and have not all been
reviewed by the team, so these figures are provisional. The final run's
figures are in
[`benchmark/runs/final-2026-11/RESULTS.md`](benchmark/runs/final-2026-11/RESULTS.md)
(component section) and the method in
[`docs/component-bench.md`](docs/component-bench.md). In that run the authz
reviewer on its own was noisy (precision 0.29 over 6 units), while the Kev
judge's verdict was right for 13 of 15 candidates, which is why the judge
sits after the reviewers.

### All results at a glance

Final evaluation, Qwen3.8 27B reviewer and Kev-4B judge, commit `af878ce`:

| Benchmark | Tuned on? | `lgtm` | `llm-only` (same model, diff only) | Semgrep only |
|---|---|---|---|---|
| Real PRs, held-out (17 advisories) | No | 15/17 caught, 1/17 false alarms | 7/17, 2/17 | 3/17, 2/17 |
| Real PRs, development (13) | Yes | 13/13 caught, 2/13 false alarms | 7/13, 0/13 | 0/13, 0/13 |
| Shoply (52 synthetic) | Yes | F1 1.00 | F1 0.94 | not run in final |
| Real-world CVEs (9 in scope) | Yes | F1 0.91 | F1 1.00 | not run in final |
| Prompt injection (6 attacks) | Yes | 0/6 succeeded | 0/6 succeeded | n/a |
| Field trial (12 ordinary PRs) | No | 0 crashes, 1 flagged, 78 s median | 0 crashes, 1 flagged, 7 s median | n/a |

What this says: on tuned or synthetic sets a plain LLM is nearly as good as
the full pipeline, but on real PRs we did not tune on, the agents (repository
tools, policy retrieval, the SQLi reviewer, the judge) double the catch rate
at the same false-alarm level. The price is time: about 2 minutes per diff
against 7 seconds.

The full history of rounds, failures, fixes and lessons is in
[`docs/evaluation-log.md`](docs/evaluation-log.md); the checkpoint report
is [`docs/checkpoint.md`](docs/checkpoint.md).

### Dataset roadmap

- ✅ 6 SQLi pairs derived from the OWASP Benchmark taxonomy (Java →
  Python/Flask translation), keeping positives and negatives balanced.
- ✅ 6 published CVEs in real Python web projects (3 SQLi, 3 authz) as 12
  development-set cases; see
  [`docs/real-world-eval.md`](docs/real-world-eval.md).
- ✅ 6 prompt-injection cases (comments, docstrings, fake JSON findings,
  renamed identifiers, a policy-exemption doc, delimiter escapes); see
  [`docs/prompt-injection.md`](docs/prompt-injection.md).
- ✅ 30 real PRs that introduced published advisories (13 development, 17
  held-out), each with its fix commit; see
  [`docs/real-prs-eval.md`](docs/real-prs-eval.md).
- ✅ 12 ordinary merged PRs as a field trial; see
  [`docs/field-trial.md`](docs/field-trial.md).
- Next: a larger held-out set (17 advisories means one case moves the rate
  by 6 points), more OWASP patterns (stacked queries, second-order
  injection), and team-reviewed labels for the component benchmark.
- Keep the held-out sets held out: prompt and config tuning uses the Shoply
  dev split, the real-world CVEs and the development real PRs only.

## Project layout

```
src/lgtm/
├── cli.py                  # click CLI: lgtm index / lgtm review
├── config.py               # LGTMConfig dataclass
├── pipeline.py             # orchestrator (lgtm / llm-only)
├── diff/git_diff.py        # git diff extraction + unified diff parser
├── diff/sanitizer.py       # comment stripper + prompt-injection detector
├── analysis/facts.py       # AST facts for the agents (static_facts flag)
├── sast/semgrep_runner.py  # semgrep subprocess + JSON parsing
├── sast/rules/             # bundled CWE-89 semgrep rules
├── rag/indexer.py          # doc discovery, chunking, ChromaDB indexing
├── rag/retriever.py        # top-k policy retrieval with line metadata
├── graph/runner.py         # codegraph subprocess: init and explore, timeouts
├── graph/session.py        # per-snapshot graph session and failure state
├── graph/exporter.py       # committed-snapshot export to temporary directories
├── graph/snapshot.py       # commit SHA resolution
├── graph/format.py         # tool output formatting
├── agents/tools.py         # read-only snapshot tools, graph tools, call budget
├── agents/sast_triage.py   # CWE-89 triage agent
├── agents/authz_reviewer.py# CWE-639/862/863 section reviewer
├── agents/plain_reviewer.py# tool-free LLM-only baseline (Baseline B)
├── validation/evidence.py  # citation validator (anti-hallucination)
└── reporting/report_builder.py  # JSON + Markdown reports
tests/                      # unit and integration tests, no Ollama needed
benchmark/                  # Shoply app, 52 cases, evaluate.py
benchmark/real_world/       # 12 real-world CVE cases, fetch.py, evaluate_real.py
benchmark/injection/        # 6 prompt-injection cases, run_injection_bench.py
```

## Development

```bash
pytest tests/ -q                           # unit + integration tests
python benchmark/tools/generate_cases.py   # regenerate patches + labels
```
