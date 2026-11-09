# Real-world CVE benchmark

Shoply, our synthetic app, is the only thing LGTM has been evaluated on so
far. This directory holds a small benchmark built from published
vulnerabilities in open-source Python web projects, so we can see what
happens off our own toy app. The real-world set is the development set:
prompts, rules and config are tuned against it. The synthetic eval split
(`python benchmark/evaluate.py --split eval`) is the held-out check.
Failures are documented.

## Cases

Six advisories (3 SQL injection, 3 authorization), each with a vulnerable and
a safe PR, so 12 cases. Everything is recorded in [`cases.json`](cases.json),
which mirrors the fields of `benchmark/labels.json` plus the provenance.

| Project | Advisory | CWE | Category | Fix commit(s) |
|---|---|---|---|---|
| pyload/pyload | GHSA-pwh4-6r3m-j2rf (CVE-2025-55156) | CWE-89 | sqli | `134edcd` |
| blue-yonder/postgraas_server | GHSA-vghm-8cjp-hjw6 (CVE-2018-25088) | CWE-89 | sqli | `7cd8d01`, `ed2e895` |
| alerta/alerta | GHSA-8prr-286p-4w7j (CVE-2026-34400) | CWE-89 | sqli | `fdd52cd` |
| aegra/aegra | GHSA-m98r-6667-4wq7 (CVE-2026-44504) | CWE-639 | authz | `e1b2042` |
| langflow-ai/langflow | GHSA-rf6x-r45m-xv3w (CVE-2026-33053) | CWE-639 | authz | `fdc1b3b` |
| BerriAI/litellm | GHSA-wpfp-gwwc-vwq6 (CVE-2026-47102) | CWE-863 | authz | `e6f18ce`, `128d32d`, `bdc7265` |

Case ids are `<project>_<sqli|authz>_<vulnerable|safe>`, and `split` is
`real_world` so results can sit beside the synthetic `dev` / `eval` splits.

## How a case is built

Nothing is written by hand; `fetch.py` derives every PR from the fix commit.

- **Safe case** (`construction: fix-commit`): the real history. Base = the
  parent of the fix, PR = the fix commit. This asks whether LGTM raises a
  false alarm on a genuine security fix.
- **Vulnerable case** (`construction: synthetic-revert`): two synthetic
  commits on top of the pre-fix commit. The base commit has the fix's tree
  with every other file the fix touched (tests, docs, ...) at its pre-fix
  content, so it holds the fixed `touched_files` and none of the fix's test
  changes. The PR commit has the pre-fix tree, so the PR diff is exactly the
  reverse of the fix's changes to `touched_files` and neither tree contains
  the tests the fix added.
- **Multi-commit fixes** (postgraas, litellm): `fix_commits` is a linear
  chain; the pre-fix state is the parent of the first commit, and the fix is
  the last commit.

The synthetic commits use a fixed identity and date and are never signed, so
their SHAs are the same on every machine and are recorded as `base_ref` and
`pr_ref`. `fetch.py` rebuilds them and fails if a SHA differs;
`fetch.py --record-refs` writes the built SHAs into `cases.json`.

`vulnerable_locations` (same shape as in `benchmark/labels.json`) lists the
files, and where known the PR-side line ranges, that scoring treats as the
target when the flawed code spans more than `file`. `known_issues` lists
other real vulnerabilities present in the case's PR tree, each with its id,
file, inclusive PR-side `lines`, category, CWE and description; it is empty
when there are none.

## Reproducing the cases

```bash
python benchmark/real_world/fetch.py                       # all cases
python benchmark/real_world/fetch.py --cases aegra_authz_vulnerable
```

This clones each project into `benchmark/real_world/.cache/` (git-ignored)
with `--filter=blob:none`, so file contents are downloaded on demand, then
creates local branches `rw/<case-id>/base` and `rw/<case-id>/pr` in each
clone. It is idempotent, fails loudly if a SHA cannot be fetched, and checks
that `touched_files` in `cases.json` matches what the fix really changes.
Branches are built with git plumbing, so no working tree is touched. The
clones disable `core.autocrlf` so diffs are byte-identical to upstream.

`tests/test_real_world_cases.py` validates `cases.json` and the revert
construction without network access.

## Known limits (details in the write-up)

- **Small n.** Twelve cases: one flip moves F1 a lot. Treat it as a probe of
  failure modes, not a score.
- **Synthetic vulnerable PRs.** A revert is not a PR a developer wrote.
- **Memorisation.** CVE-2018-25088 is old enough that the model may have seen
  it in training.
- **Coverage.** Only the `lgtm` records carry coverage; `llm-only` records
  have none.
- **No security policy.** These projects have no `security-policy.md`; the
  evaluation runs each authorization case with the project's own documentation.

## Evaluating

The benchmark runs two conditions: LGTM (the full pipeline, including
Semgrep) and LLM-only. The CLI modes `sast-only` and `lgtm-no-sast` are for
internal development and benchmarking only; reported results compare `lgtm`
(which includes Kev judging) against `llm-only`.

```bash
python benchmark/real_world/fetch.py                # clone + build case branches
PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --gpu-model qwen3.8-27b --modes lgtm llm-only
```

`evaluate_real.py` reuses the scoring of `benchmark/evaluate.py`. It is built
for short foreground chunks (`--resume` skips units whose result JSON exists
and is not an error, re-runs error results, `--budget` stops starting new cases
after N seconds) and builds a document index for lgtm
units. Every record carries `pin` (the run pin: LGTM checkout, model, flags,
and base/PR SHAs) and `file`. The lgtm records also carry
`coverage`, which is `null` when the review reports none, and
`coverage_summary`, which holds the scalar coverage counts and
`exclusions_total`. Each output root holds a `run.json` manifest that carries
`pin`; `--resume` refuses to continue a root produced with a different model
or reasoning setting.
`evaluate_real.py` exits 4 when git cannot start for two units in a row; it
stops and lists the units it did not run, and `--resume` continues them once
git works. Otherwise it exits 0.
`--gpu-model qwen3.8-27b` selects the GPU tunnel model with thinking disabled
and cannot be combined with `--model`. Results go to
`benchmark/results/real_world/` (git-ignored); the final run is in
[`benchmark/runs/final-2026-11/real_world/`](../runs/final-2026-11/real_world/)
and earlier runs in [`benchmark/runs/archive/`](../runs/archive/), and the results and
every miss are explained in [`docs/real-world-eval.md`](../../docs/real-world-eval.md).

### Batches and the guard run

```bash
python benchmark/real_world/batch.py <results-root>
python benchmark/guard.py <results-root>
```

`batch.py` runs the next unrun batch only, `lgtm` over its cases, into
`<results-root>/batch-<n>/` (n = 1 to 4), with the `qwen3.8-27b` GPU model. The
`llm-only` control of every case is written once under `<results-root>/control/`.
A finished batch writes `<results-root>/batch-<n>/bundle.json`: the batch
number, the commit it ran on, per-case scope, correctness of `lgtm` and of the
control against the labels and the commit each control ran on, totals over the
in-scope cases, and the paths of the per-case `lgtm` result files. Running the same
command again resumes with the next unrun batch; when none remains it says so
and exits 0.

`guard.py` runs the synthetic eval split in `lgtm` mode and writes
`<results-root>/guard/flips.json`: the commit it ran on and, for each case
that went from correct to wrong against the previous complete guard run, the
case id and category. Cases that errored in either run are reported as
unscored. The first run is the reference and reports no flips. It exits 0
whatever the flips; `flips.json` records the evaluator's exit code, and a
non-zero one is printed without the evaluator's output.

`policies/<project>.md` are short access-control policies written only from
each project's public documentation. They and `fetch.py --policies` are
internal-only; `evaluate_real.py` does not use them.

The lgtm records carry `kev_verdict` and `kev_severity` per finding, and each
`summary.json` carries the `kev` metrics described in [`benchmark/README.md`](../README.md).
`--resume` runs a lgtm unit again when its judged candidates lack `kev_verdict`.
