# Real-world CVE benchmark

Shoply, our synthetic app, is the only thing LGTM has been evaluated on so
far. This directory holds a small **held-out** benchmark built from published
vulnerabilities in open-source Python web projects, so we can see what
happens off our own toy app. Failures are expected and are documented, not
tuned away: no prompt, rule or config is changed to fix a case here.

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
- **Coverage.** Only the `lgtm` and `lgtm-no-sast` records carry coverage;
  `sast-only` and `llm-only` records have none.
- **No security policy.** These projects have no `security-policy.md`; the
  evaluation runs each authorization case with and without a short policy
  written from the project's public documentation.

## Evaluating

```bash
python benchmark/real_world/fetch.py --policies     # also build the policy variants
PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes sast-only --variants own
PYTHONUTF8=1 python benchmark/real_world/evaluate_real.py --modes lgtm --resume --budget 240
```

`evaluate_real.py` reuses the scoring of `benchmark/evaluate.py`. It is built
for short foreground chunks (`--resume` skips units whose result JSON exists
and is not an error, re-runs error results, `--budget` stops starting new cases
after N seconds) and builds a document index for lgtm and lgtm-no-sast
units. Every record carries `pin` (the run pin: LGTM checkout, model, flags,
and base/PR SHAs) and `file`. The lgtm and lgtm-no-sast records also carry
`coverage`, which is `null` when the review reports none, and
`coverage_summary`, which holds the scalar coverage counts and
`exclusions_total`. Each output root holds a `run.json` manifest that carries
`pin`; `--resume` refuses to continue a root produced with a different model
or reasoning setting.
`--gpu-model qwen3.8-27b` selects the GPU tunnel model with thinking disabled
and cannot be combined with `--model`. Results go to
`benchmark/results/real_world/` (git-ignored); curated runs are in
[`benchmark/runs/real_world/`](../runs/real_world/), and the results and
every miss are explained in [`docs/real-world-eval.md`](../../docs/real-world-eval.md).

`policies/<project>.md` are short access-control policies written only from
each project's public documentation; they are what the policy variant adds
as `security-policy.md`.
