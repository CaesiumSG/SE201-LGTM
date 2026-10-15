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
| blue-yonder/postgraas_server | GHSA-vghm-8cjp-hjw6 (CVE-2018-25088) | CWE-89 | sqli | `7cd8d01` |
| alerta/alerta | GHSA-8prr-286p-4w7j (CVE-2026-34400) | CWE-89 | sqli | `fdd52cd` |
| aegra/aegra | GHSA-m98r-6667-4wq7 (CVE-2026-44504) | CWE-639 | authz | `e1b2042` |
| langflow-ai/langflow | GHSA-rf6x-r45m-xv3w (CVE-2026-33053) | CWE-639 | authz | `fdc1b3b` |
| BerriAI/litellm | GHSA-wpfp-gwwc-vwq6 (CVE-2026-47102) | CWE-863 | authz | `e6f18ce`, `128d32d` |

Case ids are `<project>_<sqli|authz>_<vulnerable|safe>`, and `split` is
`real_world` so results can sit beside the synthetic `dev` / `eval` splits.

## How a case is built

Nothing is written by hand; `fetch.py` derives every PR from the fix commit.

- **Safe case** (`construction: fix-commit`): the real history. Base = the
  parent of the fix, PR = the fix commit. This asks whether LGTM raises a
  false alarm on a genuine security fix.
- **Vulnerable case** (`construction: synthetic-revert`): base = the fix
  commit, PR = a commit on top of it that restores only the **non-test source
  files** the fix touched to their pre-fix content. This is the same code a
  maintainer would have reviewed before the fix, presented as a PR.
- **Two-commit fixes** (litellm): the pre-fix state is the first parent of
  the first commit, and the fix is the last commit.

The synthetic-revert commit uses a fixed identity and date, so its SHA is the
same on every machine and is recorded as `pr_ref`. `fetch.py` rebuilds it and
fails if the SHA differs.

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
- **Endpoint detection.** The authorization agent only reviews endpoints
  whose route decorator appears in a changed hunk, so some authorization
  fixes never reach it.
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
for short foreground chunks (`--resume` skips cases whose result JSON exists,
`--budget` stops starting new cases after N seconds) and builds a document
index only when an agent can actually run. Results go to
`benchmark/results/real_world/` (git-ignored); curated runs are in
[`benchmark/runs/real_world/`](../runs/real_world/), and the results and
every miss are explained in [`docs/real-world-eval.md`](../../docs/real-world-eval.md).

`policies/<project>.md` are short access-control policies written only from
each project's public documentation; they are what the policy variant adds
as `security-policy.md`.
