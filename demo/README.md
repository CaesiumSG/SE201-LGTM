# LGTM: the GitHub App and its dashboard

LGTM runs as a real GitHub App owned by `cyberjj999`. When a pull request is opened or updated in a connected repository, LGTM:

1. creates an in-progress **check run** on the PR,
2. fetches the base and head commits with the app's installation token,
3. runs the real pipeline in `lgtm` mode (Semgrep, investigator and section reviewers, evidence checks, Kev judge),
4. completes the check run with a summary and **line annotations**, failing it when a finding is at or above the policy severity,
5. posts a **pull-request review** with inline comments on the flagged lines (request changes when the check fails),
6. stores the run, its findings, agent trace and log in SQLite for the dashboard.

The dashboard (http://127.0.0.1:8765/) has sign in with GitHub, onboarding, an org overview, a pull-request feed with live progress, a findings inbox, per-repository pages, the benchmark accuracy page and settings. Three skins sit over the same app: **Ledger** (Vercel-like), **Night shift** (Linear-like) and **Console** (Datadog/Snyk-like). Switch them in the header or under Settings → Appearance.

The benchmark runs appear in the history as **Imported from benchmark**: those reviews ran on cached clones of public projects, and LGTM was never installed on those repositories.

## Before presenting (about 10 minutes)

1. **VPN on**, then start the GPU job (Qwen reviewer and Kev judge) from the main checkout:

   ```bash
   cd /Users/lyejiajun/projects/se201-lgtm
   model/deploy/judged-up.sh 2:30:00        # prints the job id
   model/deploy/connect.sh <job>            # Qwen on 127.0.0.1:11435; keep it running
   model/deploy/kev-connect.sh <job>        # Kev judge on 127.0.0.1:8008; keep it running
   ```

2. **Start LGTM** from the repository root (the webhook relay and the polling fallback start with it):

   ```bash
   /Users/lyejiajun/projects/se201-lgtm/.venv/bin/python demo/server.py
   ```

3. Open http://127.0.0.1:8765/ and **sign in with GitHub**. The status dots in the header should show Reviewer, Judge and Webhooks all green. If Webhooks is amber, the relay is down; polling still picks up new PRs within 30 seconds.

4. After the demo: `model/deploy/down.sh <job>`.

## The live demo

- **Demo repository** `cyberjj999/shoply-demo` (public): a small Flask shop. Three branches are ready to open as PRs:
  - `feature/user-search`: user search built with an f-string SQL query (SQL injection, CWE-89),
  - `feature/order-details`: order lookup with no ownership check (IDOR, CWE-639),
  - `feature/paged-orders`: pagination with bound parameters (safe; LGTM should pass it).
- **Real-world replay** `cyberjj999/taiga-back-replay` (private, not a fork): taiga-back as of July 2016, with the commit that introduced its epic-order SQL injection (later CVE-2025-62367) on the `epic-order` branch, under its original author. Open it as a PR and LGTM flags it; merging it shows that upstream shipped the bug.

- **Recent real-world replay** `cyberjj999/wagtail-replay` (private, not a fork): wagtail as of 13 August 2026 on `main` (one snapshot commit), and on the `documents-api-v3` branch the change that upstream merged that day as PR 14490 ("Add v3 read/write API for documents", squashed from its 16 commits, original author, diff identical to upstream). It was published as a security advisory on 20 August 2026 (GHSA-c2xx-cjmh-9q8f, medium: improper restriction handling on descendant collections in the Documents and Images API). The Workspace task "Add a read/write API for documents" replays it. Install the LGTM app on this repository before presenting. This one is a published advisory, not a live-hunt lead.
- **Recent real-world replay** `cyberjj999/authentik-replay` (private, not a fork): authentik as of 5 April 2026 on `main` (one snapshot commit), and on the `ssf-conformance` branch the change upstream merged that day as PR 21383 ("enterprise/providers/ssf: test conformance", squashed, original author, diff identical to upstream; 47 files). It added event-stream handlers without the `add_stream` permission check and was published as a security advisory on 15 July 2026 (GHSA-hmrg-vpp4-gj88, moderate). The Workspace task "Make the Shared Signals Framework pass conformance tests" replays it. Install the LGTM app on this repository before presenting. This one is a published advisory, not a live-hunt lead.

Open a PR from the GitHub web UI (or `gh pr create --repo cyberjj999/shoply-demo --head feature/user-search --base main --fill`). The check appears on the PR at once; a review takes about 2 to 3 minutes on the GPU. Follow it live under **Pull requests** in the dashboard.

Rules for anything posted to GitHub from the replay: no links to the upstream project, no `owner/repo#N` references and no @mentions. LGTM's own posts are filtered for these automatically (`github_app.safe_markdown`).

## The workspace tab (write code, push, watch LGTM review it)

**Workspace** in the dashboard is a small IDE over a connected repository: a file tree, file-name and text search, and an editor (Monaco, loaded from jsDelivr). Edits are saved to a working clone in `demo/.data/workspace/`.

- **Scripted tasks** (`workspace_presets.json`) replay a real commit into the editor, typed out live: the three shoply features (two bugs and a safe change, plus the paged-orders fix as a follow-up pushed to the same pull request) and the 2016 taiga-back change later published as CVE-2025-62367. A task resets the editor to the commit before the change; the result is byte-for-byte the original commit.
- **Ask Claude** rewrites the open file from a free-text request, streamed into the editor (Claude Sonnet on Bedrock, a few cents a request, on the shared spend ledger).
- **Commit, push and open a pull request** is real: it commits, pushes a new branch and opens the pull request with the `gh` CLI, as the GitHub account `gh` is signed in as (only when that is also who is signed in to the dashboard). It never force-pushes or pushes to the default branch. Pushing again from the same branch updates the pull request. The panel then follows LGTM's review of that commit and links to the pull request, the check run and the live review.

To replay another published advisory, create a private replay repository the way taiga-back-replay was made, connect it, and add an entry with its `base` (the commit before the change) and `source` (the change) to `workspace_presets.json`. Never add live-hunt leads.

## Recorded run (5 November 2026)

All on Qwen 3.8 27B + Kev-4B unless noted; screenshots in [screenshots/](screenshots/).

| Pull request | What LGTM did |
|---|---|
| shoply-demo #1 "Paginate my orders" | First version let any manager page through every user's orders: blocked for missing authorization (once on Claude via Bedrock with Kev, once on Qwen with Kev, re-run from GitHub's "Re-run" button). After the fix was pushed it passed, dismissed its own "Changes requested" reviews and marked the old findings fixed. |
| shoply-demo #2 "Add user search" | SQL injection (CWE-89), high, `app/routes/users.py:65`; check failed, changes requested. 1 min 49 s. |
| shoply-demo #3 "Add an order detail endpoint" | Insecure direct object reference (CWE-639), high, `app/routes/orders.py:64`. 1 min 29 s. |
| taiga-back-replay #1 (upstream change from 2016) | SQL injection (CWE-89), critical, `taiga/projects/userstories/utils.py:147`, the advisory's location. 2 min 27 s. Then merged, as upstream did. |

Every delivery came through the smee relay with a valid signature. Dashboard sessions live in memory only, so after restarting the server, sign in again (one click; no new GitHub grant).

## Setup (already done once)

1. `demo/server.py` serves `/setup.html`, which sends GitHub an App Manifest. The owner confirms it on GitHub ("Create GitHub App"), and GitHub hands back the app id, private key, webhook secret and OAuth client credentials. They are stored in `demo/.secrets/github-app.json` (mode 600, git-ignored) and never printed.
2. The webhook URL is a smee.io channel (`demo/.secrets/relay.json`). The server reads the channel itself and forwards each delivery to `/api/github/webhook`, which checks the HMAC signature.
3. The owner installs the app on the chosen repositories (GitHub → the app → Install).

Permissions: contents read, metadata read, pull requests write, checks write. Events: pull requests and check runs (installation events are always delivered).

## Files

```
demo/
  server.py        HTTP server: sign-in, manifest flow, webhook endpoint, dashboard API, static files
  github_app.py    GitHub App plumbing: manifest, JWT and installation tokens, OAuth, signatures, safe text
  reviews.py       review engine: queue, fetch, pipeline subprocess, check runs, PR reviews, poller, relay, history import
  store.py         SQLite schema and helpers (demo/.data/lgtm.db)
  results.py       stored benchmark results, normalised (verdict, findings, trace, diff)
  live_runner.py   one pipeline run in a subprocess, streaming @@EVT progress lines
  bedrock_env.py   Bedrock key and spend ledger (the reviewer can run on Claude, capped at +USD 10)
  workspace.py     the Workspace tab: working clones, files, search, scripted replays, Claude, commit and push
  workspace_presets.json  the scripted tasks (real commits to replay)
  web/             the dashboard: index.html, app.js, workspace.js, base.css, skins/{ledger,nightshift,console}.css, setup.html
  .secrets/ .data/ .runs/   git-ignored: credentials, database and clones, earlier demo runs
```

Live-hunt results are never read: most of those leads are undisclosed.
