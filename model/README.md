# Model server on the SCIS Origami GPU cluster

A standalone component that serves an Ollama model from an Origami GPU and
exposes it on the laptop as `http://127.0.0.1:11435`. It knows nothing about
LGTM; any Ollama client (LGTM's `--ollama-url`, `curl`, LangChain) can use it.

```text
model/
├── .env.example          # per-user settings → copy to .env (gitignored)
├── src/                  # code that runs on the cluster
│   ├── serve_model.ipynb # start Ollama, pull + load the model, publish the endpoint
│   ├── pull_models.ipynb # pre-download $MODELS into scratch (no GPU)
│   └── ollama_server.py  # shared helper, standard library only
├── jobs/                 # sbatch definitions that run the notebooks headless
└── deploy/               # laptop-side commands (bash; Git Bash on Windows)
```

## How it works

```text
laptop                               origami (login)                compute node (e.g. block)
deploy/sync.sh  ── git archive ────▶ ~/llm-serve/app/<hash>/
deploy/up.sh    ── sbatch ─────────▶ Slurm ───────────────────────▶ serve.sbatch
                                                                     └─ serve_model.ipynb
                                                                        ├─ ollama serve 127.0.0.1:<random>
                                                                        └─ ~/llm-serve/run/<job>.env
deploy/connect.sh ── ssh -J origami <node> -L 11435:127.0.0.1:<port> ─▶ Ollama
```

- **The notebooks are the serving code.** `serve_model.ipynb` runs the same
  way in a `mynotebook` session (leave the shutdown cell unexecuted) and
  headless in a Slurm job
  (`jobs/lib.sh` runs its code cells as one script, so output streams into
  the job log). They use only the standard library and avoid IPython magics
  for that reason.
- **Endpoint discovery:** once the model is loaded and has answered a test
  prompt, the notebook writes `~/llm-serve/run/<jobid>.env` (`NODE`, `PORT`,
  `MODEL`, mode 0600). `connect.sh` reads it, so it works the same whether
  the server was started by `up.sh` or by hand in `mynotebook`.
- **Loopback only, random port.** Nodes are shared and Ollama has no auth;
  the server is reachable only through the SSH jump via the login node.
- **Content-addressed releases.** `sync.sh` uploads the working copy of
  `model/` (uncommitted edits included, `.gitignore`d files excluded) to
  `~/llm-serve/app/<tree-hash>` and repoints `app/current`; unchanged code
  uploads nothing. `~/llm-serve/notebooks` links to `app/current/src` for
  opening in `mynotebook`. Edit locally and sync; edits made on the cluster
  are overwritten by the next release.
- **Host keys:** compute-node keys are fetched through the trusted login node
  (`ssh-keyscan`) into `model/.state/known_hosts`, so checking stays strict
  without prompts. `~/.ssh/config` and `~/.ssh/known_hosts` are not touched.
- **Model weights stay on the cluster** in `$SCRATCH_DIR/ollama-models`;
  nothing is downloaded to the laptop.

## One-time cluster setup

Each teammate runs these steps on their own laptop using their own SCIS
cluster account. You need permission to submit GPU jobs and a writable
scratch directory. Do not share passwords, private SSH keys, or `model/.env`.
The steps below use Windows PowerShell for SSH setup and Git Bash for the
scripts; Git must be installed and this repository cloned locally.

### 1. Check cluster access

Connect to SMU WLAN with a healthy ClearPass, or the SMU VPN off campus.
In PowerShell, replace `YOUR_USERNAME` with your cluster username:

```powershell
ssh YOUR_USERNAME@10.193.104.102
```

On first connection, verify the host fingerprint against the cluster's
trusted instructions before accepting it. Enter your cluster password,
run `myinfo` to check your Slurm account, partition and QOS, then `exit`
to return to your laptop. If you cannot log in or lack GPU-job access,
resolve that with the cluster administrator before continuing.

### 2. Set up your SSH key

In normal PowerShell, create a key and upload **only the public key**.
If this key already exists, reuse it rather than overwriting it.

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\id_ed25519_origami
Get-Content $env:USERPROFILE\.ssh\id_ed25519_origami.pub | ssh YOUR_USERNAME@10.193.104.102 "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
```

Use a passphrase when prompted. Open PowerShell **as Administrator** once:

```powershell
Get-Service ssh-agent | Set-Service -StartupType Automatic
Start-Service ssh-agent
```

Back in normal PowerShell, load the key and check password-free login:

```powershell
ssh-add $env:USERPROFILE\.ssh\id_ed25519_origami
ssh -i $env:USERPROFILE\.ssh\id_ed25519_origami -o BatchMode=yes YOUR_USERNAME@10.193.104.102 "whoami"
```

The last command should print your cluster username without asking for a
password. The scripts use Windows OpenSSH and its SSH agent for the jump
to the compute node. If authentication fails, check the username, uploaded
public key, and `ssh-add -l` before running the scripts.

### 3. Fill in your local settings

Open Git Bash in the repository root. If `model/.env` already exists,
skip the copy and edit it instead:

```bash
cp model/.env.example model/.env
```

Open `model/.env` in your editor and replace every `<...>` placeholder:

| Setting | What to enter |
|---|---|
| `ORIGAMI_USER` | Your cluster username, not your email address |
| `ORIGAMI_SSH_KEY` | `~/.ssh/id_ed25519_origami`, or the path to your own private key |
| `NOTIFY_EMAIL` | Your email address for job notifications |
| `SCRATCH_DIR` | Your writable cluster scratch path; the template uses `/common/scratch/users/<initial>/<smu-username>`—confirm your actual path |
| `SLURM_ACCOUNT`, `SLURM_PARTITION`, `SLURM_QOS` | Values allowed for your account, checked with `myinfo`; use `se201`, `student`, `studentqos` only if you have access |

Leave the other settings at their defaults for the first run. `model/.env`
is gitignored and is a shell settings file: do not put your cluster password
or private-key contents in it. Each account gets its own remote files and
model cache.

### 4. Download the model and start a job

In Git Bash, from the repository root:

```bash
model/deploy/provision.sh
model/deploy/up.sh
```

`provision.sh` downloads the configured models into your scratch directory
using a CPU job; wait for `COMPLETED` before starting the server. Re-run it
if you change `MODELS`; models already present are skipped.

`up.sh` uploads the notebook code, submits a GPU job using your account,
waits for the model to be ready, and opens the SSH tunnel. Keep that
terminal open. In a second Git Bash terminal, check the connection:

```bash
curl http://127.0.0.1:11435/api/tags
```

You should see JSON listing `qwen2.5:7b`. The model runs only while the job
is active (8 hours by default); the tunnel exposes it on your laptop, not
publicly. To stop the job, run `model/deploy/down.sh` from another terminal.

## Daily use (Git Bash, from the repo root)

| Task | Command |
|---|---|
| Start (or reattach to) a server and tunnel to it | `model/deploy/up.sh [model] [HH:MM:SS]` |
| Reopen the tunnel | `model/deploy/connect.sh [jobid]` |
| Push code changes | `model/deploy/sync.sh` (`up.sh`, `run.sh` and `provision.sh` sync first) |
| Run a notebook headless | `model/deploy/run.sh src/<notebook>.ipynb [HH:MM:SS]` |
| Watch | `model/deploy/status.sh`, `model/deploy/logs.sh [jobid] [-f]` |
| Stop | `model/deploy/down.sh [jobid\|all]` |

**Interactive alternative:** start `mynotebook` (GPU, Python-only is
enough), open `~/llm-serve/notebooks/serve_model.ipynb`, run the cells up to
and including endpoint publishing, then run `model/deploy/connect.sh` on
the laptop. Leave the final shutdown cell unexecuted while serving.
Run the notebook's last cell (or end the session) to stop it.

With the tunnel open:

```bash
curl http://127.0.0.1:11435/api/tags
lgtm review --repo /path/to/repo --base main --pr feature-branch --gpu-cluster
python benchmark/evaluate.py --gpu-cluster
```

`--gpu-cluster` selects `http://127.0.0.1:11435` and `qwen2.5:7b`; it does
not start the server or tunnel. `--model` and `--ollama-url` override these
defaults, including when the tunnel uses a different local port.

## Cluster facts (verified 2026-10-13)

| | |
|---|---|
| Login | `10.193.104.102` = `origami.smu.edu.sg`; Slurm cluster `crimson` |
| Account / partition / QOS | `se201` / `student` / `studentqos` |
| `studentqos` limits | 2 running · 4 submitted · 4 CPU · 32G RAM · 1 GPU · 1 day per job |
| GPU | MIG slice `1g.24gb` (24 GB) of an RTX PRO 6000 Blackwell on `block` |
| Python | `Python/3.11.11-GCCcore-13.3.0` (the docs' `3.11.7` does not exist); `module` needs a login shell, hence `#!/bin/bash -l` |
| Ollama | `/common/public/ollama/bin/ollama` v0.34.2; shared models in `/common/public/ollama/models` are read-only |
| Internet from compute nodes | Ollama registry, PyPI, GitHub and Hugging Face reachable |
| Storage | home and scratch share one 704 TB filesystem; `myinfo`'s quota line is broken |

Model sizing for a 24 GB slice: `qwen2.5:7b` (~4.7 GB) fits with ample room
for context. LGTM needs a model that returns structured tool calls through
Ollama; `qwen2.5-coder` writes them as plain text and fails the agent loop.
A `mynotebook` session counts against the 2-running-jobs limit.

## Troubleshooting

- **`Host key verification failed`:** a node was re-keyed; delete its line
  from `model/.state/known_hosts` and reconnect.
- **Job stays `PENDING`:** `status.sh` shows the reason;
  `QOSMaxJobsPerUserLimit` means two jobs are already running.
- **Server never becomes ready:** `logs.sh <jobid>` for the notebook output,
  and `~/llm-serve/logs/ollama-<jobid>.log` on the cluster for Ollama itself.
- **Port 11435 in use on the laptop:** change `LOCAL_OLLAMA_PORT` in `.env`.
