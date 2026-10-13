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
  way in a `mynotebook` session (*Run All*) and headless in a Slurm job
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

## One-time setup

1. **Network:** SMU WLAN with a healthy ClearPass, or the SMU VPN off campus.
2. **SSH key** (PowerShell on the laptop):
   ```powershell
   ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\id_ed25519_origami
   type $env:USERPROFILE\.ssh\id_ed25519_origami.pub | ssh <user>@10.193.104.102 "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
   # Administrator PowerShell, once:
   Get-Service ssh-agent | Set-Service -StartupType Automatic; Start-Service ssh-agent
   # normal PowerShell:
   ssh-add $env:USERPROFILE\.ssh\id_ed25519_origami
   ```
   The scripts call the Windows OpenSSH client so they can use this agent;
   the jump to the compute node relies on the agent holding the key.
3. `cp model/.env.example model/.env` and fill it in.
4. `model/deploy/provision.sh` pre-downloads `$MODELS` in a CPU job. Re-run
   after changing `MODELS`; present models are skipped.

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
enough), open `~/llm-serve/notebooks/serve_model.ipynb`, *Run All*, then run
`model/deploy/connect.sh` on the laptop. Run the notebook's last cell (or end
the session) to stop it.

With the tunnel open:

```bash
curl http://127.0.0.1:11435/api/tags
lgtm review ... --ollama-url http://127.0.0.1:11435 --model qwen2.5:7b
```

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
