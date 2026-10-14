# SMU SCIS GPU Cluster — Context and Operating Instructions

> **Purpose:** Accurate operational context for preparing, transferring, running, and accessing Jupyter notebooks on Singapore Management University's School of Computing and Information Systems (SCIS) GPU Cluster.

## 1. Executive model of the cluster

The SCIS GPU Cluster provides shared computing resources for Python workloads, including GPU-enabled Jupyter notebooks. Users access it primarily through a command-line interface (CLI), and GPU/CPU resources are provisioned through cluster-managed jobs rather than by running heavy processes directly on the login node.

- Each project group is provisioned a **group account**.
- Multiple students may access the same group account simultaneously.
- The **login node is for access and lightweight management**: **do not run computationally intensive tasks on it**.
- Notebook compute is time-limited; jobs are subject to resource availability.
- **Interactive notebooks** are temporary sessions, not a guaranteed always-on web service.
- **Background notebook execution** is the documented option for long-running, unattended workloads.

**Critical architectural implication:** Write code and notebooks in a reproducible project directory; request resources using the cluster's documented tools; run computation only inside an allocated job; save outputs and checkpoints to verified persistent storage; and release unused resources promptly.

## 2. Network access and SSH authentication

### Required connectivity

- SCIS requires connection to **GlobalProtect VPN** to access the cluster, including when on campus according to the presentation.
- Connect to **only one VPN at a time**.
- **Never share credentials**.
- On Windows, the introduction recommends the **64-bit GlobalProtect client**.
- On macOS, it highlights installing the GlobalProtect **System Extension**.

### Login command

From Windows PowerShell or macOS Terminal, **after connecting to GlobalProtect**:

```bash
ssh <GROUP_USERNAME>@10.193.104.102
```

The presentation shows `IS000G1` as an **example account**, not the user's real group username:

```bash
ssh IS000G1@10.193.104.102
```

- A password change is required on first login.
- Password characters will not be displayed while typing.
- Do not hardcode passwords, tokens, or personal credentials in notebooks, scripts, logs, or repository files.
- The `10.193.104.102` address is a **private network address**, not a publicly reachable host; the required VPN must work first.

**Agent instructions:** Never presume possession of the group's username, password, VPN session, or SSH key. Ask the user to establish access through their own approved authentication flow. Avoid changing credentials, SSH configuration, or access controls without consent. Do not disable SSH host-key checks.

Official access documentation referenced by SCIS: <https://violet.scis.dev/docs/Getting%20started/loggingin>

## 3. Supported notebook and job commands

The presentation explicitly describes the following commands. They appear to be **cluster-specific commands/wrappers**; **do not invent positional arguments or flags**. Read their official docs or inspect their help output before scripting them.

| Command | Documented purpose | Important behavior |
| --- | --- | --- |
| `mynotebook` | Request a Jupyter notebook | CPU or GPU-enabled; notebook access uses an SSH tunnel; up to **6 hours**; may fail if no GPU is available; **one notebook at a time** |
| `execnotebook` | Process a notebook in the background | Up to **24 hours**; queues when resources are unavailable; notifies on completion or failure; recommended for long workloads |
| `whichgpu` | Identify the GPU assigned to the user | Useful for confirming placement and monitoring allocated GPU |
| `myqueue` | Show current jobs and their job IDs | Inspect before launching or terminating jobs |
| `scancel <jobid>` | Terminate a job | Requires the **correct** job ID; do not terminate another team member's job inadvertently |

Examples using syntax confirmed in the presentation:

```bash
myqueue
whichgpu
# Example only; replace with a job ID verified to belong to this project:
scancel 16281
```

The PDF shows the literal names `mynotebook` and `execnotebook`, **but does not document their full CLI signatures, flags, notebook path syntax, kernel/environment selection, tunnel port numbers, or output paths**. Never fabricate these details.

Official references (may require an accessible SCIS network environment):

- Interactive notebooks: <https://violet.scis.dev/docs/Interactive%20jobs/jupyter>
- Background notebook jobs: <https://violet.scis.dev/docs/Non-interactive%20jobs/execnotebook>
- GPU monitoring: <https://violet.scis.dev/docs/Advanced%20settings/monitorGPUMetrics>

## 4. Interactive notebooks: development and exploration

Use an **interactive** job for authoring, inspecting results, debugging, iterative experiments, and visual exploration.

**Documented facts:**

1. Connect to the VPN and SSH into the login node.
2. Use `mynotebook` to request a CPU or GPU-enabled Jupyter notebook (exact invocation to be checked).
3. Follow the cluster-provided **SSH tunneling instructions** to reach Jupyter from the user's local browser.
4. Work only within the allocated notebook environment.
5. The notebook runs for **at most 6 hours**, and only **one notebook at a time** is supported.
6. If no GPU is available, GPU notebook allocation may fail.
7. **Terminate the job when finished.**

**Agent implementation guidance (proposal, not a documented cluster feature):**

- Implement GPU detection in notebook code (`torch.cuda.is_available()` for PyTorch, if PyTorch is installed) and a deliberate CPU fallback where feasible.
- Save work and intermediate artifacts regularly; expect sessions to end at the time limit.
- Avoid assuming browser tabs, VPN connections, SSH sessions, notebook kernels, or port numbers will persist across runs.
- Prefer an explicit configuration file over hardcoded paths and devices.
- Treat the SSH tunnel as an access mechanism for the current notebook session, **not permanent public hosting**.

## 5. Background notebooks: unattended execution

Use `execnotebook` when a task is long-running, particularly when the user's laptop cannot remain on or connected.

**Documented facts:**

- Jobs run **up to 24 hours**.
- Background execution is described as **fire and forget**.
- If cluster resources are exhausted, the job is **queued**.
- Completion or failure triggers a **notification**; the presentation does not specify the notification channel.
- This workflow is recommended for long workloads instead of keeping an interactive browser/SSH connection continuously open.

**Agent implementation guidance (proposal):**

1. Create an executable, self-contained `.ipynb` with a clear initialization/config cell and deterministic inputs.
2. Ensure datasets and imports are in locations visible to the compute job (verify shared storage semantics first).
3. Write checkpoints and results incrementally to verified durable project storage, not only to notebook memory.
4. Submit through **verified** `execnotebook` usage; do not assume it accepts arbitrary shell scripts or `sbatch`-style flags.
5. Record the returned job ID or reliable submission identifier.
6. Inspect the job with `myqueue` and watch the appropriate logs or outputs **after their actual locations have been verified**.
7. Distinguish queued, running, completed, failed, cancelled, and timed-out states wherever available.
8. Confirm output files exist before reporting success.
9. Resubmit failed work only after determining whether existing checkpoints make resumption safe.

**24 hours is a maximum runtime, not a guaranteed reservation or completion time.** A queued job could start later.

## 6. Job management and GPU observability

### Jobs

```bash
myqueue
scancel <jobid>
```

The PDF shows `myqueue` for listing current jobs (including IDs) and `scancel` for cancelling a specified job. Since accounts may be shared by multiple students, **confirm job ownership and purpose before cancellation**.

### GPU usage

```bash
whichgpu
```

The presentation also points to an SMU intranet GPU usage page:

<https://green.smu.edu.sg/gpustats>

It is labeled **SMU intranet only**. Monitoring includes allocated GPU identity, utilization, and used/remaining GPU memory. No specific GPU models, available VRAM sizes, quotas, or concurrency guarantees are included in the slides.

### Ordinary shell navigation

```bash
ls
cd <foldername>
cat filename.log
tail -f <filename>   # Ctrl+C to stop following
```

## 7. What “hosting notebooks” means here

The documented cluster provides **interactive Jupyter notebook sessions** and **batch notebook execution**, not confirmed permanent external web hosting.

| Desired result | Documented support | Agent response |
| --- | --- | --- |
| Write and version notebooks | Normal notebook-development workflow; transfer/sync mechanism not specified | Prepare clean `.ipynb` files and a reproducible project structure |
| Open a running notebook in a browser | **Yes**, during an interactive allocation via SSH tunnel | Follow `mynotebook` and the actual tunnel instructions returned by the cluster |
| Execute notebooks without a laptop staying connected | **Yes**, with `execnotebook` | Submit a background job and inspect results later |
| Keep an interactive notebook available indefinitely | **No guarantee**; interactive sessions have a 6-hour cap | Design for restartability and save state |
| Host a persistent public Jupyter server or API | **Not established by the supplied slides** | Do not expose ports or deploy persistent services without a documented permitted mechanism and administrator approval |
| Schedule recurring automated notebook runs | **Not established** by the supplied slides | Ask/verify whether job scheduling is permitted; do not invent cron or scheduler integrations |

**Interpretation for the coding agent:** Aim to make notebooks **accessible while their allocated interactive jobs are alive** and **runnable offline as background jobs**. Do not promise an always-on hosted Jupyter instance.

## 8. Proposed repository design (agent engineering recommendation)

This layout is **recommended**, not an SCIS-specified convention:

```text
project/
├── README.md                  # local and cluster run instructions
├── notebooks/
│   ├── 01_exploration.ipynb
│   ├── 02_training.ipynb
│   └── 03_evaluation.ipynb
├── src/                       # reusable Python modules
│   ├── __init__.py
│   ├── config.py
│   └── pipeline.py
├── configs/
│   └── example.yaml           # no secrets
├── tests/
│   └── test_smoke.py
├── requirements.txt           # or another lockable environment spec
├── scripts/
│   └── verify_environment.py
├── data/                       # dataset handling depends on cluster storage policy
├── outputs/                    # checkpoints and metrics; avoid committing large outputs
├── .gitignore
└── AGENTS.md                   # coding-agent constraints from this document
```

Implementation expectations:

- Keep substantive computation in importable Python modules, with notebooks as readable orchestration and visualization layers.
- Make notebook execution **non-interactive** where possible: no input prompts, UI clicks, manual file pickers, or unconfigured secrets.
- Validate Python/library versions, CUDA/device visibility, dependencies, data paths, and write access **inside an allocated compute environment**.
- Use small smoke-test data before expensive GPU work.
- Save checkpoints and structured metrics; include reproducible seeds when appropriate.
- Allow a safe CPU path for development when a GPU is unavailable, but don't pretend CPU execution validates GPU-specific behavior.
- Add a configuration option for output paths and verify they persist after the job ends.
- Keep large datasets and checkpoint binaries out of Git unless explicitly required.
- Never install packages globally or alter shared environment setup without verifying local cluster policy. Prefer a project-owned environment if supported.
- Never run the actual training/sustained inference from the SSH login node.

## 9. Required discovery before automating anything

The PDF does **not** provide enough low-level instructions to fully automate deployment safely. Once the user has established authorized access, the agent must verify:

1. **Account and connection:** correct group username; VPN state; working SSH; whether SSH key-based login is permitted.
2. **Shell commands:** supported syntax and help output for `mynotebook`, `execnotebook`, `whichgpu`, and `myqueue`; exact cancel semantics.
3. **Interactive access:** actual SSH tunnel command, bind ports, Jupyter address/token flow, and how to shut the session down cleanly.
4. **Execution environment:** OS, default shell, Python version, package/virtual-environment support, CUDA availability, preinstalled libraries, and available kernels.
5. **Storage:** home/project directories, disk quotas, shared file systems, persistence after jobs, scratch cleanup, and permitted dataset locations.
6. **Data movement:** whether `scp`, `sftp`, Git, VS Code Remote SSH, or another sync mechanism is supported and allowed.
7. **Job resources:** GPU types, VRAM, partitions/queues, CPU/RAM limits, concurrency limits, request flags, and waiting behavior.
8. **Background output:** exact `execnotebook` input path, output notebook/log paths, return values, notification channel, timeout behavior, and resumption support.
9. **Networking restrictions:** outbound connectivity, package installation, public inbound access, and whether APIs or persistent web services are allowed.
10. **Collaboration:** safe procedures under the shared group login; directory ownership, Git workflow, naming conventions, and coordination to avoid terminating someone else's work.

If a fact is unknown, report it as **unknown / needs cluster verification**. Do not use generic Slurm commands such as `sbatch`, `srun`, `squeue`, or `sinfo` as though the PDF endorsed them; the presentation does show `scancel`, but this alone is insufficient to establish a fully supported direct Slurm workflow.

## 10. Agent execution plan

### Phase A — Prepare locally (no cluster access required)

- Inspect existing source code, datasets, and notebook needs.
- Build `.ipynb` notebooks and reusable modules.
- Include dependency specifications, smoke tests, and execution documentation.
- Ensure no large training runs are triggered merely by importing modules.
- Establish predictable filenames for logs, model checkpoints, metrics, and notebook outputs.

### Phase B — Verify authorized cluster access

- Ask the user to establish GlobalProtect VPN and authenticate with their assigned group credentials.
- Connect using `ssh <GROUP_USERNAME>@10.193.104.102` only with authorization.
- Inspect actual command help and official documentation and record confirmed command syntax.
- Confirm files can be transferred and that persistent project storage exists.

### Phase C — Smoke test on an allocated job

- Use an approved CPU interactive notebook or GPU interactive notebook, as needed.
- Verify imports, device access, read/write permissions, and execution of a tiny sample.
- Test the SSH tunnel as documented, without opening Jupyter to a public interface.
- Cleanly terminate the temporary job after validation.

### Phase D — Execute the real workloads

- Short interactive work: use `mynotebook` (subject to one-at-a-time and six-hour limits).
- Long work: use `execnotebook` (subject to 24-hour cap and possible queue time).
- Confirm output/checkpoints survive completed sessions and can be downloaded or reopened.
- Track job IDs and avoid unrelated shared-account jobs.

### Phase E — Report back

Return:

- Where the notebooks and source files are stored.
- Confirmed cluster access/run commands, **with actual flags from the environment rather than guesses**.
- The difference between interactive and background launch steps.
- The actual tunnel/access steps for the active interactive session, if any.
- Expected outputs and their verified durable locations.
- Job identifiers, current status, and any failure/timeout evidence.
- Any open items requiring the user's action or SCIS administrator guidance.

## 11. Hard constraints

1. **NEVER run heavy processing on the login node.**
2. **NEVER assume an interactive allocation lasts longer than six hours.**
3. **NEVER assume a background notebook can run longer than 24 hours.**
4. **NEVER launch multiple simultaneous interactive notebooks for the group when the documented limit is one.**
5. **NEVER fabricate cluster-specific command flags, ports, storage paths, GPU types, quotas, or hosting capabilities.**
6. **NEVER expose notebooks, tokens, private datasets, or SSH endpoints to the public internet.**
7. **NEVER store passwords, access tokens, or other credentials in source code or agent context.**
8. **NEVER cancel a job until its ID and ownership are established.**
9. **ALWAYS design notebook runs to save outputs and tolerate time-limited sessions.**
10. **ALWAYS label inferences/recommendations separately from verified cluster capabilities.**

## 12. Source links and escalation

- SCIS GPU Cluster documentation landing page: <https://violet.scis.dev>
- SSH access: <https://violet.scis.dev/docs/Getting%20started/loggingin>
- Interactive Jupyter: <https://violet.scis.dev/docs/Interactive%20jobs/jupyter>
- Background notebook execution: <https://violet.scis.dev/docs/Non-interactive%20jobs/execnotebook>
- GPU metrics: <https://violet.scis.dev/docs/Advanced%20settings/monitorGPUMetrics>
- SMU-only GPU monitoring: <https://green.smu.edu.sg/gpustats>
