"""Kev-4B deploy scripts and job file under model/, run against stubbed ssh (no cluster)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import hashlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MODEL = REPO / "model"
BASH = shutil.which("bash")

KEV_COMMANDS = ["provision", "up", "connect", "status", "logs", "down"]
KEV_JOB = "kev-serve.sbatch"
QWEN_PORT = "11435"
KEV_PORT = "8008"
STUB_JOB_ID = "4242"
QWEN_JOB_ID = "1111"

QWEN_SHA256 = {
    "deploy/connect.sh": "c6a787819a424499549a3d0689c0772d49da923fe2cb013597bddd0098b5a62e",
    "deploy/down.sh": "b293f0d9803445516bc16eeb2b1e7419f76e6ca31e00de3eaeab2e6deb7297fd",
    "deploy/logs.sh": "51fc542c8d98fc1c55b8381a3b0e24ee47ac80c4aebba8a26a42225775018d1a",
    "deploy/provision.sh": "581228b2c5ab42dce91643a72c5d1ca2452dadf73bfd2ddb4277b9c3a95715b5",
    "deploy/run.sh": "505e2da09351a3927cd2da8f7c795997b9a5b90a9810585d94784940105bacf7",
    "deploy/status.sh": "b235a9d20e5fc4cdab91bae160c3235790bf88b34ba75c10f90cb3142dd91ae2",
    "deploy/sync.sh": "ee77cbbedf343a61f64a3ecb7a597cba765111a2622b9d2594cd4e31ebcbebeb",
    "deploy/up.sh": "728312ef4245963a8b133110313d65180db9f74c41332a328af696c117e4ccf1",
    "jobs/notebook.sbatch": "8d20d4a8a2b744595f69942f79264c8b946446450d90328176c6d2682b0e3564",
    "jobs/provision.sbatch": "4c7c667e486d42ffb3098f896934bf68a926501ee80784114cd24c3a4f4753ce",
    "jobs/serve.sbatch": "97186b5cd006c0f06c3a5e61880da5f38936975f91b8e8ae18946219a8b9999a",
}

BASE_DEPLOY_LIB = r'''# Sourced by the other deploy scripts.
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_DIR="$(dirname "$DEPLOY_DIR")"
REPO_DIR="$(dirname "$MODEL_DIR")"
STATE_DIR="$MODEL_DIR/.state"
mkdir -p "$STATE_DIR"

die() { echo "error: $*" >&2; exit 1; }

[[ -f "$MODEL_DIR/.env" ]] || die "$MODEL_DIR/.env not found; copy .env.example and fill it in"
set -a
# shellcheck disable=SC1090
source <(tr -d '\r' < "$MODEL_DIR/.env")
set +a

: "${REMOTE_ROOT:=llm-serve}"
: "${LOCAL_OLLAMA_PORT:=11435}"
: "${FALLBACK_GRES:=gpu:rtx_pro_6000_blackwell_max:1}"

# Only the Windows OpenSSH client can use the Windows ssh-agent service.
if [[ -x /c/Windows/System32/OpenSSH/ssh.exe ]]; then
  SSH_BIN=/c/Windows/System32/OpenSSH/ssh.exe
  native_path() { cygpath -w "$1"; }
else
  SSH_BIN=ssh
  native_path() { printf '%s\n' "$1"; }
fi

LOGIN="$ORIGAMI_USER@$ORIGAMI_HOST"
KNOWN_HOSTS="$STATE_DIR/known_hosts"
SSH_OPTS=(
  -i "$(native_path "${ORIGAMI_SSH_KEY/#\~/$HOME}")"
  -o BatchMode=yes
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=4
)

remote() { "$SSH_BIN" "${SSH_OPTS[@]}" "$LOGIN" "$@"; }

# Compute-node host keys are fetched through the already-trusted login node,
# so the jump hop never relies on an interactive trust-on-first-use prompt.
trust_node() {
  local node=$1 key
  touch "$KNOWN_HOSTS"
  grep -q "^$node " "$KNOWN_HOSTS" && return 0
  key=$(remote "ssh-keyscan -t ed25519 $node 2>/dev/null" | tr -d '\r' | grep -v '^#' || true)
  [[ -n "$key" ]] || die "could not fetch the host key for $node"
  printf '%s\n' "$key" >> "$KNOWN_HOSTS"
}

node_ssh() {
  local node=$1
  shift
  # ssh splits UserKnownHostsFile on whitespace unless the path is quoted.
  "$SSH_BIN" "${SSH_OPTS[@]}" \
    -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=\"$(native_path "$KNOWN_HOSTS")\"" \
    -J "$LOGIN" "$ORIGAMI_USER@$node" "$@"
}

record_job() { printf '%s %s %s %s\n' "$(date +%FT%T)" "$1" "$2" "$3" >> "$STATE_DIR/jobs"; }

last_job() {
  [[ -f "$STATE_DIR/jobs" ]] || return 0
  awk -v kind="${1:-}" 'kind == "" || $2 == kind { id = $3 } END { print id }' "$STATE_DIR/jobs"
}

job_state() { remote "squeue -h -j $1 -o %T 2>/dev/null" | tr -d '\r'; }

final_state() { remote "sacct -n -X -j $1 -o State%20" | tr -d '\r ' | head -n 1; }

# Newest endpoint file whose job is still running. Covers both deploy/up.sh jobs
# and serve_model.ipynb started by hand in a mynotebook session.
live_endpoint() {
  remote "cd ~/$REMOTE_ROOT/run 2>/dev/null || exit 0
    for f in \$(ls -t *.env 2>/dev/null); do
      id=\${f%.env}
      [[ \"\$(squeue -h -j \$id -o %T 2>/dev/null)\" == RUNNING ]] && { echo \$id; break; }
    done
    exit 0" | tr -d '\r'
}

current_release() {
  [[ -f "$STATE_DIR/release" ]] || die "nothing deployed yet; run deploy/sync.sh"
  cat "$STATE_DIR/release"
}

# Usage: submit <job> <release> [job args...]; prints the job id.
# Set JOB_TIME or JOB_GRES to override the walltime or GPU request in the sbatch file.
submit() {
  local job=$1 release=$2
  shift 2
  local time_arg="" gres_arg="" args=""
  [[ -n "${JOB_TIME:-}" ]] && time_arg="--time=$JOB_TIME"
  [[ -n "${JOB_GRES:-}" ]] && gres_arg="--gres=$JOB_GRES"
  (($#)) && args=$(printf '%q ' "$@")
  remote "cd ~/$REMOTE_ROOT && sbatch --parsable \
    --account=$SLURM_ACCOUNT --partition=$SLURM_PARTITION --qos=$SLURM_QOS \
    --mail-user=$NOTIFY_EMAIL --mail-type=END,FAIL $time_arg $gres_arg \
    --output=logs/%x-%j.out \
    --export=ALL,LLM_SERVE_ROOT=\$HOME/$REMOTE_ROOT,LLM_SERVE_APP=\$HOME/$REMOTE_ROOT/app/$release \
    app/$release/jobs/$job.sbatch $args" | tr -d '\r' | cut -d';' -f1
}

# Like submit, but resubmits with FALLBACK_GRES when the sbatch file's GPU type has
# no free card. Jobs held by a QOS limit stay queued.
submit_gpu() {
  local id state reason
  id=$(submit "$@")
  for _ in {1..10}; do
    read -r state reason < <(remote "squeue -h -j $id -o '%T %r'" | tr -d '\r') || true
    [[ "$state" == PENDING && "$reason" =~ ^(None|Resources|Priority)$ ]] || { echo "$id"; return 0; }
    sleep 3
  done
  remote "scancel $id"
  echo "no free GPU for job $id; resubmitting with $FALLBACK_GRES" >&2
  JOB_GRES=$FALLBACK_GRES submit "$@"
}

# Progress goes to stderr so callers can capture the result on stdout.
progress() { printf '\r%s: %s ' "$1" "$2" >&2; }

# Blocks until the job leaves PENDING; fails if it is no longer queued.
wait_running() {
  local id=$1 state
  while :; do
    state=$(job_state "$id")
    case "$state" in
      RUNNING) echo >&2; return 0 ;;
      "") echo >&2; die "job $id is no longer queued ($(final_state "$id")); see deploy/logs.sh $id" ;;
      *) progress "$id" "$state"; sleep 10 ;;
    esac
  done
}

# Blocks until the job leaves the queue; prints its final Slurm state.
wait_finished() {
  local id=$1 state
  while state=$(job_state "$id") && [[ -n "$state" ]]; do
    progress "$id" "$state"
    sleep 15
  done
  echo >&2
  final_state "$id"
}
'''

SSH_STUB = r"""#!/usr/bin/env bash
a="$*"; a=${a//$'\n'/ }
echo "$a" >> "$STUB_LOG"
[ -t 0 ] || cat >/dev/null
case "$a" in
  *scancel*) ;;
  *sbatch*) echo "$STUB_JOB_ID" ;;
  *ssh-keyscan*) echo "n1 ssh-ed25519 AAAA" ;;
  *"ls -t"*) if [[ "$a" != *kev* && -n "${STUB_LIVE:-}" ]]; then echo "$STUB_LIVE"; fi ;;
  *"%T %r"*) echo "RUNNING None" ;;
  *"squeue -h -j"*) printf '%s\n' "${STUB_JOB_STATE-RUNNING}" ;;
  *sacct*) echo COMPLETED ;;
  *"cat ~/"*run/*) printf 'NODE=n1\nPORT=5555\nMODEL=m\n' ;;
esac
exit 0
"""

SYNC_STUB = """#!/usr/bin/env bash
source "$(dirname "$0")/lib.sh"
echo rel123 > "$STATE_DIR/release"
"""

ENV_FILE = """ORIGAMI_USER=tester
ORIGAMI_HOST=10.0.0.1
ORIGAMI_SSH_KEY=~/.ssh/none
SLURM_ACCOUNT=acct
SLURM_PARTITION=part
SLURM_QOS=qos
NOTIFY_EMAIL=t@example.com
SCRATCH_DIR=/scratch/t
REMOTE_ROOT=llm-serve
PYTHON_MODULE=Python/3
DEFAULT_MODEL=qwen3.8:27b
SESSION_TIME=01:00:00
"""


class Sandbox:
    def __init__(self, root: Path, model_src: Path):
        self.model = root / "model"
        self.bin = root / "bin"
        self.log = root / "ssh.log"
        shutil.copytree(model_src / "deploy", self.model / "deploy")
        shutil.copytree(model_src / "jobs", self.model / "jobs")
        for sh in (self.model / "deploy").glob("*.sh"):
            text = sh.read_bytes().replace(b"/c/Windows/System32/OpenSSH/ssh.exe", b"/nonexistent/ssh.exe")
            sh.write_bytes(text)
        (self.model / "deploy" / "sync.sh").write_bytes(SYNC_STUB.encode())
        (self.model / ".env").write_text(ENV_FILE)
        self.bin.mkdir()
        (self.bin / "ssh").write_bytes(SSH_STUB.encode())
        (self.bin / "sleep").write_bytes(b"#!/usr/bin/env bash\nexit 0\n")
        for p in (*self.bin.iterdir(), *(self.model / "deploy").glob("*.sh")):
            p.chmod(0o755)
        self.log.write_text("")
        self.state = self.model / ".state"

    def seed_qwen_job(self) -> None:
        self.state.mkdir(exist_ok=True)
        (self.state / "jobs").write_text(f"2026-01-01T00:00:00 serve {QWEN_JOB_ID} rel0\n")

    def run(self, script: str, *args: str, **env: str) -> subprocess.CompletedProcess:
        full = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "STUB_LOG": self.log.as_posix(),
            "STUB_JOB_ID": STUB_JOB_ID,
            **env,
        }
        return subprocess.run(
            [BASH, str(self.model / "deploy" / script), *args],
            env=full, capture_output=True, text=True, timeout=60,
        )

    def calls(self) -> list[str]:
        return [re.sub(r'UserKnownHostsFile="[^"]*"', "UKH", c) for c in self.log.read_text().splitlines()]


def ok(result: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def base_model_dir(root: Path) -> Path:
    """Current scripts with deploy/lib.sh replaced by its recorded pre-Kev text."""
    dest = root / "src" / "model"
    shutil.copytree(MODEL / "deploy", dest / "deploy")
    shutil.copytree(MODEL / "jobs", dest / "jobs")
    (dest / "deploy" / "lib.sh").write_bytes(BASE_DEPLOY_LIB.encode())
    return dest


def lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    return Sandbox(tmp_path / "cur", MODEL)


def tunnels(calls: list[str]) -> list[str]:
    return [c for c in calls if " -L " in c]


def sbatch_calls(calls: list[str]) -> list[str]:
    return [c for c in calls if "sbatch" in c]


def job_text() -> str:
    return (MODEL / "jobs" / KEV_JOB).read_text()


# AC-5-1

@pytest.mark.parametrize("command", KEV_COMMANDS)
def test_each_deploy_command_has_a_kev_form(command):
    script = MODEL / "deploy" / f"kev-{command}.sh"
    assert script.is_file() and script.read_text().strip(), script


def test_kev_job_file_exists_beside_qwen_job():
    assert (MODEL / "jobs" / KEV_JOB).is_file()


@pytest.mark.parametrize("preseed", [False, True])
def test_kev_commands_leave_qwen_job_state_untouched(sb, preseed):
    if preseed:
        sb.seed_qwen_job()
    before = (sb.state / "jobs").read_bytes() if preseed else None
    ok(sb.run("kev-up.sh"))
    ok(sb.run("kev-status.sh"))
    ok(sb.run("kev-down.sh"))
    jobs = sb.state / "jobs"
    if preseed:
        assert jobs.read_bytes() == before
    else:
        assert not jobs.exists()


# AC-5-2

def test_kev_job_serves_kev_4b_on_loopback_with_node_chosen_port():
    text = job_text()
    assert "kev.serve" in text
    assert "jaredpalmer/kev-4b" in text
    assert "0.0.0.0" not in text
    port = re.search(r"--port[ =]+(\S+)", text)
    assert port, "kev.serve needs an explicit --port"
    assert not port.group(1).strip("\"'").isdigit(), "port must be chosen on the node, not fixed"


def test_kev_job_publishes_endpoint_state_for_connect():
    text = job_text()
    assert "NODE=" in text and "PORT=" in text
    assert re.search(r"SLURM_JOB_ID", text)


def test_kev_job_requests_a_gpu():
    gres = re.search(r"^#SBATCH\s+--gres=gpu(?::[\w.]+)*:([1-9]\d*)\s*$", job_text(), re.M)
    assert gres, "kev job must request at least one GPU"


# AC-5-6

def test_kev_and_qwen_jobs_share_no_job_name_or_endpoint_file_or_port():
    kev, qwen = job_text(), (MODEL / "jobs" / "serve.sbatch").read_text()
    name = lambda t: re.search(r"^#SBATCH\s+--job-name=(\S+)", t, re.M).group(1)
    assert name(kev) != name(qwen)
    assert "ollama" not in kev.lower()
    assert QWEN_PORT not in kev
    assert not re.search(r"run/\$\{?SLURM_JOB_ID\}?\.env", kev), "qwen endpoint file path reused"
    assert re.search(r"^#SBATCH\s+--gres=gpu", qwen, re.M) and re.search(r"^#SBATCH\s+--gres=gpu", kev, re.M)


def test_kev_up_does_not_cancel_or_reuse_a_running_qwen_server(sb):
    sb.seed_qwen_job()
    ok(sb.run("kev-up.sh", STUB_LIVE=QWEN_JOB_ID))
    calls = sb.calls()
    assert not [c for c in calls if "scancel" in c]
    submits = sbatch_calls(calls)
    assert len(submits) == 1 and KEV_JOB in submits[0]
    assert not [c for c in tunnels(calls) if f"-L {QWEN_PORT}:" in c]


def test_qwen_up_does_not_reuse_or_cancel_a_recorded_kev_job(sb):
    ok(sb.run("kev-up.sh"))
    start = len(sb.calls())
    ok(sb.run("up.sh"))
    calls = sb.calls()[start:]
    assert not [c for c in calls if "scancel" in c]
    submits = sbatch_calls(calls)
    assert len(submits) == 1 and "jobs/serve.sbatch" in submits[0] and "kev" not in submits[0]
    assert [c for c in tunnels(calls) if f"-L {QWEN_PORT}:127.0.0.1:" in c]


# AC-5-3

def test_kev_up_submits_the_kev_job_and_opens_tunnel_on_kev_port(sb):
    ok(sb.run("kev-up.sh"))
    calls = sb.calls()
    submits = sbatch_calls(calls)
    assert len(submits) == 1 and f"jobs/{KEV_JOB}" in submits[0]
    assert "serve.sbatch" not in submits[0].replace(KEV_JOB, "")
    tun = tunnels(calls)
    assert len(tun) == 1 and f"-L {KEV_PORT}:127.0.0.1:5555" in tun[0] and "n1" in tun[0]


def test_kev_connect_reads_kev_endpoint_state_and_tunnels_to_node_port(sb):
    ok(sb.run("kev-connect.sh", STUB_JOB_ID))
    calls = sb.calls()
    reads = [c for c in calls if "cat ~/" in c and STUB_JOB_ID in c]
    assert reads
    assert not [c for c in reads if re.search(rf"run/{STUB_JOB_ID}\.env", c)], "qwen endpoint file read"
    tun = tunnels(calls)
    assert len(tun) == 1 and f"-L {KEV_PORT}:127.0.0.1:5555" in tun[0] and "n1" in tun[0]


def test_kev_status_queries_the_queue_for_kev_jobs(sb):
    ok(sb.run("kev-up.sh"))
    start = len(sb.calls())
    ok(sb.run("kev-status.sh"))
    queue = [c for c in sb.calls()[start:] if "squeue" in c]
    assert queue and all("kev" in c.lower() or STUB_JOB_ID in c for c in queue)


@pytest.mark.parametrize("args", [[STUB_JOB_ID], []])
def test_kev_logs_reads_the_kev_job_log(sb, args):
    sb.seed_qwen_job()
    ok(sb.run("kev-up.sh"))
    start = len(sb.calls())
    ok(sb.run("kev-logs.sh", *args))
    reads = [c for c in sb.calls()[start:] if "logs/" in c]
    assert reads and all(STUB_JOB_ID in c and QWEN_JOB_ID not in c for c in reads)


@pytest.mark.parametrize("args", [[STUB_JOB_ID], []])
def test_kev_down_cancels_only_the_kev_job(sb, args):
    sb.seed_qwen_job()
    ok(sb.run("kev-up.sh"))
    start = len(sb.calls())
    ok(sb.run("kev-down.sh", *args))
    cancels = [c for c in sb.calls()[start:] if "scancel" in c]
    assert len(cancels) == 1 and STUB_JOB_ID in cancels[0] and QWEN_JOB_ID not in cancels[0]


def test_kev_down_without_a_recorded_kev_job_cancels_nothing(sb):
    sb.seed_qwen_job()
    ok(sb.run("kev-down.sh"))
    assert not [c for c in sb.calls() if "scancel" in c]


def test_kev_provision_prepares_kev_4b_without_touching_qwen(sb):
    sb.seed_qwen_job()
    ok(sb.run("kev-provision.sh", STUB_JOB_STATE=""))
    calls = sb.calls()
    assert [c for c in calls if "jaredpalmer/kev-4b" in c or "kev-4b" in c.lower()]
    assert not [c for c in calls if "scancel" in c or "ollama" in c.lower() or "serve.sbatch" in c.replace(KEV_JOB, "")]
    assert (sb.state / "jobs").read_text() == f"2026-01-01T00:00:00 serve {QWEN_JOB_ID} rel0\n"


def test_kev_local_port_differs_from_qwen_and_is_declared_in_env_example():
    assert KEV_PORT != QWEN_PORT
    env = (MODEL / ".env.example").read_text()
    assert re.search(rf"^#?\s*KEV\w*PORT={KEV_PORT}\s*$", env, re.M)


# AC-5-4

@pytest.mark.parametrize("rel", sorted(QWEN_SHA256))
def test_qwen_scripts_are_byte_identical_to_base(rel):
    assert hashlib.sha256(lf((MODEL / rel).read_bytes())).hexdigest() == QWEN_SHA256[rel]


QWEN_RUNS = [
    ("up.sh", []),
    ("connect.sh", [STUB_JOB_ID]),
    ("status.sh", []),
    ("logs.sh", [STUB_JOB_ID]),
    ("down.sh", [STUB_JOB_ID]),
    ("provision.sh", []),
]


@pytest.mark.parametrize("script,args", QWEN_RUNS, ids=[s for s, _ in QWEN_RUNS])
def test_qwen_commands_issue_the_same_calls_and_port_as_base(tmp_path, script, args):
    env = {"STUB_JOB_STATE": ""} if script == "provision.sh" else {}
    base = Sandbox(tmp_path / "base", base_model_dir(tmp_path))
    cur = Sandbox(tmp_path / "cur", MODEL)
    rb = base.run(script, *args, **env)
    rc = cur.run(script, *args, **env)
    assert rc.returncode == rb.returncode
    assert cur.calls() == base.calls()
    if script in ("up.sh", "connect.sh"):
        assert [c for c in tunnels(cur.calls()) if f"-L {QWEN_PORT}:127.0.0.1:5555" in c]
