"""Job-local Ollama server for the Origami GPU cluster.

Used by the notebooks in this folder. Standard library only, so it runs in the
`mynotebook` kernel, in a plain `python3`, or headless from an sbatch job.

Settings come from <root>/cluster.env (uploaded by deploy/sync.sh); environment
variables with the same names override them.
"""

from __future__ import annotations

import atexit
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(os.environ.get("LLM_SERVE_ROOT", Path.home() / "llm-serve"))

CONFIG_KEYS = (
    "ORIGAMI_USER", "ORIGAMI_HOST", "SCRATCH_DIR", "OLLAMA_BIN",
    "MODELS", "DEFAULT_MODEL",
    "OLLAMA_KEEP_ALIVE", "OLLAMA_CONTEXT_LENGTH", "OLLAMA_NUM_PARALLEL",
    "OLLAMA_FLASH_ATTENTION", "OLLAMA_KV_CACHE_TYPE",
)
# Forwarded to `ollama serve` when set; they tune the server, not this module.
SERVER_ENV_KEYS = (
    "OLLAMA_KEEP_ALIVE", "OLLAMA_CONTEXT_LENGTH", "OLLAMA_NUM_PARALLEL",
    "OLLAMA_FLASH_ATTENTION", "OLLAMA_KV_CACHE_TYPE",
)


def load_config() -> dict[str, str]:
    config: dict[str, str] = {}
    path = ROOT / "cluster.env"
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip().strip("\"'")
    config.update({k: os.environ[k] for k in CONFIG_KEYS if k in os.environ})
    missing = [k for k in ("SCRATCH_DIR", "OLLAMA_BIN", "DEFAULT_MODEL") if not config.get(k)]
    if missing:
        raise RuntimeError(f"{path} is missing {missing}; run deploy/sync.sh from the laptop")
    return config


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def job_id() -> str:
    return os.environ.get("SLURM_JOB_ID", "local")


def node_name() -> str:
    return os.environ.get("SLURMD_NODENAME") or socket.gethostname().split(".")[0]


class OllamaServer:
    """One `ollama serve` process bound to a random loopback port.

    Loopback only: compute nodes are shared between users, and Ollama has no
    authentication. Clients reach it through an SSH jump via the login node.
    """

    def __init__(self, config: dict[str, str]):
        self.config = config
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.models_dir = Path(config["SCRATCH_DIR"]) / "ollama-models"
        self.log_path = ROOT / "logs" / f"ollama-{job_id()}.log"
        self.endpoint_path: Path | None = None
        self.proc: subprocess.Popen | None = None

    def start(self, timeout: int = 60) -> None:
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["OLLAMA_HOST"] = f"127.0.0.1:{self.port}"
        env["OLLAMA_MODELS"] = str(self.models_dir)
        env.update({k: self.config[k] for k in SERVER_ENV_KEYS if self.config.get(k)})
        # llama-server defaults to the node's core count, not the job's CPU allocation
        env.setdefault("LLAMA_ARG_THREADS", str(len(os.sched_getaffinity(0))))

        log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [self.config["OLLAMA_BIN"], "serve"], env=env, stdout=log, stderr=subprocess.STDOUT
        )
        atexit.register(self.stop)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"ollama exited with {self.proc.returncode}; see {self.log_path}")
            try:
                self._request("GET", "/api/version", timeout=2)
                print(f"ollama running at {self.url} (log {self.log_path})")
                return
            except OSError:
                time.sleep(1)
        raise RuntimeError(f"ollama did not answer within {timeout}s; see {self.log_path}")

    def stop(self) -> None:
        if self.endpoint_path:
            self.endpoint_path.unlink(missing_ok=True)
            self.endpoint_path = None
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            print("ollama stopped")

    def models(self) -> list[str]:
        return [m["name"] for m in self._request("GET", "/api/tags")["models"]]

    def pull(self, model: str) -> None:
        if model in self.models():
            print(f"{model}: already present")
            return
        print(f"{model}: pulling into {self.models_dir}")
        last_report = ""
        for event in self._stream("/api/pull", {"model": model}):
            if "error" in event:
                raise RuntimeError(f"pull {model} failed: {event['error']}")
            report = event.get("status", "")
            if event.get("total"):
                # Progress events arrive many times a second; report each 10% step once.
                percent = 100 * event.get("completed", 0) // event["total"]
                report = f"{report} {percent // 10 * 10}%"
            if report != last_report:
                print(f"  {report}", flush=True)
                last_report = report

    def warm(self, model: str) -> float:
        """Load the model into GPU memory so the first client request is not slow."""
        started = time.monotonic()
        body = {"model": model, "stream": False}
        keep_alive = self.config.get("OLLAMA_KEEP_ALIVE")
        if keep_alive:
            # The API rejects the string "-1"; bare numbers must be sent as integers.
            body["keep_alive"] = int(keep_alive) if keep_alive.lstrip("-").isdigit() else keep_alive
        self._request("POST", "/api/generate", body, timeout=600)
        return time.monotonic() - started

    def loaded(self) -> list[dict]:
        return self._request("GET", "/api/ps")["models"]

    def generate(self, model: str, prompt: str) -> str:
        body = {"model": model, "prompt": prompt, "stream": False}
        return self._request("POST", "/api/generate", body, timeout=600)["response"]

    def publish(self, model: str) -> Path:
        """Write the endpoint file that deploy/connect.sh reads to build the tunnel."""
        path = ROOT / "run" / f"{job_id()}.env"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"NODE={node_name()}\nPORT={self.port}\nMODEL={model}\n")
        self.endpoint_path = path
        return path

    def connection_help(self) -> str:
        user = self.config.get("ORIGAMI_USER", "<user>")
        host = self.config.get("ORIGAMI_HOST", "10.193.104.102")
        return (
            f"From the laptop:  model/deploy/connect.sh {job_id()}\n"
            f"or by hand:       ssh -N -J {user}@{host} -L 11435:127.0.0.1:{self.port} {user}@{node_name()}\n"
            f"then use          http://127.0.0.1:11435"
        )

    def serve_forever(self) -> None:
        """Block until the server exits or the job is cancelled (SIGTERM from Slurm)."""
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        while self.proc and self.proc.poll() is None:
            time.sleep(30)
        raise RuntimeError(f"ollama exited with {self.proc.returncode}; see {self.log_path}")

    def _request(self, method: str, path: str, body: dict | None = None, timeout: int = 30) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, method=method, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)

    def _stream(self, path: str, body: dict):
        req = urllib.request.Request(
            self.url + path, data=json.dumps(body).encode(), method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3600) as resp:
            for line in resp:
                if line.strip():
                    yield json.loads(line)
