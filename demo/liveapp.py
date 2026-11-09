"""App mode for the workspace: run a repository's own app from the workspace copy, and relay requests to it.

Only repositories listed in APPS can run. The app runs in its own virtual environment (demo/.data/apps/venv,
with the app's requirements) on a local port, and is restarted on demand so it always serves the code that
is in the editor right now. Requests reach it only through the signed-in dashboard (server.py relays them).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / ".data" / "apps"
VENV_PY = DATA / "venv" / "bin" / "python"
APPS = {   # by repository name, so a fork under any owner runs too
    "shoply-demo": {"launcher": HERE / "apps" / "shoply_launcher.py", "port": 8791},
}


class LiveAppError(Exception):
    def __init__(self, msg: str, status: int = 400):
        super().__init__(msg)
        self.status = status


class LiveApps:
    def __init__(self, workspace_root: Path):
        self.root = workspace_root
        self.procs: dict[str, subprocess.Popen] = {}
        self.lock = threading.Lock()

    def supported(self, repo: str) -> bool:
        return repo.partition("/")[2] in APPS

    def _ready(self, port: int, timeout: float = 15) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return True
            except OSError:
                time.sleep(0.15)
        return False

    def stop(self, repo: str) -> None:
        p = self.procs.pop(repo, None)
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    @staticmethod
    def _free_port(cfg: dict) -> None:
        """Stop an app left running by an earlier dashboard process (it lost the handle when it restarted),
        so a restart never talks to stale code. Only our own launcher is stopped, never another program."""
        pids = subprocess.run(["lsof", "-t", f"-iTCP:{cfg['port']}", "-sTCP:LISTEN"], capture_output=True, text=True).stdout.split()
        for pid in pids:
            cmd = subprocess.run(["ps", "-o", "command=", "-p", pid], capture_output=True, text=True).stdout
            if Path(cfg["launcher"]).name in cmd:
                subprocess.run(["kill", pid], capture_output=True)
        for _ in range(20):
            if not subprocess.run(["lsof", "-t", f"-iTCP:{cfg['port']}", "-sTCP:LISTEN"], capture_output=True, text=True).stdout.strip():
                return
            time.sleep(0.25)

    @staticmethod
    def _make_venv(ws: Path) -> None:
        """First run on this machine: the app's own environment, with the app's requirements (about 20 s)."""
        reqs = ws / "requirements.txt"
        venv = VENV_PY.parent.parent
        try:
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True, timeout=120)
            subprocess.run([str(VENV_PY), "-m", "pip", "install", "--quiet",
                            *(["-r", str(reqs)] if reqs.is_file() else ["flask>=3.0", "sqlalchemy>=2.0"])],
                           check=True, capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.SubprocessError) as exc:
            shutil.rmtree(venv, ignore_errors=True)
            detail = getattr(exc, "stderr", "") or str(exc)
            raise LiveAppError(f"Could not set up the app's environment in {venv}: {str(detail)[-300:]}", 500) from exc

    def start(self, repo: str) -> dict:
        """(Re)start the app from the workspace's current files, with fresh demo data."""
        cfg = APPS.get(repo.partition("/")[2])
        if not cfg:
            raise LiveAppError("This repository has no app to run.", 404)
        owner, name = repo.split("/")
        ws = self.root / owner / name
        if not (ws / ".git").is_dir():
            raise LiveAppError("Open the repository in the workspace first.", 409)
        if not VENV_PY.exists():
            self._make_venv(ws)
        with self.lock:
            self.stop(repo)
            self._free_port(cfg)
            log = DATA / f"{name}.log"
            DATA.mkdir(parents=True, exist_ok=True)
            fh = open(log, "w", encoding="utf-8")
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}
            env.pop("AWS_BEARER_TOKEN_BEDROCK", None)
            self.procs[repo] = subprocess.Popen([str(VENV_PY), str(cfg["launcher"]), str(ws), str(DATA / name), str(cfg["port"])],
                                                cwd=DATA, stdout=fh, stderr=subprocess.STDOUT, env=env)
            ok = self._ready(cfg["port"])
            proc = self.procs[repo]
            if not ok or proc.poll() is not None:
                fh.flush()
                tail = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-12:]
                self.stop(repo)
                raise LiveAppError("The app did not start. The code in the workspace may have an error:\n" + "\n".join(tail), 422)
        return {"running": True, "routes": self.call(repo, "GET", "/__lgtm/routes")["body"]}

    def call(self, repo: str, method: str, path: str, token: str | None = None, body=None) -> dict:
        cfg = APPS.get(repo.partition("/")[2])
        if not cfg:
            raise LiveAppError("This repository has no app to run.", 404)
        p = self.procs.get(repo)
        if not p or p.poll() is not None:
            raise LiveAppError("The app is not running. Start it from App mode.", 409)
        if not path.startswith("/") or method not in ("GET", "POST", "PUT", "DELETE"):
            raise LiveAppError("Bad request")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{cfg['port']}{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        except OSError as exc:
            raise LiveAppError(f"The app did not answer: {exc}", 502) from exc
        try:
            parsed = json.loads(raw or b"null")
        except ValueError:
            parsed = raw.decode("utf-8", "replace")[:2000]
        if status >= 500:   # say why the app crashed: the last exception line in its log
            crash = next((ln.strip() for ln in reversed(self.log(repo).splitlines())
                          if re.match(r"^[\w.]+(Error|Exception)\b", ln.strip())), "")
            parsed = {"error": "the app crashed", "crash": crash[:300]}
        return {"status": status, "body": parsed, "ms": round((time.monotonic() - started) * 1000)}

    def log(self, repo: str) -> str:
        cfg = APPS.get(repo.partition("/")[2])
        name = repo.split("/")[-1]
        f = DATA / f"{name}.log"
        return f.read_text(encoding="utf-8", errors="replace")[-6000:] if cfg and f.is_file() else ""
