"""Test doubles for the graph runtime: a scriptable fake executable and a fake runner."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from lgtm.graph.runner import GraphOutcome

FLOOD_TOKEN = "ZQXJ"

_SCRIPT = r'''
import json, os, subprocess, sys, time

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "behavior.json"), encoding="utf-8") as fh:
    spec = json.load(fh)

stdin_len = None
try:
    stdin_len = len(sys.stdin.read())
except Exception as exc:
    stdin_len = "error:" + type(exc).__name__

argv = sys.argv[1:]
home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or ""
record = {
    "argv": argv,
    "env": dict(os.environ),
    "cwd": os.getcwd(),
    "pid": os.getpid(),
    "stdin_len": stdin_len,
    "home_is_dir": bool(home) and os.path.isdir(home),
}
with open(os.path.join(here, "calls.jsonl"), "a", encoding="utf-8") as fh:
    fh.write(json.dumps(record) + "\n")

if spec.get("child"):
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    with open(os.path.join(here, "pids.txt"), "a", encoding="utf-8") as fh:
        fh.write(str(child.pid) + "\n")

out_total = int(spec.get("stdout_flood", 0))
err_total = int(spec.get("stderr_flood", 0))
chunk = 65536
while out_total > 0 or err_total > 0:
    if out_total > 0:
        n = min(chunk, out_total)
        os.write(1, b"x" * n)
        out_total -= n
    if err_total > 0:
        n = min(chunk, err_total)
        os.write(2, (b"ZQXJ" * (n // 4 + 1))[:n])
        err_total -= n

if spec.get("stdout"):
    sys.stdout.write(spec["stdout"])
    sys.stdout.flush()
if spec.get("stderr"):
    sys.stderr.write(spec["stderr"])
    sys.stderr.flush()
if spec.get("hang"):
    time.sleep(float(spec["hang"]))
sys.exit(int(spec.get("exit", 0)))
'''


@dataclass
class FakeExecutable:
    path: Path
    directory: Path

    def configure(self, **behavior: object) -> "FakeExecutable":
        (self.directory / "behavior.json").write_text(json.dumps(behavior), encoding="utf-8")
        return self

    def calls(self) -> list[dict]:
        log = self.directory / "calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]

    def child_pids(self) -> list[int]:
        log = self.directory / "pids.txt"
        if not log.exists():
            return []
        return [int(line) for line in log.read_text(encoding="utf-8").split()]

    def all_pids(self) -> list[int]:
        return self.child_pids() + [c["pid"] for c in self.calls()]


def make_fake_executable(directory: Path, **behavior: object) -> FakeExecutable:
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "fake_codegraph.py"
    script.write_text(_SCRIPT, encoding="utf-8")
    if os.name == "nt":
        shim = directory / "codegraph.cmd"
        shim.write_text(
            f'@echo off\r\n"{sys.executable}" "{script}" %*\r\nexit /b %ERRORLEVEL%\r\n',
            encoding="utf-8",
        )
    else:
        shim = directory / "codegraph"
        shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return FakeExecutable(shim, directory).configure(**behavior)


def pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code))
            return code.value == 259
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_all_dead(pids: list[int], timeout: float = 10.0) -> list[int]:
    deadline = time.monotonic() + timeout
    alive = [p for p in pids if pid_alive(p)]
    while alive and time.monotonic() < deadline:
        time.sleep(0.05)
        alive = [p for p in alive if pid_alive(p)]
    return alive


def kill_pids(pids: list[int]) -> None:
    for pid in pids:
        if not pid_alive(pid):
            continue
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
        else:
            try:
                os.kill(pid, 9)
            except OSError:
                pass


def outcome(
    ok: bool = True,
    reason: str | None = None,
    text: str = "",
    truncated: bool = False,
    omitted_chars: int = 0,
) -> GraphOutcome:
    return GraphOutcome(ok=ok, reason=reason, text=text, truncated=truncated, omitted_chars=omitted_chars)


def success(text: str = "RESULT-TOKEN") -> GraphOutcome:
    return outcome(True, None, text)


def no_match() -> GraphOutcome:
    return outcome(True, "no_match", "")


def failure(reason: str) -> GraphOutcome:
    return outcome(False, reason, "")


def snapshot_label(root: Path) -> str:
    """Tests export the git_repo fixture: only the pr snapshot defines find_user."""
    app = Path(root) / "app.py"
    return "pr" if app.exists() and "find_user" in app.read_text(encoding="utf-8") else "base"


Script = Callable[[str, Path], GraphOutcome]


class FakeRunner:
    """Scripted stand-in for the graph runner. A script maps (label, root) to an outcome."""

    def __init__(
        self,
        init: dict[str, GraphOutcome | Script] | None = None,
        explore: dict[str, GraphOutcome | Script] | None = None,
        *,
        available: bool = True,
        init_delay: float = 0.0,
        explore_delay: float = 0.0,
    ) -> None:
        self._scripts = {"init": init or {}, "explore": explore or {}}
        self._available = available
        self._delay = {"init": init_delay, "explore": explore_delay}
        self.calls: list[dict] = []

    def available(self) -> bool:
        return self._available

    def init(self, root) -> GraphOutcome:
        return self._run("init", Path(root), None)

    def explore(self, root, query) -> GraphOutcome:
        return self._run("explore", Path(root), query)

    def _run(self, kind: str, root: Path, query: str | None) -> GraphOutcome:
        label = snapshot_label(root)
        app = root / "app.py"
        self.calls.append({
            "kind": kind,
            "label": label,
            "root": root,
            "query": query,
            "root_existed": root.is_dir(),
            "app_py": app.read_text(encoding="utf-8") if app.exists() else None,
        })
        if self._delay[kind]:
            time.sleep(self._delay[kind])
        step = self._scripts[kind].get(label, success())
        return step(label, root) if callable(step) else step

    def count(self, kind: str, label: str | None = None) -> int:
        return sum(1 for c in self.calls if c["kind"] == kind and label in (None, c["label"]))

    def roots(self) -> set[Path]:
        return {c["root"] for c in self.calls}
