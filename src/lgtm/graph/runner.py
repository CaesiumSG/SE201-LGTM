"""Bounded, argv-only process runner for the CodeGraph binary."""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_QUERY_CHARS = 300
EXPLORE_MAX_FILES = "8"
STDERR_LOG_CHARS = 500
TRUNCATION_MARKER = "\n[TRUNCATED]"

_QUERY_DISALLOWED = re.compile(r"[^A-Za-z0-9_ .,:/@#+=-]")
_WHITESPACE = re.compile(r"\s+")
_PASS_THROUGH = frozenset({"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG"})
_HARDENING = {
    "CODEGRAPH_NO_UPDATE_CHECK": "1",
    "DO_NOT_TRACK": "1",
    "CODEGRAPH_NO_DAEMON": "1",
    "CODEGRAPH_NO_WATCH": "1",
}
_POLL_INTERVAL_S = 0.1
_REMOVE_ATTEMPTS = 3
_REMOVE_RETRY_S = 0.2
_JOIN_TIMEOUT_S = 5


@dataclass(frozen=True)
class GraphOutcome:
    ok: bool
    reason: str | None
    text: str
    truncated: bool
    omitted_chars: int


def sanitize_query(query: str) -> str:
    cleaned = _QUERY_DISALLOWED.sub("", _WHITESPACE.sub(" ", query)).strip()[:MAX_QUERY_CHARS].strip()
    if not cleaned:
        raise ValueError("query must not be empty")
    return cleaned


class GraphRunner:
    def __init__(
        self,
        binary: str,
        *,
        init_timeout_s: float = 120,
        query_timeout_s: float = 20,
        max_output_chars: int = 6000,
    ) -> None:
        self._binary = binary
        self._init_timeout_s = init_timeout_s
        self._query_timeout_s = query_timeout_s
        self._max_output_chars = max_output_chars

    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    def init(self, root: Path | str) -> GraphOutcome:
        return self._invoke(["init", "-y", str(root)], self._init_timeout_s, explore=False)

    def explore(self, root: Path | str, query: str) -> GraphOutcome:
        argv = ["explore", "-p", str(root), "--max-files", EXPLORE_MAX_FILES, "--", sanitize_query(query)]
        return self._invoke(argv, self._query_timeout_s, explore=True)

    def _invoke(self, argv: list[str], timeout_s: float, *, explore: bool) -> GraphOutcome:
        binary = shutil.which(self._binary)
        if binary is None:
            return _failed("missing")
        work = Path(tempfile.mkdtemp(prefix="lgtm-graph-"))
        try:
            return self._spawn(binary, argv, timeout_s, work, explore=explore)
        finally:
            remove_tree(work)

    def _spawn(
        self, binary: str, argv: list[str], timeout_s: float, work: Path, *, explore: bool
    ) -> GraphOutcome:
        cwd, home, config = work / "cwd", work / "home", work / "config"
        for directory in (cwd, home, config):
            directory.mkdir()
        if os.name == "nt":
            group_kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            group_kwargs = {"start_new_session": True}
        try:
            proc = subprocess.Popen(
                [binary, *argv],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=_child_env(home, config),
                **group_kwargs,
            )
        except OSError:
            logger.warning("codegraph could not be launched: %s", binary)
            return _failed("launch_failed")

        tree = _ProcessTree(proc)
        stdout = _Capture(proc.stdout, self._max_output_chars)
        stderr = _Capture(proc.stderr, STDERR_LOG_CHARS)
        try:
            timed_out = _wait(proc, timeout_s)
        finally:
            tree.kill(proc)
            stdout.join()
            stderr.join()
            tree.close()
            for stream in (proc.stdout, proc.stderr):
                with contextlib.suppress(OSError):
                    stream.close()

        if stderr.head:
            logger.debug("codegraph %s stderr: %s", argv[0], stderr.head.decode("utf-8", "replace"))
        if timed_out:
            return _failed("timeout")
        if proc.returncode != 0:
            return _failed("nonzero")
        text, truncated, omitted = stdout.result()
        if explore and not text.strip():
            return GraphOutcome(ok=True, reason="no_match", text="", truncated=False, omitted_chars=0)
        return GraphOutcome(ok=True, reason=None, text=text, truncated=truncated, omitted_chars=omitted)


def _failed(reason: str) -> GraphOutcome:
    return GraphOutcome(ok=False, reason=reason, text="", truncated=False, omitted_chars=0)


def _child_env(home: Path, config: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if upper in _PASS_THROUGH or upper.startswith("LC_"):
            env[upper if os.name == "nt" else key] = value
    env.update(_HARDENING)
    env["HOME"] = env["USERPROFILE"] = str(home)
    env["XDG_CONFIG_HOME"] = str(config)
    return env


def _wait(proc: subprocess.Popen, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            proc.wait(timeout=min(_POLL_INTERVAL_S, max(deadline - time.monotonic(), 0.0)))
            return False
        except subprocess.TimeoutExpired:
            if time.monotonic() >= deadline:
                return True


class _Capture:
    """Drains a pipe to EOF, retaining only the first `limit` bytes."""

    def __init__(self, stream, limit: int) -> None:
        self._fd = stream.fileno()
        self._limit = limit
        self.head = bytearray()
        self._total = 0
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        while True:
            try:
                chunk = os.read(self._fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            self._total += len(chunk)
            room = self._limit - len(self.head)
            if room > 0:
                self.head += chunk[:room]

    def join(self) -> None:
        self._thread.join(_JOIN_TIMEOUT_S)

    def result(self) -> tuple[str, bool, int]:
        if self._total <= self._limit:
            return bytes(self.head).decode("utf-8", "replace"), False, 0
        keep = bytes(self.head[: max(0, self._limit - len(TRUNCATION_MARKER))])
        return keep.decode("utf-8", "replace") + TRUNCATION_MARKER, True, self._total - len(keep)


class _ProcessTree:
    """Owns the child's process group (POSIX) or Job Object (Windows) for reaping descendants."""

    def __init__(self, proc: subprocess.Popen) -> None:
        self._job = _assign_job(proc.pid) if os.name == "nt" else None

    def kill(self, proc: subprocess.Popen) -> None:
        if os.name == "nt":
            if proc.poll() is None:
                system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
                taskkill = os.path.join(system_root, "System32", "taskkill.exe")
                subprocess.run(
                    [taskkill, "/PID", str(proc.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
        else:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
        if proc.poll() is None:
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=_JOIN_TIMEOUT_S)

    def close(self) -> None:
        if self._job is not None:
            _close_handle(self._job)
            self._job = None


def _assign_job(pid: int) -> int | None:
    """Descendants of an exited parent are unreachable by taskkill /T; closing a kill-on-close job reaps them."""
    import ctypes
    from ctypes import wintypes

    class _BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
        )]

    class _ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimit),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = _ExtendedLimit()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    process_set_quota, process_terminate = 0x0100, 0x0001
    process = kernel32.OpenProcess(process_set_quota | process_terminate, False, pid)
    assigned = False
    if process:
        try:
            assigned = bool(kernel32.SetInformationJobObject(
                job, 9, ctypes.byref(info), ctypes.sizeof(info)
            ) and kernel32.AssignProcessToJobObject(job, process))
        finally:
            kernel32.CloseHandle(process)
    if not assigned:
        kernel32.CloseHandle(job)
        return None
    return job


def _close_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle(handle)


def remove_tree(path: Path) -> None:
    for attempt in range(_REMOVE_ATTEMPTS):
        try:
            shutil.rmtree(path, onerror=_clear_read_only_and_retry)
            return
        except OSError:
            if attempt + 1 < _REMOVE_ATTEMPTS:
                time.sleep(_REMOVE_RETRY_S)
    logger.warning("could not remove graph scratch directory: %s", path)


def _clear_read_only_and_retry(func, path, _exc_info) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IWRITE)
    with contextlib.suppress(FileNotFoundError):
        func(path)
