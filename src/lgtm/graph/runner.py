"""Bounded, argv-only process runner for the CodeGraph binary."""

from __future__ import annotations

import codecs
import contextlib
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
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
_NO_MATCH_PREFIX = "No relevant code found"
_STALE_MARKER = "changed since last index sync"
_STALE_NOTICE = f"· ⚠ {_STALE_MARKER}"
_LINE_SCAN_CHARS = 16384

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
    spaced = _WHITESPACE.sub(" ", query)
    cleaned = _WHITESPACE.sub(" ", _QUERY_DISALLOWED.sub("", spaced)).strip()[:MAX_QUERY_CHARS].strip()
    if not cleaned:
        raise ValueError("query must not be empty")
    return cleaned


class GraphRunner:
    def __init__(
        self,
        binary: str,
        *,
        init_timeout_s: float,
        query_timeout_s: float,
        max_output_chars: int,
    ) -> None:
        self._binary = binary
        self._init_timeout_s = init_timeout_s
        self._query_timeout_s = query_timeout_s
        self._max_output_chars = max_output_chars

    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    def init(self, root: Path | str) -> GraphOutcome:
        outcome = self._invoke(["init", "-y", str(root)], self._init_timeout_s, explore=False)
        # Exit 0 is returned without an index when no files are found.
        if outcome.ok and not (Path(root) / ".codegraph").is_dir():
            return failed_outcome("nonzero")
        return outcome

    def explore(self, root: Path | str, query: str) -> GraphOutcome:
        argv = ["explore", "-p", str(root), "--max-files", EXPLORE_MAX_FILES, "--", sanitize_query(query)]
        return self._invoke(argv, self._query_timeout_s, explore=True)

    def _invoke(self, argv: list[str], timeout_s: float, *, explore: bool) -> GraphOutcome:
        binary = shutil.which(self._binary)
        if binary is None:
            return failed_outcome("missing")
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
            return failed_outcome("launch_failed")

        tree: _ProcessTree | None = None
        stdout: _Capture | None = None
        stderr: _Capture | None = None
        try:
            tree = _ProcessTree(proc)
            stdout = _Capture(proc.stdout, self._max_output_chars)
            stderr = _Capture(proc.stderr, STDERR_LOG_CHARS)
            timed_out = _wait(proc, timeout_s)
        finally:
            _terminate(proc)
            if tree is not None:
                tree.close()
            for capture in (stdout, stderr):
                if capture is not None:
                    capture.join()
            for stream in (proc.stdout, proc.stderr):
                with contextlib.suppress(OSError):
                    stream.close()

        if stderr.head:
            logger.debug("codegraph %s stderr: %s", argv[0], stderr.head)
        if timed_out:
            return failed_outcome("timeout")
        if proc.returncode != 0:
            return failed_outcome("nonzero")
        if explore and stdout.stale:
            return failed_outcome("stale")
        text, truncated, omitted = stdout.result()
        # The binary reports no match on stdout with exit 0.
        if explore and (not text.strip() or text.strip().startswith(_NO_MATCH_PREFIX)):
            return GraphOutcome(ok=True, reason="no_match", text="", truncated=False, omitted_chars=0)
        return GraphOutcome(ok=True, reason=None, text=text, truncated=truncated, omitted_chars=omitted)


def failed_outcome(reason: str) -> GraphOutcome:
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
    """Drains a pipe to EOF, retaining only the first `limit` characters of its UTF-8 decoding."""

    def __init__(self, stream, limit: int) -> None:
        self._fd = stream.fileno()
        self._limit = limit
        self.head = ""
        self.stale = False
        self._line: str | None = ""
        self._total = 0
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while True:
            try:
                chunk = os.read(self._fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            self._absorb(decoder.decode(chunk))
        self._absorb(decoder.decode(b"", final=True))

    def _absorb(self, text: str) -> None:
        self._total += len(text)
        # Notice detection covers the full stream; the head cap does not bound it.
        *complete, tail = text.split("\n")
        if complete:
            if self._line is not None:
                complete[0] = self._line + complete[0]
            else:
                complete = complete[1:]
            if any(line.startswith("**") and _STALE_NOTICE in line for line in complete):
                self.stale = True
            carried: str | None = tail
        else:
            carried = None if self._line is None else self._line + tail
        self._line = None if carried is None or len(carried) > _LINE_SCAN_CHARS else carried
        room = self._limit - len(self.head)
        if room > 0:
            self.head += text[:room]

    def join(self) -> None:
        self._thread.join(_JOIN_TIMEOUT_S)

    def result(self) -> tuple[str, bool, int]:
        if self._total <= self._limit:
            return self.head, False, 0
        keep = self.head[: max(0, self._limit - len(TRUNCATION_MARKER))]
        return keep + TRUNCATION_MARKER, True, self._total - len(keep)


class _ProcessTree:
    """Owns the child's Job Object (Windows) so descendants of an exited parent are reaped on close."""

    def __init__(self, proc: subprocess.Popen) -> None:
        self._job = _assign_job(proc.pid) if os.name == "nt" else None
        if os.name == "nt" and self._job is None:
            logger.debug("Job Object assignment failed for pid %s; descendants may outlive the call", proc.pid)

    def close(self) -> None:
        if self._job is not None:
            _close_handle(self._job)
            self._job = None


def _terminate(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        if proc.poll() is None:
            system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
            taskkill = os.path.join(system_root, "System32", "taskkill.exe")
            try:
                subprocess.run(
                    [taskkill, "/PID", str(proc.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except OSError as exc:
                logger.debug("taskkill could not be launched for pid %s: %s", proc.pid, exc)
    else:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
    if proc.poll() is None:
        proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=_JOIN_TIMEOUT_S)


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
    root = os.path.normcase(os.path.realpath(path))

    def clear_and_retry(func, failed, _exc) -> None:
        _grant_owner_write(failed, root)
        with contextlib.suppress(FileNotFoundError):
            func(failed)

    for attempt in range(_REMOVE_ATTEMPTS):
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(path, onexc=clear_and_retry)
            else:
                shutil.rmtree(path, onerror=clear_and_retry)
            return
        except OSError:
            if attempt + 1 < _REMOVE_ATTEMPTS:
                time.sleep(_REMOVE_RETRY_S)
    logger.warning("could not remove graph scratch directory: %s", path)


def _grant_owner_write(failed, root: str) -> None:
    for entry in (failed, os.path.dirname(failed)):
        if not _is_within_tree(entry, root):
            continue
        with contextlib.suppress(OSError):
            mode = stat.S_IMODE(os.lstat(entry).st_mode)
            extra = stat.S_IRWXU if os.path.isdir(entry) else stat.S_IWUSR
            os.chmod(entry, mode | extra)


def _is_within_tree(path, root: str) -> bool:
    isjunction = getattr(os.path, "isjunction", None)
    if os.path.islink(path) or (isjunction is not None and isjunction(path)):
        return False
    real = os.path.normcase(os.path.realpath(path))
    return real == root or real.startswith(root + os.sep)
