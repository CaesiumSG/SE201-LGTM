from __future__ import annotations

import os
import queue
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from lgtm.config import GRAPH_EXPORT_BYTES_CEILING, GRAPH_EXPORT_FILES_CEILING

_MAX_SKIPPED = 50
_CHUNK_SIZE = 65536
_QUEUE_POLL_S = 0.05
_INVENTORY_MAX_BYTES = 8 * 1024 * 1024
_INVENTORY_MAX_RECORD = 65536
_ARCHIVE_MEMBER_OVERHEAD = 1024
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


@dataclass(frozen=True)
class ExportResult:
    root: Path
    file_count: int
    byte_count: int
    member_count: int
    stripped: bool
    truncated: bool
    incomplete: bool
    skipped: tuple
    notes: tuple = ()


def _fail() -> NoReturn:
    raise ValueError("export_failed")


def _safe(name: str) -> bool:
    if "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return False
    parts = name.rstrip("/").split("/")
    return not any(
        p in ("", ".", "..") or ":" in p or p.endswith((".", " ")) or p.split(".")[0].upper() in _RESERVED_NAMES
        for p in parts
    )


def _clear_read_only(func: Callable[[str], object], path: str, *_: object) -> None:
    os.chmod(path, stat.S_IWRITE)
    func(path)


_RMTREE_ERROR_HANDLER = {"onexc": _clear_read_only} if sys.version_info >= (3, 12) else {"onerror": _clear_read_only}


def _remove_owned_root(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    for attempt in range(3):
        try:
            shutil.rmtree(path, **_RMTREE_ERROR_HANDLER)
        except OSError:
            pass
        if not path.exists() and not path.is_symlink():
            return
        if attempt < 2:
            time.sleep(0.2)
    _fail()


class RawArchiveLimit(Exception):
    pass


class TimedStream:
    def __init__(self, chunks: queue.Queue, deadline: float, raw_limit: int) -> None:
        self._chunks = chunks
        self._deadline = deadline
        self._raw_limit = raw_limit
        self._pending = bytearray()
        self._delivered = 0

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = self._raw_limit - self._delivered + 1
        capped = self._delivered + amount > self._raw_limit
        if capped:
            amount = self._raw_limit - self._delivered
        while len(self._pending) < amount:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                chunk = self._chunks.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError
            if chunk is None:
                break
            if isinstance(chunk, BaseException):
                raise chunk
            self._pending.extend(chunk)
        result = bytes(self._pending[:amount])
        del self._pending[:len(result)]
        self._delivered += len(result)
        if capped:
            raise RawArchiveLimit
        return result


def _time_left(deadline: float, floor: float = 0.001) -> float:
    return max(floor, deadline - time.monotonic())


def _grace(deadline: float) -> float:
    return max(0.01, min(0.5, deadline - time.monotonic()))


def _put(items: queue.Queue, item: object, abandoned: Callable[[], bool]) -> None:
    while not abandoned():
        try:
            items.put(item, timeout=_QUEUE_POLL_S)
            return
        except queue.Full:
            continue


def _pump(read: Callable[[int], bytes], items: queue.Queue, stop: threading.Event, cancelled: threading.Event) -> None:
    try:
        while not cancelled.is_set():
            chunk = read(_CHUNK_SIZE)
            if not chunk:
                break
            _put(items, chunk, lambda: stop.is_set() or cancelled.is_set())
    except BaseException as exc:
        _put(items, exc, stop.is_set)
    finally:
        _put(items, None, stop.is_set)


def _start_pump(
    read: Callable[[int], bytes], name: str, stop: threading.Event, cancelled: threading.Event
) -> tuple[queue.Queue, threading.Thread]:
    items: queue.Queue = queue.Queue(maxsize=2)
    thread = threading.Thread(target=_pump, args=(read, items, stop, cancelled), name=name)
    thread.start()
    return items, thread


def _close_pipes(proc: subprocess.Popen) -> None:
    for pipe in (proc.stdout, proc.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


def _stop_inventory(
    proc: subprocess.Popen | None, reader: threading.Thread | None, stop: threading.Event, deadline: float
) -> None:
    stop.set()
    if proc is not None:
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(timeout=_grace(deadline))
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=_grace(deadline))
        _close_pipes(proc)
    if reader is not None:
        reader.join(timeout=_grace(deadline))
        if reader.is_alive():
            _fail()


def _reap(proc: subprocess.Popen | None, reader: threading.Thread | None, stop: threading.Event) -> None:
    stop.set()
    if proc is not None:
        try:
            if proc.poll() is None:
                proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except BaseException:
            pass
        _close_pipes(proc)
    if reader is not None:
        reader.join(timeout=2)


def _record_skip(skipped: list[dict[str, str]], category: str) -> None:
    if len(skipped) < _MAX_SKIPPED:
        skipped.append({"category": category, "path": "<rejected>"})


def export_snapshot(
    repo: str | os.PathLike[str],
    sha: str,
    destination: str | os.PathLike[str],
    *,
    max_files: int = GRAPH_EXPORT_FILES_CEILING,
    max_bytes: int = GRAPH_EXPORT_BYTES_CEILING,
    timeout: float = 60,
) -> ExportResult:
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        _fail()
    max_files, max_bytes = min(max_files, GRAPH_EXPORT_FILES_CEILING), min(max_bytes, GRAPH_EXPORT_BYTES_CEILING)
    if max_files <= 0 or max_bytes <= 0 or timeout <= 0:
        _fail()
    dest = Path(destination)
    if dest.exists() or dest.is_symlink():
        if not dest.is_dir() or any(dest.iterdir()):
            _fail()
    else:
        try:
            dest.mkdir(parents=True)
        except OSError:
            _fail()
    proc = inventory_proc = None
    reader = inventory_reader = None
    stop_reader = threading.Event()
    inventory_stop = threading.Event()
    deadline = time.monotonic() + timeout
    inventory_capped = False
    inventory_paths: set[str] = set()
    inventory_gitlinks: set[str] = set()
    incomplete = False
    try:
        check = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"],
            capture_output=True,
            timeout=_time_left(deadline),
        )
        if check.returncode:
            _fail()
        inventory_proc = subprocess.Popen(
            ["git", "-C", str(repo), "ls-tree", "-r", "-z", "--full-tree", sha],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        inventory_chunks, inventory_reader = _start_pump(
            inventory_proc.stdout.read1, "lgtm-git-tree-reader", inventory_stop, inventory_stop
        )
        inventory_data = bytearray()
        inventory_bytes = records = 0
        inventory_limit = max_files + 1
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                chunk = inventory_chunks.get(timeout=remaining)
            except queue.Empty:
                raise TimeoutError
            if isinstance(chunk, BaseException):
                raise chunk
            if chunk is None:
                break
            inventory_bytes += len(chunk)
            if inventory_bytes > _INVENTORY_MAX_BYTES:
                inventory_capped = True
                break
            start = 0
            while True:
                end = chunk.find(b"\0", start)
                if end < 0:
                    inventory_data.extend(chunk[start:])
                    if len(inventory_data) > _INVENTORY_MAX_RECORD:
                        inventory_capped = True
                    break
                inventory_data.extend(chunk[start:end])
                record = bytes(inventory_data)
                inventory_data.clear()
                start = end + 1
                records += 1
                if records > inventory_limit:
                    inventory_capped = True
                    break
                try:
                    metadata, raw_path = record.split(b"\t", 1)
                    mode, objtype, object_id = metadata.split(b" ")
                    if len(object_id) != 40 or objtype not in (b"blob", b"commit"):
                        raise ValueError
                    path = raw_path.decode("utf-8", "surrogateescape")
                except (ValueError, UnicodeError):
                    _fail()
                inventory_paths.add(path)
                if mode == b"160000":
                    inventory_gitlinks.add(path)
                if path.endswith("/.gitattributes") or path == ".gitattributes":
                    incomplete = True
            if inventory_capped:
                break
        if not inventory_capped and inventory_data:
            _fail()
        if inventory_capped:
            _stop_inventory(inventory_proc, inventory_reader, inventory_stop, deadline)
            inventory_paths.clear()
            inventory_gitlinks.clear()
        else:
            try:
                inventory_proc.wait(timeout=_time_left(deadline))
            except subprocess.TimeoutExpired:
                _fail()
            if inventory_proc.returncode:
                _fail()
            inventory_stop.set()
            inventory_reader.join(timeout=_time_left(deadline, 0.01))
            if inventory_reader.is_alive():
                _fail()
            for pipe in (inventory_proc.stdout, inventory_proc.stderr):
                if pipe is not None:
                    pipe.close()
        proc = subprocess.Popen(
            ["git", "-C", str(repo), "archive", "--format=tar", sha],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        pump_cancelled = threading.Event()
        chunks, reader = _start_pump(proc.stdout.read, "lgtm-git-archive-reader", stop_reader, pump_cancelled)
        member_limit = GRAPH_EXPORT_FILES_CEILING + max_files
        raw_limit = max_bytes + _ARCHIVE_MEMBER_OVERHEAD * member_limit + _INVENTORY_MAX_BYTES
        stream = TimedStream(chunks, deadline, raw_limit)
        count = size = members = 0
        skipped: list[dict[str, str]] = []
        nodes: dict[str, tuple[str, str]] = {}
        seen_inventory: set[str] = set()
        stripped = truncated = False
        try:
            with tarfile.open(fileobj=stream, mode="r|*") as archive:
                for item in archive:
                    if members >= member_limit:
                        truncated = incomplete = True
                        break
                    members += 1
                    name = item.name.rstrip("/")
                    parts = name.split("/")
                    if any(p == ".codegraph" for p in parts) or parts[-1] in (".gitignore", "codegraph.json"):
                        stripped = True
                        seen_inventory.add(name)
                        continue
                    if time.monotonic() > deadline:
                        proc.kill()
                        _fail()
                    if not _safe(item.name):
                        incomplete = True
                        _record_skip(skipped, "unsafe_path")
                        continue
                    if not item.isdir() and not item.isfile():
                        incomplete = True
                        _record_skip(skipped, "nonregular")
                        continue
                    components = []
                    conflict = False
                    for index in range(len(parts)):
                        spelling = "/".join(parts[:index + 1])
                        key = spelling.casefold()
                        kind = "dir" if index < len(parts) - 1 or item.isdir() else "file"
                        prior = nodes.get(key)
                        if prior and prior != (spelling, kind):
                            conflict = True
                            break
                        components.append((key, spelling, kind))
                    if conflict:
                        incomplete = True
                        _record_skip(skipped, "collision")
                        continue
                    for key, spelling, kind in components:
                        nodes.setdefault(key, (spelling, kind))
                    if item.isdir():
                        continue
                    seen_inventory.add(name)
                    if count >= max_files or size + item.size > max_bytes:
                        truncated = incomplete = True
                        break
                    target = dest.joinpath(*parts)
                    source = archive.extractfile(item)
                    if source is None:
                        incomplete = True
                        continue
                    try:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        resolved = target.resolve()
                        if dest.resolve() not in resolved.parents:
                            _fail()
                        out = target.open("xb")
                    except OSError:
                        incomplete = True
                        _record_skip(skipped, "unwritable")
                        continue
                    failed_write = False
                    remaining = item.size
                    try:
                        while remaining:
                            chunk = source.read(min(_CHUNK_SIZE, remaining))
                            if not chunk:
                                _fail()
                            remaining -= len(chunk)
                            try:
                                out.write(chunk)
                            except OSError:
                                failed_write = True
                                break
                    finally:
                        try:
                            out.close()
                        except OSError:
                            failed_write = True
                    if failed_write:
                        try:
                            target.unlink(missing_ok=True)
                        except OSError:
                            _fail()
                        incomplete = True
                        _record_skip(skipped, "unwritable")
                        continue
                    count += 1
                    size += item.size
        except RawArchiveLimit:
            truncated = incomplete = True
        if truncated:
            pump_cancelled.set()
            stop_reader.set()
            if proc.poll() is None:
                proc.terminate()
        try:
            proc.wait(timeout=_time_left(deadline))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
            if not truncated:
                _fail()
        if not truncated and proc.returncode:
            _fail()
        if inventory_capped:
            truncated = incomplete = True
        if inventory_gitlinks or inventory_paths.difference(seen_inventory):
            incomplete = True
        for _ in sorted(inventory_gitlinks)[:_MAX_SKIPPED]:
            _record_skip(skipped, "gitlink")
        if truncated:
            pump_cancelled.set()
            stop_reader.set()
        _close_pipes(proc)
        reader.join(timeout=2)
        if reader.is_alive():
            _fail()
        return ExportResult(dest, count, size, members, stripped, truncated, incomplete, tuple(skipped))
    except BaseException as exc:
        try:
            _stop_inventory(inventory_proc, inventory_reader, inventory_stop, deadline)
        except BaseException:
            pass
        _reap(proc, reader, stop_reader)
        if isinstance(exc, ValueError):
            _remove_owned_root(dest)
            raise
        if not isinstance(exc, Exception):
            try:
                _remove_owned_root(dest)
            except ValueError:
                pass
            raise
        _remove_owned_root(dest)
        _fail()
