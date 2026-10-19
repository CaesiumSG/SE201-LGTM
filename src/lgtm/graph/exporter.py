from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
import threading
import time
import queue
from dataclasses import dataclass
from pathlib import Path


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


def _fail():
    raise ValueError("export_failed")


def _safe(name):
    if "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return False
    parts = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") or ":" in p or p.endswith((".", " ")) or p.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1,10)), *(f"LPT{i}" for i in range(1,10))} for p in parts):
        return False
    return True


def export_snapshot(repo, sha, destination, *, max_files=20000, max_bytes=209715200, timeout=60):
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        _fail()
    max_files, max_bytes = min(max_files, 20000), min(max_bytes, 209715200)
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
    inventory_paths = set()
    inventory_gitlinks = set()
    incomplete = False
    def cleanup_inventory():
        inventory_stop.set()
        if inventory_proc is not None:
            if inventory_proc.poll() is None:
                try: inventory_proc.terminate()
                except OSError: pass
                try: inventory_proc.wait(timeout=max(0.01, min(0.5, deadline-time.monotonic())))
                except subprocess.TimeoutExpired:
                    inventory_proc.kill()
                    inventory_proc.wait(timeout=max(0.01, min(0.5, deadline-time.monotonic())))
            for pipe in (inventory_proc.stdout, inventory_proc.stderr):
                if pipe is not None:
                    try: pipe.close()
                    except OSError: pass
        if inventory_reader is not None:
            inventory_reader.join(timeout=max(0.01, min(0.5, deadline-time.monotonic())))
            if inventory_reader.is_alive(): _fail()
    try:
        check = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True, timeout=max(0.001, deadline - time.monotonic()))
        if check.returncode:
            _fail()
        inventory_proc = subprocess.Popen(["git", "-C", str(repo), "ls-tree", "-r", "-z", "--full-tree", sha], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        inventory_chunks = queue.Queue(maxsize=2)
        inventory_data = bytearray()
        inventory_bytes = records = 0
        inventory_limit = max_files + 1
        def inventory_pump():
            try:
                while not inventory_stop.is_set():
                    chunk = inventory_proc.stdout.read1(65536)
                    if not chunk: break
                    while not inventory_stop.is_set():
                        try: inventory_chunks.put(chunk, timeout=0.05); break
                        except queue.Full: continue
            except BaseException as exc:
                while not inventory_stop.is_set():
                    try: inventory_chunks.put(exc, timeout=0.05); break
                    except queue.Full: continue
            finally:
                while not inventory_stop.is_set():
                    try: inventory_chunks.put(None, timeout=0.05); break
                    except queue.Full: continue
        inventory_reader = threading.Thread(target=inventory_pump, name="lgtm-git-tree-reader")
        inventory_reader.start()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError
            try: chunk = inventory_chunks.get(timeout=remaining)
            except queue.Empty: raise TimeoutError
            if isinstance(chunk, BaseException): raise chunk
            if chunk is None: break
            inventory_bytes += len(chunk)
            if inventory_bytes > 8 * 1024 * 1024:
                inventory_capped = True; break
            start = 0
            while True:
                end = chunk.find(b"\0", start)
                if end < 0:
                    inventory_data.extend(chunk[start:])
                    if len(inventory_data) > 65536: inventory_capped = True
                    break
                inventory_data.extend(chunk[start:end])
                record = bytes(inventory_data); inventory_data.clear(); start = end + 1
                records += 1
                if records > inventory_limit:
                    inventory_capped = True; break
                try:
                    metadata, raw_path = record.split(b"\t", 1)
                    mode, objtype, object_id = metadata.split(b" ")
                    if len(object_id) != 40 or objtype not in (b"blob", b"commit"):
                        raise ValueError
                    path = raw_path.decode("utf-8", "surrogateescape")
                except (ValueError, UnicodeError):
                    _fail()
                inventory_paths.add(path)
                if mode == b"160000": inventory_gitlinks.add(path)
                if path.endswith("/.gitattributes") or path == ".gitattributes": incomplete = True
            if inventory_capped: break
        if not inventory_capped and inventory_data: _fail()
        if inventory_capped:
            cleanup_inventory()
            inventory_paths.clear(); inventory_gitlinks.clear()
        else:
            try: inventory_proc.wait(timeout=max(0.001, deadline-time.monotonic()))
            except subprocess.TimeoutExpired: _fail()
            if inventory_proc.returncode: _fail()
            inventory_stop.set()
            if inventory_reader.is_alive(): inventory_reader.join(timeout=max(0.01, deadline-time.monotonic()))
            if inventory_reader.is_alive(): _fail()
            for pipe in (inventory_proc.stdout, inventory_proc.stderr):
                if pipe is not None: pipe.close()
        proc = subprocess.Popen(["git", "-C", str(repo), "archive", "--format=tar", sha], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        chunks = queue.Queue(maxsize=2)
        pump_cancelled = threading.Event()
        def pump():
            try:
                while not pump_cancelled.is_set():
                    chunk = proc.stdout.read(65536)
                    if not chunk: break
                    while not stop_reader.is_set() and not pump_cancelled.is_set():
                        try:
                            chunks.put(chunk, timeout=0.05)
                            break
                        except queue.Full:
                            continue
            except BaseException as exc:
                if not stop_reader.is_set():
                    try: chunks.put(exc, timeout=0.05)
                    except queue.Full: pass
            finally:
                while not stop_reader.is_set():
                    try:
                        chunks.put(None, timeout=0.05)
                        break
                    except queue.Full:
                        continue
        reader = threading.Thread(target=pump, name="lgtm-git-archive-reader")
        reader.start()
        member_limit = 20000 + max_files
        raw_limit = max_bytes + 1024 * member_limit + 8 * 1024 * 1024
        class RawArchiveLimit(Exception): pass
        class TimedStream:
            pending = bytearray()
            delivered = 0
            def read(self, amount=-1):
                if amount < 0:
                    amount = raw_limit - self.delivered + 1
                if self.delivered + amount > raw_limit:
                    allowed = raw_limit - self.delivered
                    amount = allowed
                    capped = True
                else:
                    capped = False
                while len(self.pending) < amount:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: raise TimeoutError
                    try: chunk = chunks.get(timeout=remaining)
                    except queue.Empty: raise TimeoutError
                    if chunk is None: break
                    if isinstance(chunk, BaseException): raise chunk
                    self.pending.extend(chunk)
                result = bytes(self.pending[:amount])
                del self.pending[:len(result)]
                self.delivered += len(result)
                if capped: raise RawArchiveLimit
                return result
        stream = TimedStream()
        count = size = members = 0
        skipped = []
        nodes = {}
        seen_inventory = set()
        stripped = truncated = False
        try:
            archive_context = tarfile.open(fileobj=stream, mode="r|*")
            with archive_context as archive:
                for item in archive:
                    if members >= member_limit:
                        truncated = incomplete = True
                        break
                    members += 1
                    name = item.name.rstrip("/")
                    parts = name.split("/")
                    if any(p == ".codegraph" for p in parts) or parts[-1] in (".gitignore", "codegraph.json"):
                        stripped = True
                        continue
                    if time.monotonic() > deadline:
                        proc.kill(); _fail()
                    if not _safe(item.name):
                        incomplete = True
                        if len(skipped) < 50: skipped.append({"category": "unsafe_path", "path": "<rejected>"})
                        continue
                    if not item.isdir() and not item.isfile():
                        incomplete = True
                        if len(skipped) < 50: skipped.append({"category": "nonregular", "path": "<rejected>"})
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
                        if len(skipped) < 50: skipped.append({"category": "collision", "path": "<rejected>"})
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
                        if len(skipped) < 50: skipped.append({"category": "unwritable", "path": "<rejected>"})
                        continue
                    failed_write = False
                    remaining = item.size
                    try:
                        while remaining:
                            chunk = source.read(min(65536, remaining))
                            if not chunk: _fail()
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
                        if len(skipped) < 50: skipped.append({"category": "unwritable", "path": "<rejected>"})
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
            proc.wait(timeout=max(0.001, deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
            if not truncated: _fail()
        if not truncated and proc.returncode:
            _fail()
        if inventory_capped:
            truncated = incomplete = True
        if inventory_gitlinks or inventory_paths.difference(seen_inventory):
            incomplete = True
        for path in sorted(inventory_gitlinks)[:50]:
            if len(skipped) < 50:
                skipped.append({"category": "gitlink", "path": "<rejected>"})
        if truncated:
            pump_cancelled.set()
            stop_reader.set()
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                try: pipe.close()
                except OSError: pass
        if reader is not None:
            reader.join(timeout=2)
            if reader.is_alive(): _fail()
        return ExportResult(dest, count, size, members, stripped, truncated, incomplete, tuple(skipped))
    except ValueError:
        cleanup_inventory()
        if proc is not None:
            stop_reader.set()
            if proc.poll() is None:
                try: proc.kill()
                except OSError: pass
            try: proc.wait(timeout=2)
            except BaseException: pass
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try: pipe.close()
                    except OSError: pass
        if reader is not None: reader.join(timeout=2)
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except BaseException:
        try: cleanup_inventory()
        except BaseException: pass
        stop_reader.set()
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=2)
            except BaseException:
                pass
            for pipe in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
                if pipe is not None:
                    try: pipe.close()
                    except OSError: pass
        if reader is not None:
            reader.join(timeout=2)
        shutil.rmtree(dest, ignore_errors=True)
        _fail()
