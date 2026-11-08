"""Git diff extraction and unified-diff parsing.

Runs ``git diff <base>..<pr>`` via subprocess and parses the output into
structured :class:`FileDiff` objects.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)

# The two paths on a "diff --git" line, quoted or plain (plain may have spaces)
DIFF_GIT_RE = re.compile(
    r'^diff --git (?P<old>"(?:[^"\\]|\\.)*"|a/.*?) (?P<new>"(?:[^"\\]|\\.)*"|b/.*)$'
)

# Escapes inside a quoted path: octal bytes (\303) or C escapes (\t, \")
QUOTED_ESCAPE_RE = re.compile(rb'\\([0-7]{3}|[abtnvfr"\\])')
C_ESCAPES = {
    b"a": b"\a", b"b": b"\b", b"t": b"\t", b"n": b"\n", b"v": b"\v",
    b"f": b"\f", b"r": b"\r", b'"': b'"', b"\\": b"\\",
}


class GitError(RuntimeError):
    """Raised when a git subprocess call fails."""


@dataclass
class LineChange:
    """A single changed line within a hunk."""

    kind: str  # "add" | "del" | "context"
    content: str
    old_lineno: int | None = None  # line number in the base file (None for adds)
    new_lineno: int | None = None  # line number in the PR file (None for dels)


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str = ""
    changes: list[LineChange] = field(default_factory=list)

    @property
    def added_lines(self) -> list[LineChange]:
        return [c for c in self.changes if c.kind == "add"]

    @property
    def deleted_lines(self) -> list[LineChange]:
        return [c for c in self.changes if c.kind == "del"]


@dataclass
class FileDiff:
    path: str  # new path (b-side); for deletions this is the old path
    old_path: str | None = None
    status: str = "modified"  # "added" | "deleted" | "modified" | "renamed"
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def added_line_numbers(self) -> list[int]:
        """New-file line numbers of all added lines."""
        nums: list[int] = []
        for hunk in self.hunks:
            nums.extend(
                c.new_lineno for c in hunk.changes if c.kind == "add" and c.new_lineno
            )
        return nums

    @property
    def added_text(self) -> str:
        """All added lines joined, useful as agent context."""
        lines: list[str] = []
        for hunk in self.hunks:
            lines.extend(c.content for c in hunk.changes if c.kind == "add")
        return "\n".join(lines)

    @property
    def removed_text(self) -> str:
        """All deleted lines joined."""
        lines: list[str] = []
        for hunk in self.hunks:
            lines.extend(c.content for c in hunk.deleted_lines)
        return "\n".join(lines)

    def hunk_text(self) -> str:
        """Render the diff of this file back as a unified-diff fragment."""
        out: list[str] = [f"--- a/{self.old_path or self.path}", f"+++ b/{self.path}"]
        for hunk in self.hunks:
            out.append(
                f"@@ -{hunk.old_start},{hunk.old_count} "
                f"+{hunk.new_start},{hunk.new_count} @@{hunk.header}"
            )
            for change in hunk.changes:
                prefix = {"add": "+", "del": "-", "context": " "}[change.kind]
                out.append(prefix + change.content)
        return "\n".join(out)


def _run_git(args: list[str], repo: str | Path, timeout: int = 60) -> str:
    """Run a git command in ``repo`` and return its output.

    Some files aren't UTF-8 (e.g. Latin-1). Bytes that can't be decoded
    become "�" instead of crashing the review. Line numbers don't change.
    """
    cmd = ["git", "-C", str(repo), *args]
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git command timed out after {timeout}s: {' '.join(cmd)}") from exc
    except FileNotFoundError as exc:
        raise GitError("git executable not found on PATH") from exc
    if result.returncode != 0:
        raise GitError(
            f"git failed (exit {result.returncode}): {' '.join(cmd)}\n{result.stderr.strip()}"
        )
    return result.stdout


def get_raw_diff(repo: str | Path, base: str, pr: str, timeout: int = 60) -> str:
    """Return the raw unified diff text between two refs."""
    return _run_git(
        ["diff", "--no-color", "--unified=3", f"{base}..{pr}"], repo, timeout
    )


def get_pr_diff(repo: str | Path, base: str, pr: str, timeout: int = 60) -> list[FileDiff]:
    """Run ``git diff base..pr`` and parse it into FileDiff objects."""
    raw = get_raw_diff(repo, base, pr, timeout)
    return parse_unified_diff(raw)


def get_changed_files(repo: str | Path, base: str, pr: str, timeout: int = 60) -> list[str]:
    """List file paths changed between two refs."""
    out = _run_git(["diff", "--name-only", f"{base}..{pr}"], repo, timeout)
    return [line.strip() for line in out.splitlines() if line.strip()]


def read_file_at_ref(
    repo: str | Path, ref: str, path: str, timeout: int = 60
) -> str:
    """Read a file's content at a specific git ref (e.g. the base branch)."""
    return _run_git(["show", f"{ref}:{path}"], repo, timeout)


def _unquote_path(path: str) -> str:
    """Turn a path git has quoted back into the real path.

    git quotes paths with unusual characters, e.g. ``café.py`` becomes
    ``"caf\\303\\251.py"``. Unquoted paths are returned as they are.
    """
    if len(path) < 2 or not (path.startswith('"') and path.endswith('"')):
        return path
    raw = QUOTED_ESCAPE_RE.sub(
        lambda m: bytes([int(m.group(1), 8)])
        if len(m.group(1)) == 3
        else C_ESCAPES[m.group(1)],
        path[1:-1].encode("utf-8"),
    )
    return raw.decode("utf-8", errors="replace")


def _diff_path(token: str, prefix: str) -> str:
    """Unquote a diff path, then remove its ``a/`` or ``b/`` prefix.

    Unquote first: in ``"b/caf\\303\\251.py"`` the prefix is inside the quotes.
    """
    path = _unquote_path(token)
    return path[len(prefix):] if path.startswith(prefix) else path


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """Parse unified diff text into structured FileDiff objects."""
    files: list[FileDiff] = []
    current: FileDiff | None = None
    hunk: Hunk | None = None
    old_lineno = new_lineno = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current = None
            hunk = None
            # Fallback paths; the ---/+++ lines override them when present
            match = DIFF_GIT_RE.match(line)
            old_p = _diff_path(match.group("old"), "a/") if match else None
            new_p = _diff_path(match.group("new"), "b/") if match else None
            current = FileDiff(path=new_p or "", old_path=old_p)
            files.append(current)
            continue
        if current is None:
            continue
        if line.startswith("new file mode"):
            current.status = "added"
            continue
        if line.startswith("deleted file mode"):
            current.status = "deleted"
            continue
        if line.startswith("rename from "):
            current.status = "renamed"
            current.old_path = _unquote_path(line[len("rename from "):].strip())
            continue
        if line.startswith("rename to "):
            current.path = _unquote_path(line[len("rename to "):].strip())
            continue
        if line.startswith("--- "):
            path = line[4:].strip()
            if path != "/dev/null":
                current.old_path = _diff_path(path, "a/")
            continue
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path != "/dev/null":
                current.path = _diff_path(path, "b/")
            elif current.old_path:
                current.path = current.old_path
            continue
        header_match = HUNK_HEADER_RE.match(line)
        if header_match:
            old_start = int(header_match.group("old_start"))
            old_count = int(header_match.group("old_count") or 1)
            new_start = int(header_match.group("new_start"))
            new_count = int(header_match.group("new_count") or 1)
            trailing = line[header_match.end():]
            hunk = Hunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                header=trailing,
            )
            current.hunks.append(hunk)
            old_lineno = old_start
            new_lineno = new_start
            continue
        if hunk is None:
            continue
        if line.startswith("+"):
            hunk.changes.append(
                LineChange(kind="add", content=line[1:], new_lineno=new_lineno)
            )
            new_lineno += 1
        elif line.startswith("-"):
            hunk.changes.append(
                LineChange(kind="del", content=line[1:], old_lineno=old_lineno)
            )
            old_lineno += 1
        elif line.startswith(" ") or line == "":
            content = line[1:] if line.startswith(" ") else ""
            hunk.changes.append(
                LineChange(
                    kind="context",
                    content=content,
                    old_lineno=old_lineno,
                    new_lineno=new_lineno,
                )
            )
            old_lineno += 1
            new_lineno += 1
        # Lines like "\ No newline at end of file" are ignored.

    return files
