"""Evidence validator.

Verifies that every claim an agent made is grounded in reality:
- cited file paths exist (on the base branch or in the PR diff),
- cited line numbers fall within the file,
- cited code snippets appear in the file (fuzzy match),
- cited policy sources exist among the indexed documents.

Code evidence labelled with a snapshot is checked only against the committed
blob at that snapshot's frozen commit, against the raw or the sanitized text.

Validation annotates each cited code item with ``grounded_in_pr``.
"""

from __future__ import annotations

import difflib
import logging
import re
from collections.abc import Mapping
from pathlib import Path

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.agents.tools import read_committed_blob, relative_path
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, GitError, Hunk, LineChange, read_file_at_ref
from lgtm.diff.sanitizer import sanitize_file_diff

logger = logging.getLogger(__name__)

FUZZY_THRESHOLD = 0.75


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _sanitized_text(path: str, lines: list[str]) -> str:
    """``lines`` as the model saw them: comments and docstrings stripped."""
    changes = [LineChange("add", line, None, n) for n, line in enumerate(lines, 1)]
    hunk = Hunk(1, 0, 1, len(lines), changes=changes)
    return sanitize_file_diff(FileDiff(path, hunks=[hunk])).added_text


def _locator_candidates(path: str) -> list[str]:
    """``path`` as cited, then with ``#anchor`` / ``:12-20`` / ``:symbol``
    / ``:line:col`` suffixes progressively removed.

    The raw path comes first so real file names containing ``:`` or ``#``
    still resolve.
    """
    raw = path.strip()
    candidates = [raw]
    current = raw.split("#", 1)[0].strip()
    for _ in range(3):
        if current and current not in candidates:
            candidates.append(current)
        stripped = re.sub(r":[\w.-]*$", "", current).strip()
        if stripped == current:
            break
        current = stripped
    if current and current not in candidates:
        candidates.append(current)
    return candidates


def _committed_blob_lines(repo: Path, sha: str, path: str, timeout: float) -> list[str] | None:
    """Lines of ``path`` at commit ``sha``; None when absent or unreadable."""
    if "\\" in path:
        return None
    rel = relative_path(path)
    if rel is None:
        return None
    done = read_committed_blob(repo, sha, rel, timeout)
    if done is None or done.returncode != 0:
        return None
    return done.stdout.splitlines()


def _is_ordered_positive_range(lines: list[int]) -> bool:
    return len(lines) == 2 and 1 <= lines[0] <= lines[1]


class EvidenceValidator:
    def __init__(
        self,
        repo: str | Path,
        base_ref: str,
        diffs: list[FileDiff] | None = None,
        config: LGTMConfig | None = None,
        *,
        shas: Mapping[str, str] | None = None,
    ):
        self.repo = Path(repo).resolve()
        self.base_ref = base_ref
        self.config = config or LGTMConfig()
        self._file_cache: dict[str, list[str] | None] = {}
        self._shas: dict[str, str] | None = None if shas is None else dict(shas)
        self._snapshot_cache: dict[tuple[str, str], list[str] | None] = {}
        # Content added by the PR, by file — snippets may legitimately cite it.
        self._diff_added: dict[str, str] = {}
        self._diff_removed: dict[str, str] = {}
        for fd in diffs or []:
            self._diff_added[fd.path] = _normalize(fd.added_text)
            self._diff_removed[fd.path] = _normalize(fd.removed_text)

    # ------------------------------------------------------------------
    def _read_base_file(self, path: str) -> list[str] | None:
        """Read a file from the base branch, cached. None when missing."""
        if path not in self._file_cache:
            try:
                content = read_file_at_ref(
                    self.repo, self.base_ref, path, self.config.git_timeout
                )
                self._file_cache[path] = content.splitlines()
            except GitError:
                # Fall back to the working tree (useful for docs not in git yet)
                fs_path = self.repo / path
                try:
                    if fs_path.resolve().is_relative_to(self.repo) and fs_path.is_file():
                        self._file_cache[path] = fs_path.read_text(
                            encoding="utf-8", errors="replace"
                        ).splitlines()
                    else:
                        self._file_cache[path] = None
                except (OSError, ValueError):
                    self._file_cache[path] = None
        return self._file_cache[path]

    def _resolve_path(self, path: str) -> str:
        """The first locator candidate that exists (base branch or PR diff)."""
        candidates = _locator_candidates(path)
        for candidate in candidates:
            if candidate in self._diff_added or self._read_base_file(candidate) is not None:
                return candidate
        return candidates[-1]

    def _snippet_in_text(self, snippet: str, haystack: str) -> bool:
        snippet_n = _normalize(snippet)
        if not snippet_n:
            return True
        if snippet_n in haystack:
            return True
        # Fuzzy: slide over the haystack in windows
        window = len(snippet_n)
        if window > len(haystack):
            ratio = difflib.SequenceMatcher(None, snippet_n, haystack).ratio()
            return ratio >= FUZZY_THRESHOLD
        # Coarse-to-fine search. A plain window // 2 stride skipped the
        # aligned offset and rejected near-verbatim snippets with one elided
        # line; a stride of 1 everywhere took ~40s on a 1000-line file. So:
        # score a grid of offsets, then search stride-1 around the best few.
        def score(i: int) -> float:
            matcher = difflib.SequenceMatcher(
                None, snippet_n, haystack[i : i + window + 20]
            )
            if matcher.quick_ratio() < FUZZY_THRESHOLD:
                return 0.0
            return matcher.ratio()

        last = len(haystack) - window
        step = max(1, window // 8)
        coarse = [(score(i), i) for i in range(0, last + 1, step)]
        if any(r >= FUZZY_THRESHOLD for r, _ in coarse):
            return True
        for _, best in sorted(coarse, reverse=True)[:3]:
            for i in range(max(0, best - step), min(last, best + step) + 1):
                if score(i) >= FUZZY_THRESHOLD:
                    return True
        return False

    def _snippet_in_file(self, snippet: str, path: str, lines: list[str]) -> bool:
        """Fuzzy match against the raw file, then against its sanitized text."""
        if self._snippet_in_text(snippet, _normalize("\n".join(lines))):
            return True
        return self._snippet_in_text(snippet, _normalize(_sanitized_text(path, lines)))

    # ------------------------------------------------------------------
    def _snapshot_lines(self, label: str, path: str) -> list[str] | None:
        key = (label, path)
        if key not in self._snapshot_cache:
            self._snapshot_cache[key] = _committed_blob_lines(
                self.repo, self._shas[label], path, self.config.git_timeout
            )
        return self._snapshot_cache[key]

    def _validate_snapshot_item(self, item: EvidenceItem) -> list[str]:
        label = item.snapshot
        if label not in self._shas:
            return [f"snapshot '{label}' is unavailable for this review"]
        lines = self._snapshot_lines(label, item.file)
        if lines is None:
            return [f"cited file {item.file} does not exist at {label} snapshot"]
        if item.lines is not None:
            if not _is_ordered_positive_range(item.lines):
                return [f"invalid cited line range for {item.file} at {label} snapshot"]
            start, end = item.lines
            if end > len(lines):
                return [
                    f"cited lines {start}-{end} out of range for {item.file} "
                    f"at {label} snapshot ({len(lines)} lines)"
                ]
        if item.content.strip():
            if not self._snippet_in_file(item.content, item.file, lines):
                return [
                    f"cited code snippet not found in {item.file} at {label} snapshot: "
                    f"{item.content[:80]!r}"
                ]
        return []

    @staticmethod
    def _conflict_issue(item: EvidenceItem) -> str:
        if item.raw_snapshot is not None:
            return f"unknown snapshot label: {item.raw_snapshot!r}"
        return "evidence snapshot field and @alias disagree"

    def _validate_code_item(self, item: EvidenceItem) -> list[str]:
        strict = self._shas is not None
        if strict and item.snapshot_conflict:
            return [self._conflict_issue(item)]
        if not item.file:
            return ["code evidence has no file path"]
        if strict and item.snapshot is not None:
            return self._validate_snapshot_item(item)
        return self._validate_unlabelled_item(item)

    def _validate_unlabelled_item(self, item: EvidenceItem) -> list[str]:
        issues: list[str] = []
        item.file = self._resolve_path(item.file)
        lines = self._read_base_file(item.file)
        in_diff = item.file in self._diff_added

        if lines is None and not in_diff:
            issues.append(f"cited file does not exist: {item.file}")
            return issues

        if item.lines and lines is not None:
            start = item.lines[0]
            end = item.lines[-1]
            if start < 1 or end > len(lines) + 50:  # new files grow; allow slack via diff
                if not in_diff:
                    issues.append(
                        f"cited lines {start}-{end} out of range for "
                        f"{item.file} ({len(lines)} lines)"
                    )

        if item.content.strip():
            found = False
            if lines is not None:
                if item.lines:
                    lo = max(0, item.lines[0] - 6)
                    hi = min(len(lines), item.lines[-1] + 5)
                    region = _normalize("\n".join(lines[lo:hi]))
                    found = self._snippet_in_text(item.content, region)
                if not found:
                    found = self._snippet_in_file(item.content, item.file, lines)
            if not found and in_diff:
                found = self._snippet_in_text(item.content, self._diff_added[item.file])
            if not found:
                issues.append(
                    f"cited code snippet not found in {item.file}: "
                    f"{item.content[:80]!r}"
                )
        return issues

    def resolution_issues(self, item: EvidenceItem) -> list[str]:
        """Why a code item does not resolve at its snapshot; unlabelled items resolve at pr, then base."""
        if self._shas is None:
            return []
        if item.snapshot is None and not item.snapshot_conflict:
            issues: list[str] = []
            for label in ("pr", "base"):
                if label in self._shas:
                    found = self._validate_code_item(item.model_copy(update={"snapshot": label}))
                    if not found:
                        return []
                    issues.extend(found)
            return issues or ["no snapshot is available for this review"]
        return self._validate_code_item(item)

    def resolves(self, item: EvidenceItem) -> bool:
        return not self.resolution_issues(item)

    def _validate_policy_item(self, item: EvidenceItem) -> list[str]:
        issues: list[str] = []
        source = item.source or item.file
        if not source:
            issues.append("policy evidence has no source document")
            return issues
        source_path = self._resolve_path(source)
        lines = self._read_base_file(source_path)
        if lines is None:
            issues.append(f"cited policy document does not exist: {source_path}")
            return issues
        if item.content.strip():
            whole = _normalize("\n".join(lines))
            if not self._snippet_in_text(item.content, whole):
                issues.append(
                    f"cited policy text not found in {source_path}: "
                    f"{item.content[:80]!r}"
                )
        return issues

    # ------------------------------------------------------------------
    def _grounds_pr(self, item: EvidenceItem, issues: list[str]) -> bool:
        """Whether a code item on its own grounds a vulnerable verdict in the PR."""
        if item.type != "code" or issues or not item.content.strip():
            return False
        labelled = self._shas is not None and item.snapshot is not None
        if labelled and item.snapshot == "pr":
            return True
        if item.file not in self._diff_added:
            return False
        texts = [self._diff_removed[item.file]]
        if not labelled:
            texts.append(self._diff_added[item.file])
        return any(self._snippet_in_text(item.content, t) for t in texts)

    def _content_at_lines(self, item: EvidenceItem, label: str) -> bool:
        lines = self._snapshot_lines(label, item.file)
        if lines is None or not item.lines or not item.content.strip():
            return False
        if not _is_ordered_positive_range(item.lines):
            return False
        return _normalize(item.content) in _normalize("\n".join(lines[item.lines[0] - 1 : item.lines[1]]))

    def read_cited_code(self, item: EvidenceItem) -> str:
        """Code at the cited location; empty when it cannot be read."""
        if not item.file:
            return ""
        lines: list[str] | None = None
        if self._shas is None:
            lines = self._read_base_file(self._resolve_path(item.file))
        else:
            labels = ["pr", "base"]
            if item.snapshot:
                labels = [item.snapshot]
            elif not item.snapshot_conflict:
                # Prefer the snapshot holding the content at the cited lines (removed or shifted code),
                # then any snapshot where the citation validates.
                valid = [
                    label
                    for label in labels
                    if label in self._shas
                    and not self._validate_code_item(item.model_copy(update={"snapshot": label}))
                ]
                labels = [label for label in valid if self._content_at_lines(item, label)] or valid or labels
            for label in labels:
                if label in self._shas:
                    lines = self._snapshot_lines(label, item.file)
                if lines is not None:
                    break
        if lines is None:
            return ""
        if item.lines is not None and _is_ordered_positive_range(item.lines):
            lines = lines[item.lines[0] - 1 : item.lines[1]]
        return "\n".join(lines)

    def validate(self, finding: AgentFinding) -> AgentFinding:
        """Annotate ``grounded_in_pr`` on each cited code item in place and return the finding."""
        for item in finding.evidence:
            if item.type != "policy":
                item.grounded_in_pr = self._grounds_pr(item, self._validate_code_item(item))
        return finding

    def validate_all(self, findings: list[AgentFinding]) -> list[AgentFinding]:
        return [self.validate(f) for f in findings]
