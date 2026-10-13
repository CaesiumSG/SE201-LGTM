"""Evidence validator.

Verifies that every claim an agent made is grounded in reality:
- cited file paths exist (on the base branch or in the PR diff),
- cited line numbers fall within the file,
- cited code snippets appear in the file (fuzzy match),
- cited policy sources exist among the indexed documents.

Findings get ``evidence_valid`` and a list of ``evidence_issues``.
"""

from __future__ import annotations

import difflib
import logging
import re
from pathlib import Path

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, GitError, read_file_at_ref

logger = logging.getLogger(__name__)

FUZZY_THRESHOLD = 0.75


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


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


class EvidenceValidator:
    def __init__(
        self,
        repo: str | Path,
        base_ref: str,
        diffs: list[FileDiff] | None = None,
        config: LGTMConfig | None = None,
    ):
        self.repo = Path(repo).resolve()
        self.base_ref = base_ref
        self.config = config or LGTMConfig()
        self._file_cache: dict[str, list[str] | None] = {}
        # Content added by the PR, by file — snippets may legitimately cite it.
        self._diff_added: dict[str, str] = {}
        for fd in diffs or []:
            self._diff_added[fd.path] = _normalize(fd.added_text)

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

    # ------------------------------------------------------------------
    def _validate_code_item(self, item: EvidenceItem) -> list[str]:
        issues: list[str] = []
        if not item.file:
            issues.append("code evidence has no file path")
            return issues
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
                    whole = _normalize("\n".join(lines))
                    found = self._snippet_in_text(item.content, whole)
            if not found and in_diff:
                found = self._snippet_in_text(item.content, self._diff_added[item.file])
            if not found:
                issues.append(
                    f"cited code snippet not found in {item.file}: "
                    f"{item.content[:80]!r}"
                )
        return issues

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
    def validate(self, finding: AgentFinding) -> AgentFinding:
        """Validate one finding in place and return it."""
        issues: list[str] = []
        for item in finding.evidence:
            if item.type == "policy":
                issues.extend(self._validate_policy_item(item))
            else:
                issues.extend(self._validate_code_item(item))

        strong_verdict = finding.verdict in ("vulnerable", "safe")
        if strong_verdict and not finding.evidence:
            issues.append(
                f"verdict '{finding.verdict}' provided without any evidence"
            )

        finding.evidence_issues = issues
        finding.evidence_valid = not issues
        if issues:
            logger.info(
                "Evidence issues for %s: %s", finding.finding_id, "; ".join(issues)
            )
        return finding

    def validate_all(self, findings: list[AgentFinding]) -> list[AgentFinding]:
        return [self.validate(f) for f in findings]
