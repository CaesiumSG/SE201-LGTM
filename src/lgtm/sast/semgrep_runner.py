"""Semgrep CE runner.

Invokes ``semgrep`` via subprocess on the changed files of a PR and parses
the JSON output into structured :class:`SemgrepFinding` objects.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path

from lgtm.diff.git_diff import FileDiff

logger = logging.getLogger(__name__)


class SemgrepError(RuntimeError):
    """Raised when semgrep cannot be executed or returns malformed output."""


@dataclass
class SemgrepFinding:
    rule_id: str
    path: str
    start_line: int
    end_line: int
    message: str
    severity: str
    cwe: list[str] = field(default_factory=list)
    matched_code: str = ""
    confidence: str = ""
    finding_id: str = ""

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = f"{self.rule_id}:{self.path}:{self.start_line}"

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_sqli(self) -> bool:
        """Heuristic: does this finding relate to SQL injection (CWE-89)?"""
        if any(c.upper().startswith("CWE-89") for c in self.cwe):
            return True
        haystack = f"{self.rule_id} {self.message}".lower()
        return "sql" in haystack and ("inject" in haystack or "format" in haystack or "query" in haystack)


def _semgrep_executable() -> list[str]:
    """Locate semgrep: PATH, next to the interpreter, or `-m semgrep`."""
    import shutil
    import sys

    found = shutil.which("semgrep")
    if found:
        return [found]
    sibling = Path(sys.executable).parent / "semgrep"
    if sibling.is_file():
        return [str(sibling)]
    return [sys.executable, "-m", "semgrep"]


def _semgrep_cmd(
    targets: list[str], config: str, repo: str | Path
) -> list[str]:
    return [
        *_semgrep_executable(),
        "scan",
        "--config",
        config,
        "--json",
        "--quiet",
        "--disable-version-check",
        "--metrics",
        "off",
        *targets,
    ]


def run_semgrep(
    repo: str | Path,
    files: list[str],
    config: str = "auto",
    timeout: int = 300,
) -> list[SemgrepFinding]:
    """Run semgrep on specific files within a repo and parse findings.

    ``files`` are paths relative to ``repo``. Files that no longer exist
    (e.g. deleted in the PR) are skipped.
    """
    repo = Path(repo)
    targets = [f for f in files if (repo / f).is_file()]
    if not targets:
        logger.info("No existing files to scan with semgrep")
        return []

    cmd = _semgrep_cmd(targets, config, repo)
    logger.debug("Running semgrep: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(repo),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepError(f"semgrep timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        raise SemgrepError(
            "semgrep executable not found. Install with: pip install semgrep"
        ) from exc

    # Exit codes: 0 = no findings, 1 = findings; anything else is an error,
    # but semgrep may still emit partial JSON with an "errors" array.
    if result.returncode not in (0, 1) and not result.stdout.strip():
        raise SemgrepError(
            f"semgrep failed (exit {result.returncode}): {result.stderr.strip()[:2000]}"
        )

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepError(
            f"Could not parse semgrep JSON output: {result.stdout[:500]!r}"
        ) from exc

    findings = parse_semgrep_json(payload)
    _fill_matched_code(findings, repo)
    return findings


def _fill_matched_code(findings: list[SemgrepFinding], repo: Path) -> None:
    """Populate matched_code from the scanned files.

    Recent semgrep CE versions redact ``extra.lines`` (emitting the literal
    string 'requires login'), so the matched snippet is read from disk.
    """
    cache: dict[str, list[str]] = {}
    for f in findings:
        if f.matched_code and "requires login" not in f.matched_code:
            continue
        if f.path not in cache:
            try:
                cache[f.path] = (
                    (repo / f.path).read_text(encoding="utf-8", errors="replace")
                ).splitlines()
            except OSError:
                cache[f.path] = []
        lines = cache[f.path]
        lo = max(1, f.start_line)
        hi = min(len(lines), max(f.end_line, f.start_line))
        f.matched_code = "\n".join(lines[lo - 1 : hi])


def parse_semgrep_json(payload: dict) -> list[SemgrepFinding]:
    """Convert a semgrep ``--json`` payload into SemgrepFinding objects."""
    findings: list[SemgrepFinding] = []
    for res in payload.get("results", []):
        extra = res.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_raw = metadata.get("cwe", [])
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        cwe = [_normalize_cwe(c) for c in cwe_raw]
        findings.append(
            SemgrepFinding(
                rule_id=res.get("check_id", "unknown"),
                path=res.get("path", "").replace("\\", "/"),
                start_line=res.get("start", {}).get("line", 0),
                end_line=res.get("end", {}).get("line", 0),
                message=extra.get("message", ""),
                severity=extra.get("severity", "INFO"),
                cwe=cwe,
                matched_code=extra.get("lines", ""),
                confidence=metadata.get("confidence", ""),
            )
        )
    errors = payload.get("errors", [])
    if errors:
        logger.warning("semgrep reported %d scan errors (continuing)", len(errors))
    logger.info("semgrep produced %d findings", len(findings))
    return findings


def _normalize_cwe(value: str) -> str:
    """Normalize strings like 'CWE-89: SQL Injection' to 'CWE-89'."""
    value = str(value).strip()
    if ":" in value:
        value = value.split(":", 1)[0].strip()
    return value


def filter_to_diff(
    findings: list[SemgrepFinding], diffs: list[FileDiff], slack: int = 2
) -> list[SemgrepFinding]:
    """Keep only findings that touch lines added/modified by the PR.

    ``slack`` allows a finding to be within N lines of an added line, since
    semgrep ranges and diff hunks don't always align exactly.
    """
    changed: dict[str, set[int]] = {}
    for fd in diffs:
        changed.setdefault(fd.path, set()).update(fd.added_line_numbers)

    kept: list[SemgrepFinding] = []
    for finding in findings:
        lines = changed.get(finding.path)
        if lines is None:
            # Try suffix match (semgrep may report paths relative to cwd)
            for path, lns in changed.items():
                if finding.path.endswith(path) or path.endswith(finding.path):
                    lines = lns
                    break
        if not lines:
            continue
        lo = finding.start_line - slack
        hi = finding.end_line + slack
        if any(lo <= ln <= hi for ln in lines):
            kept.append(finding)
    logger.info(
        "%d/%d semgrep findings overlap the PR diff", len(kept), len(findings)
    )
    return kept
