"""Sanitization and prompt-injection detection for PR diffs.

Mitigations against prompt injection:
1. strip_comments_from_diff: Strips single-line comments, inline comments,
   and multiline docstrings from PR-added code before it is passed to LLM agents.
   Deterministic SAST (Semgrep) still inspects the original raw code.
2. detect_prompt_injections: A fast heuristic scanner that identifies
   reviewer-directed instructions, fake verdicts, and override directives
   embedded within added diff lines, producing an adversarial injection finding.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Sequence

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.diff.git_diff import FileDiff, Hunk, LineChange

logger = logging.getLogger(__name__)

# Patterns indicative of prompt injection attempts aimed at security reviewers
REVIEWER_DIRECTIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bmark\s+(as\s+)?safe\b", re.IGNORECASE),
    re.compile(r"\bverdict\s*:\s*['\"]?safe['\"]?", re.IGNORECASE),
    re.compile(r"\boverride\s+(verdict|instruction)\b", re.IGNORECASE),
    re.compile(r"\[lgtm-(override|rule|skip)\]", re.IGNORECASE),
    re.compile(r"\bcritical\s+instruction\s+for\s+(llm|reviewer|security)\b", re.IGNORECASE),
    re.compile(r"\b(ignore|disregard)\s+previous\s+(instructions|constraints|rules)\b", re.IGNORECASE),
    re.compile(r"\[system\s+instruction\]", re.IGNORECASE),
    re.compile(r"</?diff>", re.IGNORECASE),
    re.compile(r"\b(security|policy)\s+exemption\b", re.IGNORECASE),
    re.compile(r'\{["\']verdict["\']\s*:\s*["\']safe["\']', re.IGNORECASE),
    re.compile(r'\{["\']finding_id["\']\s*:', re.IGNORECASE),
]


def strip_inline_comment(line: str) -> str:
    """Strip trailing # comment from a line of Python code, preserving strings."""
    in_single = False
    in_double = False
    escape = False
    for i, ch in enumerate(line):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line


def sanitize_file_diff(fd: FileDiff) -> FileDiff:
    """Return a sanitized copy of FileDiff with comments and docstrings stripped from added lines."""
    sanitized = copy.deepcopy(fd)
    if not fd.path.endswith(".py"):
        return sanitized

    for hunk in sanitized.hunks:
        new_changes: list[LineChange] = []
        in_triple_double = False
        in_triple_single = False

        for change in hunk.changes:
            if change.kind != "add":
                new_changes.append(change)
                continue

            raw = change.content
            stripped = raw.strip()

            # Handle multiline docstrings
            if not in_triple_double and not in_triple_single:
                if '"""' in stripped:
                    # Check if opens and closes on same line
                    first = stripped.find('"""')
                    second = stripped.find('"""', first + 3)
                    if second != -1:
                        # Single-line triple quote, remove or blank
                        new_content = raw[:raw.find('"""')] + raw[raw.find('"""') + len(stripped):]
                        change.content = new_content
                        new_changes.append(change)
                        continue
                    else:
                        in_triple_double = True
                        continue
                elif "'''" in stripped:
                    first = stripped.find("'''")
                    second = stripped.find("'''", first + 3)
                    if second != -1:
                        new_content = raw[:raw.find("'''")] + raw[raw.find("'''") + len(stripped):]
                        change.content = new_content
                        new_changes.append(change)
                        continue
                    else:
                        in_triple_single = True
                        continue
            else:
                if in_triple_double and '"""' in stripped:
                    in_triple_double = False
                    continue
                elif in_triple_single and "'''" in stripped:
                    in_triple_single = False
                    continue
                # Inside docstring -> omit line
                continue

            # Strip whole-line comment
            if stripped.startswith("#"):
                continue

            # Strip inline comment
            code_only = strip_inline_comment(raw)
            change.content = code_only
            new_changes.append(change)

        hunk.changes = new_changes

    return sanitized


def sanitize_diffs(diffs: Sequence[FileDiff]) -> list[FileDiff]:
    """Sanitize all diffs for LLM ingestion."""
    return [sanitize_file_diff(d) for d in diffs]


def detect_prompt_injections(diffs: Sequence[FileDiff]) -> list[AgentFinding]:
    """Scan PR diffs for adversarial instructions directing the security reviewer.

    Flags reviewer-directed instructions as findings so prompt injection attempts
    are surfaced and flagged as security flaws.
    """
    findings: list[AgentFinding] = []
    seen: set[str] = set()

    for fd in diffs:
        for hunk in fd.hunks:
            for change in hunk.changes:
                if change.kind != "add":
                    continue
                line_text = change.content
                for pat in REVIEWER_DIRECTIVE_PATTERNS:
                    match = pat.search(line_text)
                    if match:
                        lineno = change.new_lineno or hunk.new_start
                        dedup_key = f"{fd.path}:{lineno}:{match.group(0).lower()}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        finding_id = f"injection:{fd.path}:{lineno}"
                        matched_str = match.group(0)
                        findings.append(
                            AgentFinding(
                                finding_id=finding_id,
                                cwe_id="CWE-862",  # Authorization bypass / review subversion
                                explanation=(
                                    f"Potential prompt injection detected: added line contains "
                                    f"reviewer-directed instruction ({matched_str!r}) attempting "
                                    f"to influence automated security review."
                                ),
                                evidence=[
                                    EvidenceItem(
                                        type="code",
                                        file=fd.path,
                                        lines=[lineno, lineno],
                                        content=line_text.strip(),
                                    )
                                ],
                                suggested_fix="Remove reviewer-directed instructions and meta-prompts from source code.",
                                category="",  # Uncategorized so it impacts overall case verdict
                                agent="injection_detector",
                                file=fd.path,
                                line=lineno,
                                evidence_valid=True,
                                verdict="vulnerable",
                            )
                        )
                        break

    return findings
