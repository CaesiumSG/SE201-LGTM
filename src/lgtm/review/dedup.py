"""Deterministic merge of findings that cite the same file, CWE and overlapping lines."""

from __future__ import annotations

from collections.abc import Iterable

from lgtm.agents.base import AgentFinding, EvidenceItem

_VERDICT_RANK = {"vulnerable": 3, "possible": 2, "insufficient_evidence": 1}

_Span = tuple[str, int, int]


def dedup_findings(findings: Iterable[AgentFinding]) -> list[AgentFinding]:
    items = list(findings)
    spans = [_spans(f) if _mergeable(f) else [] for f in items]

    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(items)):
        if not spans[i]:
            continue
        for j in range(i + 1, len(items)):
            if not spans[j] or not _same_group(items[i], items[j]):
                continue
            if _overlaps(spans[i], spans[j]):
                root_i, root_j = find(i), find(j)
                if root_i != root_j:
                    # The smallest index stays root so each group sits at its first occurrence.
                    parent[max(root_i, root_j)] = min(root_i, root_j)

    groups: dict[int, list[AgentFinding]] = {}
    for idx, finding in enumerate(items):
        groups.setdefault(find(idx), []).append(finding)

    return [_merge(groups[idx]) for idx in range(len(items)) if find(idx) == idx]


def _mergeable(finding: AgentFinding) -> bool:
    return finding.verdict != "safe" and bool(finding.file) and bool(finding.cwe_id)


def _same_group(left: AgentFinding, right: AgentFinding) -> bool:
    return left.file == right.file and left.cwe_id == right.cwe_id


def _spans(finding: AgentFinding) -> list[_Span]:
    spans: list[_Span] = [("new", finding.line, finding.line)] if finding.line > 0 else []
    for item in finding.evidence:
        bounds = _line_bounds(item)
        if bounds is not None:
            side = "old" if item.snapshot == "base" else "new"
            spans.append((side, *bounds))
    return spans


def _line_bounds(item: EvidenceItem) -> tuple[int, int] | None:
    if not item.lines:
        return None
    bounds = item.lines[:2]
    return min(bounds), max(bounds)


def _overlaps(left: list[_Span], right: list[_Span]) -> bool:
    return any(
        l_side == r_side and l_start <= r_end and r_start <= l_end
        for l_side, l_start, l_end in left
        for r_side, r_start, r_end in right
    )


def _evidence_key(item: EvidenceItem) -> tuple:
    lines = tuple(item.lines) if item.lines is not None else None
    return (item.type, item.file, lines, item.source, item.content)


def _merge(group: list[AgentFinding]) -> AgentFinding:
    if len(group) == 1:
        return group[0]

    first = group[0]
    evidence: list[EvidenceItem] = []
    seen: set[tuple] = set()
    for finding in group:
        for item in finding.evidence:
            key = _evidence_key(item)
            if key not in seen:
                seen.add(key)
                evidence.append(item)

    return first.model_copy(
        update={
            "verdict": max(
                (f.verdict for f in group), key=lambda v: _VERDICT_RANK.get(v, 0)
            ),
            "confidence": max(f.confidence for f in group),
            "explanation": max((f.explanation for f in group), key=len),
            "suggested_fix": max((f.suggested_fix for f in group), key=len),
            "evidence": evidence,
        }
    )
