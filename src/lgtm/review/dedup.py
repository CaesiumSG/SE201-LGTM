"""Deterministic merge of findings that cite the same file, CWE and overlapping lines."""

from __future__ import annotations

from collections.abc import Iterable

from lgtm.agents.base import AgentFinding, EvidenceItem

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
            if (
                not spans[j]
                or items[i].file != items[j].file
                or items[i].cwe_id != items[j].cwe_id
            ):
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


def _spans(finding: AgentFinding) -> list[_Span]:
    spans: list[_Span] = [("new", finding.line, finding.line)] if finding.line > 0 else []
    for item in finding.evidence:
        if item.file and item.file != finding.file:
            continue
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


def _merged_pr_graph_ok(group: list[AgentFinding]) -> bool | None:
    # False takes precedence so the PR-grounding cap applies to the merged finding in any member order.
    stamps = [f.pr_graph_ok for f in group]
    if False in stamps:
        return False
    if True in stamps:
        return True
    return None


def _merge(group: list[AgentFinding]) -> AgentFinding:
    if len(group) == 1:
        return group[0]

    evidence: list[EvidenceItem] = []
    seen: set[tuple] = set()
    for finding in group:
        for item in finding.evidence:
            key = _evidence_key(item)
            if key not in seen:
                seen.add(key)
                evidence.append(item)

    return group[0].model_copy(
        update={
            "pr_graph_ok": _merged_pr_graph_ok(group),
            "evidence": evidence,
        }
    )
