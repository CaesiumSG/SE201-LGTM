"""Coverage report for a scan plan and the per-section review results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from lgtm.review.sections import HunkRef, ScanPlan, Section

Side = Literal["new", "old"]
SectionStatus = Literal["completed", "failed"]
InvestigatorStatus = Literal["ok", "failed", "skipped"]
InvestigatorInput = Literal["full", "manifest_only", "none"]


@dataclass
class SectionResult:
    status: SectionStatus
    supported: list[bool | None]
    finding_ids: list[str]
    error: str | None


def build_coverage(
    plan: ScanPlan,
    *,
    investigator_status: InvestigatorStatus,
    investigator_error: str | None,
    investigator_input: InvestigatorInput,
    investigator_tool_calls: int,
    results: Mapping[str, SectionResult],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    reviewed: set[str] = set()
    completed = 0
    failed = 0
    for section in plan.sections:
        result = results.get(section.section_id)
        if result is not None and result.status == "completed":
            completed += 1
            reviewed.update(h.hunk_id for h in section.hunks)
        elif result is not None:
            failed += 1
        rows.append(_section_row(section, result))

    scheduled = len(plan.sections)
    return {
        "planner": plan.planner,
        "investigator_status": investigator_status,
        "investigator_error": investigator_error,
        "investigator_input": investigator_input,
        "investigator_tool_calls": investigator_tool_calls,
        "files_total": plan.files_total,
        "files_in_scope": plan.files_in_scope,
        "hunks_total": plan.hunks_total,
        "hunks_assigned": plan.hunks_assigned,
        "hunks_leftover": plan.hunks_leftover,
        "hunks_reviewed": len(reviewed),
        "sections_scheduled": scheduled,
        "sections_completed": completed,
        "sections_failed": failed,
        "sections_coalesced": plan.sections_coalesced,
        "complete": failed == 0 and completed == scheduled and len(reviewed) == plan.hunks_total,
        "exclusions": [{"path": e.path, "reason": e.reason} for e in plan.exclusions],
        "invalid_refs": list(plan.invalid_refs),
        "sections": rows,
    }


def hunks_overlap(a: HunkRef, b: HunkRef, side: Side) -> bool:
    return _ranges_overlap(_side_span(a, side), _side_span(b, side))


def location_overlaps(hunk: Mapping[str, Any], location: Mapping[str, Any]) -> bool:
    if hunk["file"] != location["file"]:
        return False
    sided = [
        (side, location[f"{side}_range"])
        for side in ("old", "new")
        if location.get(f"{side}_range") is not None
    ]
    if not sided:
        return True
    return any(
        _ranges_overlap(_span(hunk[f"{side}_start"], hunk[f"{side}_count"]), bounds)
        for side, bounds in sided
    )


def _side_span(hunk: HunkRef, side: Side) -> tuple[int, int]:
    if side == "old":
        return _span(hunk.old_start, hunk.old_count)
    return _span(hunk.new_start, hunk.new_count)


def _span(start: int, count: int) -> tuple[int, int]:
    return start, start + max(count, 1) - 1


def _ranges_overlap(first: tuple[int, int], second: Sequence[int]) -> bool:
    return first[0] <= second[1] and second[0] <= first[1]


def _section_row(section: Section, result: SectionResult | None) -> dict[str, Any]:
    status, supported, finding_ids, error = (
        (None, [], [], None)
        if result is None
        else (result.status, list(result.supported), list(result.finding_ids), result.error)
    )
    return {
        "section_id": section.section_id,
        "origin": section.origin,
        "title": section.title,
        "files": list(section.files),
        "split": section.split,
        "partial_hunk": section.partial_hunk,
        "hunks": [_hunk_row(h) for h in section.hunks],
        "status": status,
        "supported": supported,
        "finding_ids": finding_ids,
        "error": error,
    }


def _hunk_row(hunk: HunkRef) -> dict[str, Any]:
    return {
        "hunk_id": hunk.hunk_id,
        "file": hunk.file,
        "old_start": hunk.old_start,
        "old_count": hunk.old_count,
        "new_start": hunk.new_start,
        "new_count": hunk.new_count,
        "change": hunk.change,
    }
