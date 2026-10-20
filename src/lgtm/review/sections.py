"""Plan review sections from investigator output and render them as unified diffs."""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field, replace
from itertools import count
from typing import Literal, TypeVar

from lgtm.agents.base import extract_json_object
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, LineChange

ChangeKind = Literal["add", "delete", "mixed"]
SnapshotName = Literal["base", "pr"]
SectionOrigin = Literal["investigator", "leftover", "fallback", "coalesced"]
Planner = Literal["investigator", "fallback"]

_T = TypeVar("_T")

_SNAPSHOTS = ("base", "pr")
_SHAPE_ERROR = 'investigator output is not a JSON object with a "sections" list'
_LINE_PREFIX = {"add": "+", "del": "-", "context": " "}


class PlanError(ValueError):
    """Investigator output that cannot be read as a section plan."""


@dataclass
class ContextPointer:
    path: str
    symbol: str
    start_line: int
    end_line: int
    snapshot: SnapshotName
    why: str


@dataclass
class ProposedSection:
    section_id: str
    title: str
    rationale: str
    hunk_refs: list[str]
    context: list[ContextPointer] = field(default_factory=list)


@dataclass
class Exclusion:
    path: str
    reason: str


@dataclass
class HunkRef:
    hunk_id: str
    file: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    change: ChangeKind
    changes: list[LineChange] = field(default_factory=list)


@dataclass
class Section:
    section_id: str
    origin: SectionOrigin
    title: str
    rationale: str = ""
    files: list[str] = field(default_factory=list)
    hunks: list[HunkRef] = field(default_factory=list)
    context: list[ContextPointer] = field(default_factory=list)
    split: bool = False
    partial_hunk: bool = False
    group_id: str | None = None
    part_index: int = 0
    part_count: int = 1


@dataclass
class ScanPlan:
    sections: list[Section] = field(default_factory=list)
    exclusions: list[Exclusion] = field(default_factory=list)
    invalid_refs: list[str] = field(default_factory=list)
    planner: Planner = "fallback"
    fallback_reason: str | None = None
    files_total: int = 0
    files_in_scope: int = 0
    hunks_total: int = 0
    hunks_assigned: int = 0
    hunks_leftover: int = 0
    sections_coalesced: int = 0


@dataclass
class _Run:
    section: Section
    size: int
    headers: dict[str, int]
    rank: int
    prev: _Run | None = None
    next: _Run | None = None
    alive: bool = True


def parse_investigator_output(raw: str) -> list[ProposedSection]:
    data = extract_json_object(raw)
    sections = data.get("sections") if isinstance(data, dict) else None
    if not isinstance(sections, list):
        raise PlanError(_SHAPE_ERROR)
    proposed: list[ProposedSection] = []
    for item in sections:
        section = _parse_section(item)
        if section is not None:
            proposed.append(section)
    return proposed


def _parse_section(item: object) -> ProposedSection | None:
    if not isinstance(item, dict):
        return None
    hunk_refs = item.get("hunks")
    if not isinstance(hunk_refs, list):
        return None
    raw_context = item.get("context")
    context: list[ContextPointer] = []
    if isinstance(raw_context, list):
        for entry in raw_context:
            pointer = _parse_context(entry)
            if pointer is not None:
                context.append(pointer)
    return ProposedSection(
        section_id=_text(item.get("id")).strip(),
        title=_text(item.get("title")),
        rationale=_text(item.get("rationale")),
        hunk_refs=[ref for ref in hunk_refs if isinstance(ref, str)],
        context=context,
    )


def _parse_context(entry: object) -> ContextPointer | None:
    if not isinstance(entry, dict):
        return None
    path = entry.get("path")
    symbol = entry.get("symbol")
    why = entry.get("why")
    start = entry.get("start_line")
    end = entry.get("end_line")
    snapshot = entry.get("snapshot")
    if not (
        isinstance(path, str) and path
        and isinstance(symbol, str)
        and isinstance(why, str)
        and _is_line_number(start)
        and _is_line_number(end)
        and snapshot in _SNAPSHOTS
    ):
        return None
    return ContextPointer(
        path=path,
        symbol=symbol,
        start_line=start,
        end_line=end,
        snapshot=snapshot,
        why=why,
    )


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _is_line_number(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def plan_sections(
    diffs: list[FileDiff], proposed: list[ProposedSection] | None, config: LGTMConfig
) -> ScanPlan:
    in_scope: list[FileDiff] = []
    exclusions: list[Exclusion] = []
    for diff in diffs:
        if not diff.path.endswith(".py"):
            exclusions.append(Exclusion(path=diff.path, reason="non_python"))
        elif not diff.hunks:
            exclusions.append(Exclusion(path=diff.path, reason="no_hunks"))
        else:
            in_scope.append(diff)

    all_refs = [_hunk_ref(diff, i) for diff in in_scope for i in range(len(diff.hunks))]
    index = {ref.hunk_id: ref for ref in all_refs}

    invalid_refs: list[str] = []
    fallback_reason: str | None = None
    investigated: list[Section] = []
    if proposed is None:
        fallback_reason = "no investigator output"
    else:
        investigated, invalid_refs = _resolve_sections(
            proposed, index, config.investigator_max_sections
        )
        if not investigated:
            fallback_reason = "no valid sections"

    planner: Planner
    if investigated:
        planner = "investigator"
        sections = investigated + _leftover_sections(all_refs, investigated)
    else:
        planner = "fallback"
        sections = _fallback_sections(all_refs)

    hunks_assigned = sum(len(s.hunks) for s in sections if s.origin != "leftover")
    hunks_leftover = sum(len(s.hunks) for s in sections if s.origin == "leftover")

    order = {ref.hunk_id: position for position, ref in enumerate(all_refs)}
    sections, coalesced = _split_and_coalesce(sections, config, order)
    _assign_unique_ids(sections)

    return ScanPlan(
        sections=sections,
        exclusions=exclusions,
        invalid_refs=invalid_refs,
        planner=planner,
        fallback_reason=fallback_reason,
        files_total=len(diffs),
        files_in_scope=len(in_scope),
        hunks_total=len(all_refs),
        hunks_assigned=hunks_assigned,
        hunks_leftover=hunks_leftover,
        sections_coalesced=coalesced,
    )


def _hunk_ref(diff: FileDiff, index: int) -> HunkRef:
    hunk = diff.hunks[index]
    return HunkRef(
        hunk_id=f"{diff.path}#{index}",
        file=diff.path,
        old_start=hunk.old_start,
        old_count=hunk.old_count,
        new_start=hunk.new_start,
        new_count=hunk.new_count,
        change=_change_kind(hunk.changes),
        changes=list(hunk.changes),
    )


def _change_kind(changes: list[LineChange]) -> ChangeKind:
    has_add = any(c.kind == "add" for c in changes)
    has_del = any(c.kind == "del" for c in changes)
    if has_add and not has_del:
        return "add"
    if has_del and not has_add:
        return "delete"
    return "mixed"


def _resolve_sections(
    proposed: list[ProposedSection], index: dict[str, HunkRef], max_sections: int
) -> tuple[list[Section], list[str]]:
    claimed: set[str] = set()
    invalid: list[str] = []
    sections: list[Section] = []
    for item in proposed:
        capped = len(sections) >= max_sections
        accepted: list[HunkRef] = []
        for ref in item.hunk_refs:
            if ref not in index or ref in claimed:
                invalid.append(ref)
            elif not capped:
                claimed.add(ref)
                accepted.append(index[ref])
        if accepted:
            sections.append(
                _section(
                    item.section_id or f"s{len(sections) + 1}",
                    "investigator",
                    item.title,
                    item.rationale,
                    accepted,
                    item.context,
                )
            )
    return sections, invalid


def _leftover_sections(
    all_refs: list[HunkRef], investigated: list[Section]
) -> list[Section]:
    placed = {h.hunk_id for s in investigated for h in s.hunks}
    unplaced = [ref for ref in all_refs if ref.hunk_id not in placed]
    return [
        _section(f"leftover:{path}", "leftover", f"Unplaced changes in {path}", "", refs)
        for path, refs in _group_by_file(unplaced).items()
    ]


def _fallback_sections(all_refs: list[HunkRef]) -> list[Section]:
    return [
        _section(f"fallback:{path}", "fallback", path, "", refs)
        for path, refs in _group_by_file(all_refs).items()
    ]


def _split_and_coalesce(
    sections: list[Section], config: LGTMConfig, order: dict[str, int]
) -> tuple[list[Section], int]:
    pieces: list[Section] = []
    for index, section in enumerate(sections):
        group_id = f"{section.section_id}@{index}"
        pieces.extend(_split_section(section, group_id, config.section_max_chars))
    return _coalesce(pieces, config.max_sections, order)


def _split_section(section: Section, group_id: str, limit: int) -> list[Section]:
    if _measure(section.hunks)[0] <= limit:
        return [section]
    groups = _pack_hunks(section.hunks, limit)
    if len(groups) < 2:
        return [section]
    return [
        Section(
            section_id=f"{section.section_id}.{k}",
            origin=section.origin,
            title=section.title,
            rationale=section.rationale,
            files=list(dict.fromkeys(h.file for h in hunks)),
            hunks=hunks,
            context=list(section.context),
            split=True,
            partial_hunk=partial,
            group_id=group_id,
            part_index=k - 1,
            part_count=len(groups),
        )
        for k, (hunks, partial) in enumerate(groups, start=1)
    ]


def _pack_hunks(hunks: list[HunkRef], limit: int) -> list[tuple[list[HunkRef], bool]]:
    groups: list[tuple[list[HunkRef], bool]] = []
    current: list[HunkRef] = []
    size = 0
    files: set[str] = set()
    for hunk in hunks:
        block = _hunk_block_len(hunk, _body_len(hunk.changes))
        header = _header_len(hunk)
        if header + block > limit:
            if current:
                groups.append((current, False))
                current, size, files = [], 0, set()
            groups.extend(([piece], True) for piece in _split_lines(hunk, limit))
            continue
        added = block if hunk.file in files else block + header
        if current and size + added > limit:
            groups.append((current, False))
            current, size, files = [hunk], block + header, {hunk.file}
        else:
            current.append(hunk)
            size += added
            files.add(hunk.file)
    if current:
        groups.append((current, False))
    return groups


def _split_lines(hunk: HunkRef, limit: int) -> list[HunkRef]:
    pieces: list[HunkRef] = []
    current: list[LineChange] = []
    old_done = new_done = 0
    old_count = new_count = body = 0
    for change in hunk.changes:
        old_add = 0 if change.kind == "add" else 1
        new_add = 0 if change.kind == "del" else 1
        line = len(change.content) + 2
        if current and _line_piece_len(
            hunk, old_done, new_done, old_count + old_add, new_count + new_add, body + line
        ) > limit:
            pieces.append(_line_piece(hunk, current, old_done, new_done))
            old_done += old_count
            new_done += new_count
            current = []
            old_count = new_count = body = 0
        current.append(change)
        old_count += old_add
        new_count += new_add
        body += line
    if current:
        pieces.append(_line_piece(hunk, current, old_done, new_done))
    return pieces


def _line_piece(
    hunk: HunkRef, changes: list[LineChange], old_done: int, new_done: int
) -> HunkRef:
    old_count = sum(1 for c in changes if c.kind != "add")
    new_count = sum(1 for c in changes if c.kind != "del")
    return HunkRef(
        hunk_id=hunk.hunk_id,
        file=hunk.file,
        old_start=_piece_start(hunk.old_start, hunk.old_count, old_done, old_count),
        old_count=old_count,
        new_start=_piece_start(hunk.new_start, hunk.new_count, new_done, new_count),
        new_count=new_count,
        change=_change_kind(changes),
        changes=list(changes),
    )


def _line_piece_len(
    hunk: HunkRef, old_done: int, new_done: int, old_count: int, new_count: int, body: int
) -> int:
    probe = replace(
        hunk,
        old_start=_piece_start(hunk.old_start, hunk.old_count, old_done, old_count),
        old_count=old_count,
        new_start=_piece_start(hunk.new_start, hunk.new_count, new_done, new_count),
        new_count=new_count,
    )
    return _header_len(probe) + _hunk_block_len(probe, body)


def _piece_start(start: int, count: int, taken: int, piece_count: int) -> int:
    # Zero-count ranges name the line before the insertion point, as git does.
    base = start if count else start + 1
    return base + taken if piece_count else base + taken - 1


def _coalesce(
    sections: list[Section], max_sections: int, order: dict[str, int]
) -> tuple[list[Section], int]:
    current = list(sections)
    limit = max(max_sections, 1)
    if len(current) > limit:
        current.sort(key=lambda s: min(order[h.hunk_id] for h in s.hunks))
    if len(current) <= limit:
        return current, 0

    runs: list[_Run] = []
    for rank, section in enumerate(current):
        size, headers = _measure(section.hunks)
        runs.append(_Run(section, size, headers, rank))
    heap: list[tuple[int, int, int, _Run, _Run]] = []
    serial = count()

    def push(left: _Run, right: _Run) -> None:
        size = left.size + right.size - _shared_header_total(left.headers, right.headers)
        heapq.heappush(heap, (size, left.rank, next(serial), left, right))

    for left, right in zip(runs, runs[1:]):
        left.next = right
        right.prev = left
        push(left, right)

    head = runs[0]
    live = len(runs)
    merges = 0
    while live > limit:
        size, _, _, left, right = heapq.heappop(heap)
        # Entries for pairs broken by an earlier merge are skipped here.
        if not (left.alive and right.alive and left.next is right):
            continue
        merges += 1
        merged = _Run(
            _merge(left.section, right.section, f"coalesced:{merges}"),
            size,
            _combine_headers(left.headers, right.headers),
            left.rank,
        )
        left.alive = right.alive = False
        merged.prev, merged.next = left.prev, right.next
        if left.prev is None:
            head = merged
        else:
            left.prev.next = merged
            push(left.prev, merged)
        if right.next is not None:
            right.next.prev = merged
            push(merged, right.next)
        live -= 1

    result: list[Section] = []
    run: _Run | None = head
    while run is not None:
        section = run.section
        if section.origin == "coalesced":
            section.files = list(dict.fromkeys(h.file for h in section.hunks))
        result.append(section)
        run = run.next
    return result, merges


def _merge(first: Section, second: Section, section_id: str) -> Section:
    # Sections partition the hunk refs, so concatenation equals the union.
    return Section(
        section_id=section_id,
        origin="coalesced",
        title=f"{first.title} + {second.title}",
        rationale=" ".join(text for text in (first.rationale, second.rationale) if text),
        hunks=first.hunks + second.hunks,
        context=_union(first.context, second.context),
        split=first.split or second.split,
        partial_hunk=first.partial_hunk or second.partial_hunk,
    )


def _shared_header_total(first: dict[str, int], second: dict[str, int]) -> int:
    small, large = (first, second) if len(first) <= len(second) else (second, first)
    return sum(second[f] for f in small if f in large)


def _combine_headers(first: dict[str, int], second: dict[str, int]) -> dict[str, int]:
    if len(first) >= len(second):
        for file, header in second.items():
            first.setdefault(file, header)
        return first
    for file, header in first.items():
        second[file] = header
    return second


def _union(first: list[_T], second: list[_T]) -> list[_T]:
    merged = list(first)
    for item in second:
        if item not in merged:
            merged.append(item)
    return merged


def _measure(hunks: list[HunkRef]) -> tuple[int, dict[str, int]]:
    headers: dict[str, int] = {}
    size = 0
    for hunk in hunks:
        if hunk.file not in headers:
            headers[hunk.file] = _header_len(hunk)
        size += _hunk_block_len(hunk, _body_len(hunk.changes))
    return size + sum(headers.values()), headers


def _body_len(changes: list[LineChange]) -> int:
    return sum(len(c.content) + 2 for c in changes)


def _hunk_block_len(hunk: HunkRef, body: int) -> int:
    return len(_hunk_header(hunk)) + 1 + body


def _header_len(hunk: HunkRef) -> int:
    return sum(len(line) + 1 for line in _file_header(hunk))


def _assign_unique_ids(sections: list[Section]) -> None:
    used: set[str] = set()
    for section in sections:
        base = section.section_id
        candidate = base
        suffix = 2
        while candidate in used:
            candidate = f"{base}-{suffix}"
            suffix += 1
        section.section_id = candidate
        used.add(candidate)


def _section(
    section_id: str,
    origin: SectionOrigin,
    title: str,
    rationale: str,
    hunks: list[HunkRef],
    context: list[ContextPointer] | None = None,
) -> Section:
    return Section(
        section_id=section_id,
        origin=origin,
        title=title,
        rationale=rationale,
        files=list(dict.fromkeys(h.file for h in hunks)),
        hunks=list(hunks),
        context=list(context or []),
    )


def _group_by_file(refs: list[HunkRef]) -> dict[str, list[HunkRef]]:
    groups: dict[str, list[HunkRef]] = {}
    for ref in refs:
        groups.setdefault(ref.file, []).append(ref)
    return groups


def render_section(section: Section) -> str:
    lines: list[str] = []
    for hunks in _group_by_file(section.hunks).values():
        lines.extend(_file_header(hunks[0]))
        for hunk in hunks:
            lines.append(_hunk_header(hunk))
            lines.extend(_LINE_PREFIX[c.kind] + c.content for c in hunk.changes)
    return "".join(line + "\n" for line in lines)


def _hunk_header(hunk: HunkRef) -> str:
    return f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@"


def _file_header(hunk: HunkRef) -> list[str]:
    # Git writes a zero start and zero count for the side a file does not have.
    old_side = "/dev/null" if hunk.old_start == 0 and hunk.old_count == 0 else f"a/{hunk.file}"
    new_side = "/dev/null" if hunk.new_start == 0 and hunk.new_count == 0 else f"b/{hunk.file}"
    return [f"--- {old_side}", f"+++ {new_side}"]
