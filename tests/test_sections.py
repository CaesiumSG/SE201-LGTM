"""Tests for investigator output parsing, section planning and rendering."""

from __future__ import annotations

import json
import re
import time

import pytest

from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, parse_unified_diff
from lgtm.review.sections import (
    PlanError,
    parse_investigator_output,
    plan_sections,
    render_section,
)


def file_diff_text(path, hunks, status="modified"):
    """Render one file as git diff text; hunks are (old_start, new_start, lines)."""
    out = [f"diff --git a/{path} b/{path}"]
    if status == "deleted":
        out += ["deleted file mode 100644", f"--- a/{path}", "+++ /dev/null"]
    else:
        out += [f"--- a/{path}", f"+++ b/{path}"]
    for old_start, new_start, lines in hunks:
        old_count = sum(1 for line in lines if line[0] in " -")
        new_count = sum(1 for line in lines if line[0] in " +")
        out.append(f"@@ -{old_start},{old_count} +{new_start},{new_count} @@")
        out.extend(lines)
    return "\n".join(out) + "\n"


def parse(*texts: str) -> list[FileDiff]:
    return parse_unified_diff("".join(texts))


def section(sid, hunks, title=None, rationale="", context=None):
    return {
        "id": sid,
        "title": title if title is not None else f"title {sid}",
        "rationale": rationale,
        "hunks": hunks,
        "context": context or [],
    }


def proposal(*sections) -> str:
    return json.dumps({"sections": list(sections)})


def plan(diffs, raw, **cfg):
    proposed = None if raw is None else parse_investigator_output(raw)
    return plan_sections(diffs, proposed, LGTMConfig(**cfg))


def hunk_ids(p) -> list[str]:
    return [h.hunk_id for s in p.sections for h in s.hunks]


def by_id(p, section_id):
    return next(s for s in p.sections if s.section_id == section_id)


def field(obj, name):
    return obj[name] if isinstance(obj, dict) else getattr(obj, name)


MIXED = [" ctx_before", "-old_value", "+new_value", " ctx_after"]
ADDS = ["+added_one", "+added_two"]
DELS = ["-removed_one", "-removed_two", "-removed_three"]

MAIN_DIFF = (
    file_diff_text("app/a.py", [(10, 10, MIXED), (40, 41, ADDS)])
    + file_diff_text("app/b.py", [(5, 5, MIXED)])
    + file_diff_text("notes.md", [(1, 1, MIXED)])
    + file_diff_text("old/c.py", [(1, 0, DELS)], status="deleted")
    + "diff --git a/app/e.py b/app/e.py\nold mode 100644\nnew mode 100755\n"
    + file_diff_text("app/d.py", [(7, 7, DELS)])
)

ALL_MAIN_HUNKS = ["app/a.py#0", "app/a.py#1", "app/b.py#0", "old/c.py#0", "app/d.py#0"]


@pytest.fixture
def main_diffs():
    return parse_unified_diff(MAIN_DIFF)


def equal_files(n, lines=("+same_length_line",)):
    return parse(
        *(file_diff_text(f"pkg/f{i}.py", [(10, 10, list(lines))]) for i in range(1, n + 1))
    )


def sized_files(sizes):
    return parse(
        *(
            file_diff_text(f"pkg/f{i}.py", [(10, 10, [f"+row_{i}_{j}" for j in range(n)])])
            for i, n in enumerate(sizes, start=1)
        )
    )


def titled(n):
    return [
        section(f"s{i}", [f"pkg/f{i}.py#0"], title=f"T{i}", rationale=f"R{i}.")
        for i in range(1, n + 1)
    ]


def test_parse_accepts_fenced_json_with_surrounding_prose():
    raw = "Here is the plan:\n```json\n" + proposal(section("s1", ["app/a.py#0"])) + "\n```\nDone."
    assert len(parse_investigator_output(raw)) == 1


@pytest.mark.parametrize(
    "raw",
    ["no json at all", '{"other": 1}', '{"sections": "nope"}', ""],
)
def test_parse_unparsable_output_raises_plan_error(raw):
    message = 'investigator output is not a JSON object with a "sections" list'
    with pytest.raises(PlanError, match=re.escape(message)):
        parse_investigator_output(raw)


def test_plan_error_is_a_value_error():
    assert issubclass(PlanError, ValueError)


def test_parse_empty_sections_list_is_valid_and_empty():
    assert parse_investigator_output('{"sections": []}') == []


def test_parse_drops_malformed_sections_and_context_entries(main_diffs):
    good_ctx = {"path": "app/x.py", "symbol": "f", "start_line": 3, "end_line": 9,
                "snapshot": "pr", "why": "callee"}
    bad_ctxs = [
        {"symbol": "f", "start_line": 1, "end_line": 2, "snapshot": "pr", "why": "w"},
        {"path": "app/x.py", "symbol": "f", "start_line": 1, "end_line": 2,
         "snapshot": "head", "why": "w"},
        {"path": "app/x.py", "symbol": "f", "start_line": "abc", "end_line": 2,
         "snapshot": "pr", "why": "w"},
        "not an object",
    ]
    raw = proposal(
        section("s1", ["app/a.py#0"], context=[good_ctx, *bad_ctxs]),
        "not an object",
        {"id": "s2", "title": "no hunks key"},
        {"id": "s3", "title": "bad hunks", "hunks": "app/b.py#0"},
    )
    parsed = parse_investigator_output(raw)
    assert len(parsed) == 1
    p = plan_sections(main_diffs, parsed, LGTMConfig())
    s1 = by_id(p, "s1")
    assert len(s1.context) == 1
    ctx = s1.context[0]
    assert (ctx.path, ctx.symbol, ctx.start_line, ctx.end_line, ctx.snapshot, ctx.why) == (
        "app/x.py", "f", 3, 9, "pr", "callee",
    )


def test_investigator_section_resolves_ids_with_coordinates_from_diff(main_diffs):
    raw = proposal(section("authz", ["app/a.py#1", "app/a.py#0"], title="Auth change",
                           rationale="why it matters"))
    p = plan(main_diffs, raw)
    s = by_id(p, "authz")
    assert p.planner == "investigator"
    assert not p.fallback_reason
    assert s.origin == "investigator"
    assert s.title == "Auth change"
    assert s.rationale == "why it matters"
    assert s.files == ["app/a.py"]
    assert [h.hunk_id for h in s.hunks] == ["app/a.py#1", "app/a.py#0"]
    first, second = s.hunks
    assert (first.file, first.old_start, first.old_count, first.new_start, first.new_count) == (
        "app/a.py", 40, 0, 41, 2,
    )
    assert first.change == "add"
    assert (second.old_start, second.old_count, second.new_start, second.new_count) == (
        10, 3, 10, 3,
    )
    assert second.change == "mixed"
    assert not s.split and not s.partial_hunk


def test_deleted_file_uses_old_path_and_deletion_only_hunks_are_in_scope(main_diffs):
    p = plan(main_diffs, proposal(section("dels", ["old/c.py#0", "app/d.py#0"])))
    s = by_id(p, "dels")
    assert s.files == ["old/c.py", "app/d.py"]
    deleted_file_hunk, deletion_only_hunk = s.hunks
    assert deleted_file_hunk.hunk_id == "old/c.py#0"
    assert (deleted_file_hunk.old_start, deleted_file_hunk.old_count,
            deleted_file_hunk.new_count) == (1, 3, 0)
    assert deleted_file_hunk.change == "delete"
    assert deletion_only_hunk.change == "delete"
    text = render_section(s)
    assert "old/c.py" in text and "app/d.py" in text
    assert "-removed_two" in text


def test_render_deleted_file_header_has_dev_null_on_the_new_side():
    diffs = parse(file_diff_text("old/c.py", [(1, 0, DELS)], status="deleted"))
    text = render_section(plan(diffs, None).sections[0])
    assert text == (
        "--- a/old/c.py\n+++ /dev/null\n@@ -1,3 +0,0 @@\n"
        "-removed_one\n-removed_two\n-removed_three\n"
    )


def test_render_added_file_header_has_dev_null_on_the_old_side():
    added = (
        "diff --git a/new/e.py b/new/e.py\nnew file mode 100644\n"
        "--- /dev/null\n+++ b/new/e.py\n@@ -0,0 +1,2 @@\n+first\n+second\n"
    )
    text = render_section(plan(parse(added), None).sections[0])
    assert text == "--- /dev/null\n+++ b/new/e.py\n@@ -0,0 +1,2 @@\n+first\n+second\n"


def test_plan_counters_for_partially_assigned_diff(main_diffs):
    p = plan(main_diffs, proposal(section("s1", ["app/a.py#0", "app/b.py#0"])))
    assert p.files_total == 6
    assert p.files_in_scope == 4
    assert p.hunks_total == 5
    assert p.hunks_assigned == 2
    assert p.hunks_leftover == 3
    assert p.sections_coalesced == 0


def test_non_python_and_hunkless_python_files_are_excluded_with_reasons(main_diffs):
    p = plan(main_diffs, proposal(section("s1", ["app/a.py#0"])))
    got = {(field(e, "path"), field(e, "reason")) for e in p.exclusions}
    assert got == {("notes.md", "non_python"), ("app/e.py", "no_hunks")}
    assert not any(h.startswith(("notes.md", "app/e.py")) for h in hunk_ids(p))


def test_unknown_duplicate_and_out_of_scope_ids_go_to_invalid_refs(main_diffs):
    raw = proposal(
        section("first", ["app/a.py#0", "missing.py#0", "app/a.py#9", "notes.md#0"]),
        section("second", ["app/a.py#0", "app/b.py#0"]),
    )
    p = plan(main_diffs, raw)
    assert p.invalid_refs == ["missing.py#0", "app/a.py#9", "notes.md#0", "app/a.py#0"]
    assert [h.hunk_id for h in by_id(p, "first").hunks] == ["app/a.py#0"]
    assert [h.hunk_id for h in by_id(p, "second").hunks] == ["app/b.py#0"]
    assert hunk_ids(p).count("app/a.py#0") == 1


def test_hunk_repeated_within_one_section_is_planned_once_and_reported_once():
    p = plan(equal_files(1), proposal(section("s1", ["pkg/f1.py#0", "pkg/f1.py#0"])))
    assert p.invalid_refs == ["pkg/f1.py#0"]
    assert hunk_ids(p) == ["pkg/f1.py#0"]


def test_sections_without_valid_hunks_are_dropped(main_diffs):
    raw = proposal(
        section("empty", [], title="nothing here"),
        section("bogus", ["missing.py#3"], title="only invalid"),
        section("real", ["app/b.py#0"]),
    )
    p = plan(main_diffs, raw)
    assert not any(s.title in ("nothing here", "only invalid") for s in p.sections)
    assert by_id(p, "real").hunks[0].hunk_id == "app/b.py#0"
    assert p.invalid_refs == ["missing.py#3"]


def test_duplicate_section_ids_get_numeric_suffixes():
    raw = proposal(
        section("x", ["pkg/f1.py#0"]),
        section("x", ["pkg/f2.py#0"]),
        section("x", ["pkg/f3.py#0"]),
    )
    p = plan(equal_files(3), raw)
    assert [s.section_id for s in p.sections] == ["x", "x-2", "x-3"]


def test_empty_section_id_becomes_s_number():
    p = plan(equal_files(1), proposal(section("", ["pkg/f1.py#0"])))
    assert len(p.sections) == 1
    assert re.fullmatch(r"s\d+", p.sections[0].section_id)


def test_empty_section_ids_stay_unique():
    raw = proposal(section("", ["pkg/f1.py#0"]), section("", ["pkg/f2.py#0"]))
    p = plan(equal_files(2), raw)
    assert len({s.section_id for s in p.sections}) == 2
    assert all(s.section_id for s in p.sections)


def test_section_id_equal_to_a_generated_suffix_stays_unique():
    raw = proposal(
        section("x", ["pkg/f1.py#0"]),
        section("x", ["pkg/f2.py#0"]),
        section("x-2", ["pkg/f3.py#0"]),
    )
    p = plan(equal_files(3), raw)
    ids = [s.section_id for s in p.sections]
    assert len(set(ids)) == 3
    assert ids[0] == "x"


def test_sections_beyond_investigator_max_send_hunks_to_leftover():
    raw = proposal(
        section("keep", ["pkg/f1.py#0"], title="kept"),
        section("over", ["pkg/f2.py#0"], title="over the cap"),
    )
    p = plan(equal_files(3), raw, investigator_max_sections=1)
    assert by_id(p, "keep").hunks[0].hunk_id == "pkg/f1.py#0"
    assert not any(s.title == "over the cap" for s in p.sections)
    assert by_id(p, "leftover:pkg/f2.py").hunks[0].hunk_id == "pkg/f2.py#0"
    assert sorted(hunk_ids(p)) == ["pkg/f1.py#0", "pkg/f2.py#0", "pkg/f3.py#0"]


def test_unassigned_hunks_form_one_leftover_section_per_file_in_diff_order(main_diffs):
    p = plan(main_diffs, proposal(section("s1", ["app/a.py#0", "app/b.py#0"])))
    leftovers = [s for s in p.sections if s.origin == "leftover"]
    assert [s.section_id for s in leftovers] == [
        "leftover:app/a.py", "leftover:old/c.py", "leftover:app/d.py",
    ]
    assert [h.hunk_id for h in leftovers[0].hunks] == ["app/a.py#1"]
    assert leftovers[1].hunks[0].change == "delete"
    assert sorted(hunk_ids(p)) == sorted(ALL_MAIN_HUNKS)


def test_multiple_leftover_hunks_of_one_file_share_one_section(main_diffs):
    p = plan(main_diffs, proposal(section("s1", ["app/b.py#0"])))
    leftover = by_id(p, "leftover:app/a.py")
    assert [h.hunk_id for h in leftover.hunks] == ["app/a.py#0", "app/a.py#1"]
    assert leftover.files == ["app/a.py"]


def test_every_in_scope_hunk_is_planned_exactly_once(main_diffs):
    p = plan(main_diffs, proposal(section("s1", ["app/d.py#0"])))
    assert sorted(hunk_ids(p)) == sorted(ALL_MAIN_HUNKS)


def test_no_investigator_output_uses_one_fallback_section_per_python_file(main_diffs):
    p = plan(main_diffs, None)
    assert p.planner == "fallback"
    assert [s.section_id for s in p.sections] == [
        "fallback:app/a.py", "fallback:app/b.py", "fallback:old/c.py", "fallback:app/d.py",
    ]
    assert all(s.origin == "fallback" for s in p.sections)
    assert [h.hunk_id for h in p.sections[0].hunks] == ["app/a.py#0", "app/a.py#1"]
    assert p.files_in_scope == 4 and p.hunks_total == 5


@pytest.mark.parametrize(
    "raw",
    [
        '{"sections": []}',
        proposal(section("bad", ["missing.py#0"])),
        proposal("junk", {"id": "x"}),
    ],
)
def test_zero_valid_sections_fall_back_with_reason(main_diffs, raw):
    p = plan(main_diffs, raw)
    assert p.planner == "fallback"
    assert p.fallback_reason == "no valid sections"
    assert p.sections[0].section_id == "fallback:app/a.py"
    assert sorted(hunk_ids(p)) == sorted(ALL_MAIN_HUNKS)


def test_fallback_applies_split_and_coalesce_steps():
    lines = [f"+payload_line_{i:02d}" for i in range(30)]
    diffs = parse(
        file_diff_text("pkg/a.py", [(1, 1, lines)]),
        file_diff_text("pkg/b.py", [(1, 1, ["+small"])]),
        file_diff_text("pkg/c.py", [(1, 1, ["+small"])]),
    )
    full = plan(diffs, None)
    big = len(render_section(by_id(full, "fallback:pkg/a.py")))
    limit = big // 2
    uncapped = plan(diffs, None, section_max_chars=limit, max_sections=100)
    p = plan(diffs, None, section_max_chars=limit, max_sections=3)
    assert len(uncapped.sections) > 3
    assert len(p.sections) == 3
    assert p.sections_coalesced == len(uncapped.sections) - 3
    rendered = "".join(render_section(s) for s in p.sections)
    assert all(line in rendered for line in lines)


def three_equal_hunks_file():
    return parse(
        file_diff_text(
            "pkg/big.py",
            [
                (10 * n, 10 * n, [f"+equal_size_line_{n}", f"+equal_size_more_{n}"])
                for n in (1, 2, 3)
            ],
        )
    )


def test_oversized_section_splits_at_hunk_boundaries_with_shared_group():
    diffs = three_equal_hunks_file()
    singles = plan(diffs, proposal(*(section(f"h{i}", [f"pkg/big.py#{i}"]) for i in range(3))))
    limit = max(len(render_section(s)) for s in singles.sections)
    raw = proposal(section("big", [f"pkg/big.py#{i}" for i in range(3)]))
    p = plan(diffs, raw, section_max_chars=limit)
    pieces = p.sections
    assert len(pieces) == 3
    assert all(s.section_id.startswith("big.") for s in pieces)
    assert len({s.section_id for s in pieces}) == 3
    assert all(s.split and not s.partial_hunk for s in pieces)
    assert pieces[0].group_id and len({s.group_id for s in pieces}) == 1
    assert all(s.part_count == 3 for s in pieces)
    assert len({s.part_index for s in pieces}) == 3
    assert all(len(render_section(s)) <= limit for s in pieces)
    assert hunk_ids(p) == [f"pkg/big.py#{i}" for i in range(3)]
    assert all(s.files == ["pkg/big.py"] for s in pieces)


def test_section_within_limit_is_not_split():
    raw = proposal(section("big", [f"pkg/big.py#{i}" for i in range(3)]))
    p = plan(three_equal_hunks_file(), raw)
    assert [s.section_id for s in p.sections] == ["big"]
    assert not p.sections[0].split and not p.sections[0].group_id


def test_single_oversized_hunk_splits_at_lines_with_recomputed_coordinates():
    lines = [f"+only_line_{i:02d}" for i in range(40)]
    diffs = parse(file_diff_text("pkg/long.py", [(5, 6, lines)]))
    raw = proposal(section("long", ["pkg/long.py#0"]))
    limit = len(render_section(plan(diffs, raw).sections[0])) // 3
    p = plan(diffs, raw, section_max_chars=limit)
    pieces = p.sections
    assert len(pieces) >= 3
    assert all(s.split and s.partial_hunk for s in pieces)
    assert len({s.group_id for s in pieces}) == 1
    assert all(len(render_section(s)) <= limit for s in pieces)
    refs = [h for s in pieces for h in s.hunks]
    assert all(h.file == "pkg/long.py" and h.hunk_id == "pkg/long.py#0" for h in refs)
    assert refs[0].new_start == 6
    for prev, nxt in zip(refs, refs[1:]):
        assert nxt.new_start == prev.new_start + prev.new_count
    assert sum(h.new_count for h in refs) == 40
    assert sum(h.old_count for h in refs) == 0
    assert all(h.old_start == 5 for h in refs)
    text = "\n".join(render_section(s) for s in pieces)
    for line in lines:
        assert text.count(line) == 1


def line_pieces(old_start, new_start, lines, per_piece):
    diffs = parse(file_diff_text("pkg/long.py", [(old_start, new_start, lines)]))
    probe = parse(file_diff_text("pkg/long.py", [(old_start, new_start, lines[:per_piece])]))
    limit = len(render_section(plan(probe, None).sections[0]))
    p = plan(diffs, proposal(section("long", ["pkg/long.py#0"])), section_max_chars=limit)
    return p.sections


def piece_coordinates(pieces):
    return [
        (h.old_start, h.old_count, h.new_start, h.new_count) for s in pieces for h in s.hunks
    ]


def assert_rendered_headers_match(pieces):
    for s in pieces:
        (h,) = s.hunks
        header = f"@@ -{h.old_start},{h.old_count} +{h.new_start},{h.new_count} @@"
        assert header in render_section(s).splitlines()


def test_deletion_only_hunk_splits_with_old_ranges_advancing_and_new_side_fixed():
    lines = [f"-del_{i}" for i in range(6)]
    pieces = line_pieces(10, 9, lines, per_piece=2)
    assert piece_coordinates(pieces) == [(10, 2, 9, 0), (12, 2, 9, 0), (14, 2, 9, 0)]
    assert all(s.split and s.partial_hunk for s in pieces)
    assert all(h.change == "delete" for s in pieces for h in s.hunks)
    assert_rendered_headers_match(pieces)


def test_mixed_hunk_splits_with_context_counted_on_both_sides():
    lines = [" ctx_0", "-del_0", "-del_1", "+add_0", " ctx_1", "-del_2", "+add_1", " ctx_2"]
    pieces = line_pieces(10, 20, lines, per_piece=3)
    assert piece_coordinates(pieces) == [(10, 3, 20, 1), (13, 2, 21, 2), (15, 1, 23, 2)]
    assert [h.change for s in pieces for h in s.hunks] == ["delete", "mixed", "add"]
    assert_rendered_headers_match(pieces)
    body = [
        line
        for s in pieces
        for line in render_section(s).splitlines()
        if not line.startswith(("---", "+++", "@@"))
    ]
    assert body == lines


def test_coalescing_merges_adjacent_pair_with_smallest_combined_size():
    def ctx(n):
        return [{"path": f"pkg/f{n}.py", "symbol": f"sym{n}", "start_line": 1,
                 "end_line": 2, "snapshot": "pr", "why": "w"}]

    secs = titled(4)
    secs[1]["context"], secs[2]["context"] = ctx(2), ctx(3)
    p = plan(sized_files([12, 1, 1, 12]), proposal(*secs), max_sections=3)
    assert [s.title for s in p.sections] == ["T1", "T2 + T3", "T4"]
    merged = p.sections[1]
    assert merged.section_id.startswith("coalesced:")
    assert merged.origin == "coalesced"
    assert [h.hunk_id for h in merged.hunks] == ["pkg/f2.py#0", "pkg/f3.py#0"]
    assert merged.files == ["pkg/f2.py", "pkg/f3.py"]
    assert merged.rationale.index("R2.") < merged.rationale.index("R3.")
    assert [c.symbol for c in merged.context] == ["sym2", "sym3"]
    assert p.sections_coalesced == 1
    assert sorted(hunk_ids(p)) == [f"pkg/f{i}.py#0" for i in range(1, 5)]


def test_coalescing_tie_goes_to_lowest_index():
    p = plan(equal_files(4), proposal(*titled(4)), max_sections=3)
    assert [s.title for s in p.sections] == ["T1 + T2", "T3", "T4"]


def test_coalescing_repeats_until_within_max_sections_without_dropping_hunks():
    p = plan(equal_files(5), proposal(*titled(5)), max_sections=2)
    assert len(p.sections) == 2
    assert sorted(hunk_ids(p)) == [f"pkg/f{i}.py#0" for i in range(1, 6)]
    assert all(s.origin == "coalesced" for s in p.sections)
    assert len({s.section_id for s in p.sections}) == 2
    assert p.sections_coalesced == 3


def test_coalescing_orders_sections_by_file_then_hunk_position():
    p = plan(equal_files(4), proposal(*reversed(titled(4))), max_sections=3)
    assert [s.title for s in p.sections] == ["T1 + T2", "T3", "T4"]


def test_coalescing_is_deterministic():
    diffs = sized_files([3, 1, 2, 5, 1])

    def shape():
        p = plan(diffs, proposal(*titled(5)), max_sections=2)
        return [
            (s.section_id, s.title, [h.hunk_id for h in s.hunks], render_section(s))
            for s in p.sections
        ]

    assert shape() == shape()


def test_coalesced_section_may_exceed_section_max_chars_and_renders_in_full():
    diffs = equal_files(2, lines=[f"+filler_line_{i:02d}" for i in range(10)])
    singles = plan(diffs, proposal(*titled(2)))
    limit = max(len(render_section(s)) for s in singles.sections)
    p = plan(diffs, proposal(*titled(2)), section_max_chars=limit, max_sections=1)
    assert len(p.sections) == 1
    only = p.sections[0]
    assert only.origin == "coalesced"
    text = render_section(only)
    assert len(text) > limit
    assert "pkg/f1.py" in text and "pkg/f2.py" in text
    assert text.count("filler_line_09") == 2


def test_split_flags_are_ored_when_coalescing():
    lines = [f"+only_line_{i:02d}" for i in range(40)]
    diffs = parse(
        file_diff_text("pkg/other.py", [(1, 1, ["+x"])]),
        file_diff_text("pkg/long.py", [(5, 6, lines)]),
    )
    raw = proposal(section("other", ["pkg/other.py#0"]), section("long", ["pkg/long.py#0"]))
    limit = len(render_section(by_id(plan(diffs, raw), "long"))) // 3
    p = plan(diffs, raw, section_max_chars=limit, max_sections=1)
    assert len(p.sections) == 1
    assert p.sections[0].origin == "coalesced"
    assert p.sections[0].split and p.sections[0].partial_hunk


def test_hunk_boundary_split_coalesces_without_marking_a_partial_hunk():
    diffs = parse(
        file_diff_text("pkg/other.py", [(1, 1, ["+x"])]),
        file_diff_text(
            "pkg/big.py",
            [(10 * n, 10 * n, [f"+equal_size_line_{n}", f"+equal_size_more_{n}"]) for n in (1, 2, 3)],
        ),
    )
    singles = plan(diffs, proposal(*(section(f"h{i}", [f"pkg/big.py#{i}"]) for i in range(3))))
    limit = max(len(render_section(s)) for s in singles.sections)
    raw = proposal(
        section("other", ["pkg/other.py#0"]),
        section("big", [f"pkg/big.py#{i}" for i in range(3)]),
    )
    uncapped = plan(diffs, raw, section_max_chars=limit, max_sections=10)
    assert any(s.split and not s.partial_hunk for s in uncapped.sections)
    p = plan(diffs, raw, section_max_chars=limit, max_sections=1)
    assert len(p.sections) == 1
    assert p.sections[0].split
    assert not p.sections[0].partial_hunk


def test_render_has_one_header_pair_per_file_and_one_hunk_header_per_hunk(main_diffs):
    raw = proposal(section("s1", ["app/a.py#0", "app/a.py#1", "app/b.py#0"]))
    text = render_section(by_id(plan(main_diffs, raw), "s1"))
    assert len(re.findall(r"^\+\+\+ ", text, re.M)) == 2
    assert len(re.findall(r"^--- .*app/a\.py", text, re.M)) == 1
    assert len(re.findall(r"^--- .*app/b\.py", text, re.M)) == 1
    assert len(re.findall(r"^@@ ", text, re.M)) == 3
    for line in ("+new_value", "-old_value", "+added_one", "+added_two"):
        assert line in text
    assert text.index("app/a.py") < text.index("app/b.py")


def three_hunk_file(path):
    return file_diff_text(path, [(10, 10, MIXED), (40, 41, ADDS), (70, 72, DELS)])


def test_leftover_hunks_merged_into_a_coalesced_section_still_count_as_leftover():
    diffs = parse(three_hunk_file("pkg/a.py"), file_diff_text("pkg/b.py", [(5, 5, MIXED), (30, 30, ADDS)]))
    p = plan(diffs, proposal(section("s1", ["pkg/a.py#0"])), max_sections=2)
    assert len(p.sections) == 2
    assert p.sections_coalesced == 1
    assert p.hunks_total == 5
    assert p.hunks_assigned == 1
    assert p.hunks_leftover == 4


@pytest.mark.parametrize(
    "claimed, cfg",
    [
        (["app/a.py#0"], {}),
        (["app/a.py#0", "app/b.py#0"], {"max_sections": 2}),
        (["app/a.py#0"], {"max_sections": 1}),
        (["app/a.py#0", "app/a.py#1", "app/b.py#0", "old/c.py#0", "app/d.py#0"], {"max_sections": 1}),
        (["app/b.py#0"], {"section_max_chars": 150, "max_sections": 3}),
    ],
)
def test_investigator_plan_assigned_and_leftover_partition_the_hunks(claimed, cfg):
    diffs = parse_unified_diff(MAIN_DIFF)
    p = plan(diffs, proposal(section("s1", claimed)), **cfg)
    assert p.planner == "investigator"
    assert p.hunks_assigned == len(claimed)
    assert p.hunks_assigned + p.hunks_leftover == p.hunks_total == 5


def test_hunks_beyond_investigator_section_cap_count_as_leftover():
    raw = proposal(section("keep", ["pkg/f1.py#0"]), section("over", ["pkg/f2.py#0"]))
    p = plan(equal_files(3), raw, investigator_max_sections=1)
    assert (p.hunks_assigned, p.hunks_leftover, p.hunks_total) == (1, 2, 3)


PLANNING_TIME_LIMIT_S = 5.0


def test_planning_many_small_hunks_finishes_within_a_bounded_time():
    hunks = [(10 * n, 10 * n, [f"+row_{n}"]) for n in range(1, 21)]
    diffs = parse(*(file_diff_text(f"pkg/f{i}.py", hunks) for i in range(150)))
    started = time.perf_counter()
    p = plan(diffs, None, section_max_chars=400, max_sections=10)
    elapsed = time.perf_counter() - started
    assert elapsed < PLANNING_TIME_LIMIT_S
    assert p.hunks_total == 3000
    assert len(p.sections) <= 10
    assert len(hunk_ids(p)) == 3000


def test_planning_one_huge_hunk_finishes_within_a_bounded_time():
    diffs = parse(file_diff_text("pkg/huge.py", [(1, 1, [f"+row_{i}" for i in range(20000)])]))
    started = time.perf_counter()
    p = plan(diffs, None, section_max_chars=2000, max_sections=10)
    elapsed = time.perf_counter() - started
    assert elapsed < PLANNING_TIME_LIMIT_S
    assert len(p.sections) <= 10
    assert sum(h.new_count for s in p.sections for h in s.hunks) == 20000
