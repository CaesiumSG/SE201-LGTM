"""Tests for deterministic de-duplication of findings across sections."""

from __future__ import annotations

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.review.dedup import dedup_findings

FILE = "app/views.py"


def ev(lines, snapshot=None, file=FILE, content="code", type="code", source=None):
    return EvidenceItem(
        type=type, file=file, lines=lines, snapshot=snapshot, content=content, source=source
    )


def finding(fid, *, line=0, evidence=(), file=FILE, cwe="CWE-639", verdict="possible", **kw):
    return AgentFinding(
        finding_id=fid, file=file, line=line, cwe_id=cwe, verdict=verdict,
        evidence=list(evidence), **kw,
    )


def ids(findings):
    return [f.finding_id for f in findings]


def test_empty_input_gives_empty_output():
    assert dedup_findings([]) == []


def test_findings_on_the_same_line_with_same_cwe_merge_into_one():
    merged = dedup_findings([finding("a", line=10), finding("b", line=10)])
    assert ids(merged) == ["a"]


def test_merged_finding_keeps_strongest_verdict_highest_confidence_and_longest_text():
    first = finding(
        "a", line=10, verdict="insufficient_evidence", confidence=0.9,
        explanation="short", suggested_fix="a much longer suggested fix",
    )
    second = finding(
        "b", line=10, verdict="vulnerable", confidence=0.4,
        explanation="a considerably longer explanation", suggested_fix="fix",
    )
    third = finding("c", line=10, verdict="possible", confidence=0.6)
    (merged,) = dedup_findings([first, second, third])
    assert merged.finding_id == "a"
    assert merged.verdict == "vulnerable"
    assert merged.confidence == 0.9
    assert merged.explanation == "a considerably longer explanation"
    assert merged.suggested_fix == "a much longer suggested fix"


def test_possible_beats_insufficient_evidence():
    (merged,) = dedup_findings([
        finding("a", line=3, verdict="insufficient_evidence"),
        finding("b", line=3, verdict="possible"),
    ])
    assert merged.verdict == "possible"


def test_merged_evidence_is_the_union_without_duplicates():
    shared = ev([10, 12], content="shared")
    a = finding("a", line=10, evidence=[shared, ev([10, 10], content="only a")])
    b = finding("b", line=10, evidence=[ev([10, 12], content="shared"), ev([11, 11], content="only b"),
                                        ev(None, type="policy", file=None, source="docs/p.md",
                                           content="policy text")])
    (merged,) = dedup_findings([a, b])
    assert [e.content for e in merged.evidence] == ["shared", "only a", "only b", "policy text"]


def test_evidence_with_different_lines_or_content_is_kept_apart():
    a = finding("a", line=10, evidence=[ev([10, 12], content="x")])
    b = finding("b", line=10, evidence=[ev([10, 13], content="x"), ev([10, 12], content="y")])
    (merged,) = dedup_findings([a, b])
    assert len(merged.evidence) == 3


# --- overlap on the new side -----------------------------------------------------


def test_new_side_range_comes_from_line_and_unlabelled_or_pr_evidence():
    a = finding("a", line=50)
    b = finding("b", line=0, evidence=[ev([48, 50])])
    c = finding("c", line=0, evidence=[ev([50, 55], snapshot="pr")])
    assert ids(dedup_findings([a, b])) == ["a"]
    assert ids(dedup_findings([a, c])) == ["a"]


def test_adjacent_but_non_overlapping_new_ranges_stay_separate():
    a = finding("a", line=0, evidence=[ev([10, 12], snapshot="pr")])
    b = finding("b", line=0, evidence=[ev([13, 15], snapshot="pr")])
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_line_zero_without_evidence_has_no_range_and_never_merges():
    assert ids(dedup_findings([finding("a", line=0), finding("b", line=0)])) == ["a", "b"]


def test_line_zero_gives_no_new_side_range_from_line():
    a = finding("a", line=0, evidence=[ev([30, 30], snapshot="base")])
    b = finding("b", line=0, evidence=[ev([40, 40], snapshot="pr")])
    assert ids(dedup_findings([a, b])) == ["a", "b"]


# --- overlap on the old side -------------------------------------------------------


def test_base_snapshot_evidence_overlaps_on_the_old_side():
    a = finding("a", line=0, evidence=[ev([20, 25], snapshot="base")])
    b = finding("b", line=0, evidence=[ev([25, 30], snapshot="base")])
    assert ids(dedup_findings([a, b])) == ["a"]


def test_old_and_new_side_ranges_are_not_compared_with_each_other():
    a = finding("a", line=20)
    b = finding("b", line=0, evidence=[ev([20, 20], snapshot="base")])
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_finding_overlapping_on_either_side_merges():
    a = finding("a", line=100, evidence=[ev([20, 25], snapshot="base")])
    b = finding("b", line=0, evidence=[ev([24, 30], snapshot="base")])
    assert ids(dedup_findings([a, b])) == ["a"]


# --- non-merge conditions ----------------------------------------------------------


def test_different_files_do_not_merge():
    a = finding("a", line=10)
    b = finding("b", line=10, file="app/other.py")
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_different_cwe_does_not_merge():
    a = finding("a", line=10, cwe="CWE-639")
    b = finding("b", line=10, cwe="CWE-862")
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_empty_file_does_not_merge():
    a = finding("a", line=10, file="")
    b = finding("b", line=10, file="")
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_empty_cwe_does_not_merge():
    a = finding("a", line=10, cwe="")
    b = finding("b", line=10, cwe="")
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_non_overlapping_lines_do_not_merge_and_pass_through_unchanged():
    a = finding("a", line=10, confidence=0.3, explanation="x")
    b = finding("b", line=90, confidence=0.7, explanation="y")
    result = dedup_findings([a, b])
    assert result == [a, b]


# --- transitivity and order --------------------------------------------------------


def test_merging_is_transitive_through_a_bridging_finding():
    a = finding("a", line=0, evidence=[ev([10, 12])], verdict="insufficient_evidence")
    c = finding("c", line=0, evidence=[ev([20, 25])], verdict="possible", confidence=0.8)
    bridge = finding("b", line=0, evidence=[ev([12, 20])], verdict="vulnerable", confidence=0.2)
    (merged,) = dedup_findings([a, c, bridge])
    assert merged.finding_id == "a"
    assert merged.verdict == "vulnerable"
    assert merged.confidence == 0.8


def test_output_keeps_first_occurrence_order():
    x = finding("x", line=10)
    y = finding("y", line=500, file="app/other.py")
    z = finding("z", line=10)
    w = finding("w", line=70, cwe="CWE-89")
    result = dedup_findings([x, y, z, w])
    assert ids(result) == ["x", "y", "w"]


# --- safe findings -----------------------------------------------------------------


def test_safe_findings_pass_through_unchanged_and_unmerged():
    s1 = finding("s1", line=10, verdict="safe", explanation="fine")
    s2 = finding("s2", line=10, verdict="safe", explanation="also fine")
    assert dedup_findings([s1, s2]) == [s1, s2]


def test_safe_finding_is_not_merged_with_an_overlapping_vulnerable_one():
    safe = finding("s", line=10, verdict="safe")
    vuln = finding("v", line=10, verdict="vulnerable")
    result = dedup_findings([safe, vuln])
    assert ids(result) == ["s", "v"]
    assert result[0].verdict == "safe" and result[1].verdict == "vulnerable"


def test_safe_findings_keep_their_position_among_merged_ones():
    first = finding("a", line=10)
    safe = finding("s", line=10, verdict="safe")
    dup = finding("b", line=10, verdict="vulnerable")
    result = dedup_findings([first, safe, dup])
    assert ids(result) == ["a", "s"]
    assert result[0].verdict == "vulnerable"
