"""Tests for deterministic de-duplication of findings across sections."""

from __future__ import annotations

import pytest

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.diff.git_diff import get_pr_diff
from lgtm.review.dedup import dedup_findings
from lgtm.validation.evidence import PR_GROUNDING_CAP_MARKER, EvidenceValidator

FILE = "app/views.py"


def ev(lines, snapshot=None, file=FILE, content="code", type="code", source=None):
    return EvidenceItem(
        type=type, file=file, lines=lines, snapshot=snapshot, content=content, source=source
    )


def finding(fid, *, line=0, evidence=(), file=FILE, cwe="CWE-639", verdict="", **kw):
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


def test_merged_finding_keeps_the_first_id_takes_member_text_and_carries_no_verdict_or_confidence():
    first = finding("a", line=10, explanation="short", suggested_fix="a much longer suggested fix")
    second = finding(
        "b", line=10, explanation="a considerably longer explanation", suggested_fix="fix"
    )
    third = finding("c", line=10)
    (merged,) = dedup_findings([first, second, third])
    assert merged.finding_id == "a"
    assert not merged.verdict
    assert "confidence" not in merged.model_dump()
    assert merged.explanation == "short"
    assert merged.suggested_fix == "a much longer suggested fix"


def test_merged_evidence_is_the_union_without_duplicates():
    shared = ev([10, 12], content="shared")
    a = finding("a", line=10, evidence=[shared, ev([10, 10], content="only a")])
    b = finding("b", line=10, evidence=[ev([10, 12], content="shared"), ev([11, 11], content="only b"),
                                        ev(None, type="policy", file=None, source="docs/p.md",
                                           content="policy text")])
    (merged,) = dedup_findings([a, b])
    assert [e.content for e in merged.evidence] == ["shared", "only a", "only b", "policy text"]


@pytest.mark.parametrize(
    "other",
    [
        {"type": "policy"},
        {"file": "app/helpers.py"},
        {"source": "docs/policy_b.md"},
    ],
    ids=["type", "file", "source"],
)
def test_evidence_differing_only_by_type_file_or_source_is_kept_apart(other):
    base = {"type": "code", "file": FILE, "source": "docs/policy_a.md"}
    a = finding("a", line=10, evidence=[ev([10, 12], content="same", **base)])
    b = finding("b", line=10, evidence=[ev([10, 12], content="same", **{**base, **other})])
    (merged,) = dedup_findings([a, b])
    assert len(merged.evidence) == 2


def test_evidence_identical_in_type_file_lines_source_and_content_is_collapsed():
    item = dict(type="code", file=FILE, source="docs/policy_a.md", content="same")
    a = finding("a", line=10, evidence=[ev([10, 12], **item)])
    b = finding("b", line=10, evidence=[ev([10, 12], **item)])
    (merged,) = dedup_findings([a, b])
    assert len(merged.evidence) == 1


def test_merging_does_not_modify_the_input_findings():
    a = finding("a", line=10, evidence=[ev([10, 12], content="x")])
    b = finding("b", line=10, evidence=[ev([10, 13], content="y")], explanation="longer text")
    before = [f.model_dump() for f in (a, b)]
    dedup_findings([a, b])
    assert [f.model_dump() for f in (a, b)] == before


def test_evidence_with_different_lines_or_content_is_kept_apart():
    a = finding("a", line=10, evidence=[ev([10, 12], content="x")])
    b = finding("b", line=10, evidence=[ev([10, 13], content="x"), ev([10, 12], content="y")])
    (merged,) = dedup_findings([a, b])
    assert len(merged.evidence) == 3


def test_new_side_range_comes_from_line_and_unlabelled_or_pr_evidence():
    a = finding("a", line=50)
    b = finding("b", line=0, evidence=[ev([48, 50])])
    c = finding("c", line=0, evidence=[ev([50, 55], snapshot="pr")])
    assert ids(dedup_findings([a, b])) == ["a"]
    assert ids(dedup_findings([a, c])) == ["a"]


def test_reversed_evidence_line_pair_is_read_as_an_ordered_range():
    a = finding("a", line=0, evidence=[ev([12, 10])])
    b = finding("b", line=11)
    assert ids(dedup_findings([a, b])) == ["a"]


def test_evidence_from_another_file_does_not_contribute_ranges_for_overlap():
    a = finding("a", line=0, evidence=[ev([10, 12], file="app/helpers.py")])
    b = finding("b", line=11)
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_evidence_from_another_file_on_the_old_side_does_not_contribute_ranges():
    a = finding("a", line=0, evidence=[ev([20, 25], snapshot="base", file="app/helpers.py")])
    b = finding("b", line=0, evidence=[ev([22, 24], snapshot="base")])
    assert ids(dedup_findings([a, b])) == ["a", "b"]


def test_evidence_of_the_findings_own_file_or_without_file_contributes_ranges():
    a = finding("a", line=0, evidence=[ev([10, 12], file=None, type="policy", source="p.md")])
    b = finding("b", line=11)
    assert ids(dedup_findings([a, b])) == ["a"]


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
    a = finding("a", line=10, explanation="x")
    b = finding("b", line=90, explanation="y")
    result = dedup_findings([a, b])
    assert result == [a, b]


def test_merging_is_transitive_through_a_bridging_finding():
    a = finding("a", line=0, evidence=[ev([10, 12])])
    c = finding("c", line=0, evidence=[ev([20, 25])])
    bridge = finding("b", line=0, evidence=[ev([12, 20])])
    (merged,) = dedup_findings([a, c, bridge])
    assert merged.finding_id == "a"
    assert not merged.verdict


def test_output_keeps_first_occurrence_order():
    x = finding("x", line=10)
    y = finding("y", line=500, file="app/other.py")
    z = finding("z", line=10)
    w = finding("w", line=70, cwe="CWE-89")
    result = dedup_findings([x, y, z, w])
    assert ids(result) == ["x", "y", "w"]


def test_safe_findings_pass_through_unchanged_and_unmerged():
    s1 = finding("s1", line=10, verdict="safe", explanation="fine")
    s2 = finding("s2", line=10, verdict="safe", explanation="also fine")
    assert dedup_findings([s1, s2]) == [s1, s2]


def test_safe_finding_is_not_merged_with_an_overlapping_vulnerable_one():
    safe = finding("s", line=10, verdict="safe")
    vuln = finding("v", line=10)
    result = dedup_findings([safe, vuln])
    assert ids(result) == ["s", "v"]
    assert result[0].verdict == "safe" and not result[1].verdict


def test_safe_findings_keep_their_position_among_merged_ones():
    first = finding("a", line=10)
    safe = finding("s", line=10, verdict="safe")
    dup = finding("b", line=10)
    result = dedup_findings([first, safe, dup])
    assert ids(result) == ["a", "s"]
    assert not result[0].verdict


def _stamped_pair(first_stamp, second_stamp):
    first = finding("a", line=10, pr_graph_ok=first_stamp)
    second = finding("b", line=10, pr_graph_ok=second_stamp)
    return first, second


@pytest.mark.parametrize("reverse", [False, True], ids=["first-stamped-up", "second-stamped-up"])
def test_merged_finding_keeps_pr_graph_down_stamp_whatever_the_section_order(reverse):
    pair = list(_stamped_pair(True, False))
    if reverse:
        pair.reverse()
    (merged,) = dedup_findings(pair)
    assert merged.pr_graph_ok is False


@pytest.mark.parametrize("stamp", [True, None])
def test_merged_findings_with_the_same_pr_graph_stamp_keep_it(stamp):
    (merged,) = dedup_findings(_stamped_pair(stamp, stamp))
    assert merged.pr_graph_ok is stamp


@pytest.mark.parametrize("reverse", [False, True], ids=["first-stamped-up", "second-stamped-up"])
def test_merged_candidate_stays_unjudged_after_validation_when_pr_graph_went_down(
    git_repo, reverse
):
    pair = list(_stamped_pair(True, False))
    if reverse:
        pair.reverse()
    (merged,) = dedup_findings(pair)
    EvidenceValidator(git_repo, "main").validate(merged)
    assert not merged.verdict
    assert PR_GROUNDING_CAP_MARKER not in merged.explanation


def test_merged_candidate_grounded_in_pr_code_stays_unjudged_and_unmarked(git_repo):
    snippet = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
    grounded = EvidenceItem(type="code", file="app.py", content=snippet)
    first = finding("a", line=10, file="app.py", pr_graph_ok=True)
    second = finding(
        "b", line=10, file="app.py", pr_graph_ok=False,
        evidence=[grounded],
    )
    (merged,) = dedup_findings([first, second])
    diffs = get_pr_diff(git_repo, "main", "pr")
    EvidenceValidator(git_repo, "main", diffs).validate(merged)
    assert not merged.verdict
    assert PR_GROUNDING_CAP_MARKER not in merged.explanation
