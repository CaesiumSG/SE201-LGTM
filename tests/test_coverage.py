"""Tests for coverage reporting, hunk/location overlap and run provenance."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import parse_unified_diff
from lgtm.review.coverage import (
    SectionResult,
    build_coverage,
    hunks_overlap,
    location_overlaps,
)
from lgtm.review.provenance import run_pin
from lgtm.review.sections import render_section
from tests.conftest import git
from tests.test_sections import (
    MAIN_DIFF,
    file_diff_text,
    parse,
    plan,
    proposal,
    section,
)

TOP_KEYS = {
    "planner", "investigator_status", "investigator_error", "investigator_input",
    "investigator_tool_calls", "files_total", "files_in_scope", "hunks_total",
    "hunks_assigned", "hunks_leftover", "hunks_reviewed", "sections_scheduled",
    "sections_completed", "sections_failed", "sections_coalesced", "complete",
    "exclusions", "invalid_refs", "sections",
}
SECTION_KEYS = {
    "section_id", "origin", "title", "files", "split", "partial_hunk", "hunks",
    "status", "supported", "finding_ids", "error",
}
HUNK_KEYS = {"hunk_id", "file", "old_start", "old_count", "new_start", "new_count", "change"}


def completed(supported=(False,), finding_ids=()):
    return SectionResult(
        status="completed", supported=list(supported), finding_ids=list(finding_ids), error=None
    )


def failed(error="llm timeout"):
    return SectionResult(status="failed", supported=[], finding_ids=[], error=error)


def coverage(p, results, **kw):
    args = dict(
        investigator_status="ok",
        investigator_error=None,
        investigator_input="full",
        investigator_tool_calls=3,
        results=results,
    )
    args.update(kw)
    return build_coverage(p, **args)


@pytest.fixture
def main_plan():
    raw = proposal(
        section("s1", ["app/a.py#0", "missing.py#0"], title="first"),
        section("s2", ["app/b.py#0"], title="second"),
    )
    return plan(parse_unified_diff(MAIN_DIFF), raw)


def all_completed(p):
    return {s.section_id: completed() for s in p.sections}


def test_coverage_has_exactly_the_contract_keys(main_plan):
    cov = coverage(main_plan, all_completed(main_plan))
    assert set(cov) == TOP_KEYS
    for row in cov["sections"]:
        assert set(row) == SECTION_KEYS
        for hunk in row["hunks"]:
            assert set(hunk) == HUNK_KEYS


def test_coverage_is_json_serialisable(main_plan):
    cov = coverage(main_plan, all_completed(main_plan))
    assert json.loads(json.dumps(cov)) == cov


def test_coverage_copies_plan_counters_and_investigator_fields(main_plan):
    cov = coverage(
        main_plan, all_completed(main_plan),
        investigator_status="failed", investigator_error="boom",
        investigator_input="manifest_only", investigator_tool_calls=7,
    )
    assert cov["planner"] == "investigator"
    assert cov["investigator_status"] == "failed"
    assert cov["investigator_error"] == "boom"
    assert cov["investigator_input"] == "manifest_only"
    assert cov["investigator_tool_calls"] == 7
    assert (cov["files_total"], cov["files_in_scope"]) == (6, 4)
    assert (cov["hunks_total"], cov["hunks_assigned"], cov["hunks_leftover"]) == (5, 2, 3)
    assert cov["sections_coalesced"] == main_plan.sections_coalesced
    assert cov["invalid_refs"] == ["missing.py#0"]
    assert {(e["path"], e["reason"]) for e in cov["exclusions"]} == {
        ("notes.md", "non_python"), ("app/e.py", "no_hunks"),
    }
    assert all(set(e) == {"path", "reason"} for e in cov["exclusions"])


def test_fully_completed_plan_is_complete(main_plan):
    cov = coverage(main_plan, all_completed(main_plan))
    n = len(main_plan.sections)
    assert cov["sections_scheduled"] == n
    assert cov["sections_completed"] == n
    assert cov["sections_failed"] == 0
    assert cov["hunks_reviewed"] == cov["hunks_total"] == 5
    assert cov["complete"] is True


def test_section_rows_carry_plan_data_and_results(main_plan):
    results = all_completed(main_plan)
    results["s1"] = completed(supported=[True, False], finding_ids=["f1", "f2"])
    cov = coverage(main_plan, results)
    row = next(r for r in cov["sections"] if r["section_id"] == "s1")
    assert row["origin"] == "investigator"
    assert row["title"] == "first"
    assert row["files"] == ["app/a.py"]
    assert row["split"] is False and row["partial_hunk"] is False
    assert row["status"] == "completed"
    assert row["supported"] == [True, False]
    assert row["finding_ids"] == ["f1", "f2"]
    assert row["hunks"] == [{
        "hunk_id": "app/a.py#0", "file": "app/a.py", "old_start": 10, "old_count": 3,
        "new_start": 10, "new_count": 3, "change": "mixed",
    }]
    assert [r["section_id"] for r in cov["sections"]] == [s.section_id for s in main_plan.sections]


def test_failed_section_makes_coverage_incomplete_and_is_not_reviewed(main_plan):
    results = all_completed(main_plan)
    results["s2"] = failed("llm timeout")
    cov = coverage(main_plan, results)
    n = len(main_plan.sections)
    assert cov["sections_failed"] == 1
    assert cov["sections_completed"] == n - 1
    assert cov["sections_scheduled"] == n
    assert cov["hunks_reviewed"] == cov["hunks_total"] - 1
    assert cov["complete"] is False
    row = next(r for r in cov["sections"] if r["section_id"] == "s2")
    assert row["status"] == "failed"
    assert row["error"] == "llm timeout"


def test_hunks_reviewed_counts_unique_hunk_ids_across_split_pieces():
    lines = [f"+only_line_{i:02d}" for i in range(40)]
    diffs = parse(file_diff_text("pkg/long.py", [(5, 6, lines)]))
    raw = proposal(section("long", ["pkg/long.py#0"]))
    limit = len(render_section(plan(diffs, raw).sections[0])) // 3
    p = plan(diffs, raw, section_max_chars=limit)
    assert len(p.sections) >= 3
    cov = coverage(p, all_completed(p))
    assert cov["sections_scheduled"] == len(p.sections)
    assert cov["hunks_total"] == 1
    assert cov["hunks_reviewed"] == 1
    assert cov["complete"] is True


def test_split_hunk_with_a_failed_piece_is_incomplete():
    lines = [f"+only_line_{i:02d}" for i in range(40)]
    diffs = parse(file_diff_text("pkg/long.py", [(5, 6, lines)]))
    raw = proposal(section("long", ["pkg/long.py#0"]))
    limit = len(render_section(plan(diffs, raw).sections[0])) // 3
    p = plan(diffs, raw, section_max_chars=limit)
    results = all_completed(p)
    results[p.sections[-1].section_id] = failed()
    cov = coverage(p, results)
    assert cov["sections_failed"] == 1
    assert cov["hunks_reviewed"] == 1
    assert cov["complete"] is False


def test_section_without_a_result_is_neither_completed_nor_failed_and_blocks_completeness(main_plan):
    results = all_completed(main_plan)
    del results["s2"]
    cov = coverage(main_plan, results)
    n = len(main_plan.sections)
    assert cov["sections_scheduled"] == n
    assert cov["sections_completed"] == n - 1
    assert cov["sections_failed"] == 0
    assert cov["hunks_reviewed"] == cov["hunks_total"] - 1
    assert cov["complete"] is False
    row = next(r for r in cov["sections"] if r["section_id"] == "s2")
    assert row["status"] is None
    assert row["supported"] == [] and row["finding_ids"] == [] and row["error"] is None


def test_fallback_plan_reports_planner_and_skipped_investigator():
    p = plan(parse_unified_diff(MAIN_DIFF), None)
    cov = coverage(
        p, all_completed(p),
        investigator_status="skipped", investigator_input="none", investigator_tool_calls=0,
    )
    assert cov["planner"] == "fallback"
    assert cov["investigator_status"] == "skipped"
    assert cov["investigator_input"] == "none"
    assert cov["investigator_tool_calls"] == 0
    assert cov["complete"] is True


def one_hunk(old_start, old_count, new_start, new_count):
    old_lines = [f"-gone_{i}" for i in range(old_count)]
    new_lines = [f"+came_{i}" for i in range(new_count)]
    diffs = parse(file_diff_text("pkg/m.py", [(old_start, new_start, old_lines + new_lines)]))
    ref = plan(diffs, None).sections[0].hunks[0]
    assert (ref.old_start, ref.old_count, ref.new_start, ref.new_count) == (
        old_start, old_count, new_start, new_count,
    )
    return ref


def test_hunks_overlap_uses_inclusive_ranges_on_the_requested_side():
    a = one_hunk(10, 5, 100, 5)
    assert hunks_overlap(a, one_hunk(14, 3, 50, 1), side="old")
    assert not hunks_overlap(a, one_hunk(15, 3, 50, 1), side="old")
    assert hunks_overlap(a, one_hunk(1, 1, 104, 2), side="new")
    assert not hunks_overlap(a, one_hunk(1, 1, 105, 2), side="new")
    assert not hunks_overlap(a, one_hunk(10, 5, 200, 5), side="new")
    assert hunks_overlap(a, one_hunk(10, 5, 200, 5), side="old")


def test_hunks_overlap_treats_zero_count_as_one_line():
    deletion = one_hunk(8, 3, 7, 0)
    insertion = one_hunk(7, 0, 8, 2)
    assert hunks_overlap(deletion, one_hunk(1, 1, 7, 1), side="new")
    assert not hunks_overlap(deletion, one_hunk(1, 1, 8, 1), side="new")
    assert hunks_overlap(insertion, one_hunk(7, 1, 1, 1), side="old")
    assert not hunks_overlap(insertion, one_hunk(8, 1, 1, 1), side="old")


def hunk_dict(file="pkg/m.py", old=(10, 5), new=(100, 5), change="mixed"):
    return {
        "hunk_id": f"{file}#0", "file": file, "old_start": old[0], "old_count": old[1],
        "new_start": new[0], "new_count": new[1], "change": change,
    }


def loc(file="pkg/m.py", old_range=None, new_range=None):
    return {"file": file, "old_range": old_range, "new_range": new_range}


def test_location_in_other_file_never_overlaps():
    assert not location_overlaps(hunk_dict(), loc(file="pkg/other.py", new_range=[100, 104]))
    assert not location_overlaps(hunk_dict(), loc(file="pkg/other.py"))


def test_location_without_ranges_matches_any_hunk_of_the_file():
    assert location_overlaps(hunk_dict(), loc())
    assert location_overlaps(hunk_dict(old=(1, 0), new=(500, 0)), loc())


def test_location_new_range_is_inclusive():
    h = hunk_dict(new=(100, 5))
    assert location_overlaps(h, loc(new_range=[104, 120]))
    assert location_overlaps(h, loc(new_range=[90, 100]))
    assert location_overlaps(h, loc(new_range=[102, 102]))
    assert not location_overlaps(h, loc(new_range=[105, 120]))
    assert not location_overlaps(h, loc(new_range=[1, 99]))


def test_location_old_range_checks_the_old_side_only():
    h = hunk_dict(old=(10, 5), new=(100, 5))
    assert location_overlaps(h, loc(old_range=[14, 20]))
    assert not location_overlaps(h, loc(old_range=[15, 20]))
    assert not location_overlaps(h, loc(old_range=[100, 104]))
    assert not location_overlaps(h, loc(new_range=[10, 14]))


def test_location_zero_count_hunk_occupies_one_line():
    deletion_only = hunk_dict(old=(8, 3), new=(7, 0), change="delete")
    assert location_overlaps(deletion_only, loc(new_range=[7, 7]))
    assert not location_overlaps(deletion_only, loc(new_range=[8, 9]))
    assert location_overlaps(deletion_only, loc(old_range=[10, 12]))
    addition_only = hunk_dict(old=(7, 0), new=(8, 2), change="add")
    assert location_overlaps(addition_only, loc(old_range=[7, 7]))
    assert not location_overlaps(addition_only, loc(old_range=[8, 9]))


def test_location_with_both_ranges_matches_when_either_side_overlaps():
    h = hunk_dict(old=(10, 5), new=(100, 5))
    assert location_overlaps(h, loc(old_range=[10, 10], new_range=[100, 100]))
    assert location_overlaps(h, loc(old_range=[10, 10], new_range=[1, 2]))
    assert location_overlaps(h, loc(old_range=[1, 2], new_range=[100, 100]))
    assert not location_overlaps(h, loc(old_range=[1, 2], new_range=[1, 2]))


@pytest.fixture
def pin_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "pinned"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@t.local")
    git(repo, "config", "user.name", "T")
    (repo / "tracked.py").write_text("x = 1\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    return repo


REFS = {"base": "base-ref-sha", "pr": "pr-ref-sha"}


def pin_config():
    return LGTMConfig(
        llm_temperature=0.25,
        mode="sast-only",
        static_facts=True,
        authz_role_guidance=True,
        strip_comments=True,
        detect_prompt_injection=True,
        require_tool_use=True,
        investigator_max_tool_calls=3,
        investigator_max_iterations=4,
        max_agent_iterations=5,
        reasoning=True,
        investigator_diff_chars=5000,
        investigator_max_sections=6,
        section_max_chars=2000,
        max_sections=9,
        max_tool_calls=8,
    )


def test_run_pin_records_head_sha_and_clean_tree(pin_repo):
    pin = run_pin(pin_config(), pin_repo, REFS)
    assert pin["code_sha"] == git(pin_repo, "rev-parse", "HEAD").strip()
    assert pin["code_dirty"] is False
    assert pin["base_sha"] == "base-ref-sha"
    assert pin["pr_sha"] == "pr-ref-sha"


def test_run_pin_flags_uncommitted_changes_as_dirty(pin_repo):
    (pin_repo / "tracked.py").write_text("x = 2\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS)
    assert pin["code_sha"] == git(pin_repo, "rev-parse", "HEAD").strip()
    assert pin["code_dirty"] is True


def test_run_pin_flags_untracked_files_as_dirty(pin_repo):
    (pin_repo / "new_file.py").write_text("y = 1\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS)
    assert pin["code_dirty"] is True


def test_run_pin_flags_staged_only_changes_as_dirty(pin_repo):
    (pin_repo / "tracked.py").write_text("x = 3\n", encoding="utf-8")
    git(pin_repo, "add", "tracked.py")
    pin = run_pin(pin_config(), pin_repo, REFS)
    assert pin["code_dirty"] is True


@pytest.mark.parametrize(
    "refs, base_sha, pr_sha",
    [
        ({}, "", ""),
        ({"base": "only-base"}, "only-base", ""),
        ({"pr": "only-pr"}, "", "only-pr"),
    ],
)
def test_run_pin_with_missing_ref_keys_gives_empty_shas_without_raising(
    pin_repo, refs, base_sha, pr_sha
):
    pin = run_pin(pin_config(), pin_repo, refs)
    assert pin["base_sha"] == base_sha
    assert pin["pr_sha"] == pr_sha
    assert pin["code_sha"] == git(pin_repo, "rev-parse", "HEAD").strip()


def test_run_pin_records_model_sampling_budgets_and_flags(pin_repo):
    config = pin_config()
    pin = run_pin(config, pin_repo, REFS)
    assert pin["model"] == config.ollama_model
    assert pin["sampling"] == {"llm_temperature": 0.25, "reasoning": True}
    assert pin["budgets"] == {
        "max_tool_calls": 8,
        "max_agent_iterations": 5,
        "investigator_max_tool_calls": 3,
        "investigator_max_iterations": 4,
        "investigator_diff_chars": 5000,
        "investigator_max_sections": 6,
        "section_max_chars": 2000,
        "max_sections": 9,
    }
    assert pin["flags"] == {
        "mode": "sast-only",
        "static_facts": True,
        "authz_role_guidance": True,
        "strip_comments": True,
        "detect_prompt_injection": True,
        "require_tool_use": True,
    }


def test_run_pin_is_json_serialisable(pin_repo):
    pin = run_pin(pin_config(), pin_repo, REFS)
    assert json.loads(json.dumps(pin)) == pin


def test_run_pin_outside_a_git_repo_reports_unknown_without_raising(tmp_path):
    plain = tmp_path / "not_a_repo"
    plain.mkdir()
    probe = subprocess.run(
        ["git", "-C", str(plain), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    if probe.returncode == 0:
        pytest.skip("temporary directory is inside a git repository")
    pin = run_pin(pin_config(), plain, REFS)
    assert pin["code_sha"] == ""
    assert pin["code_dirty"] is None
    assert pin["base_sha"] == "base-ref-sha"


def test_run_pin_with_missing_directory_reports_unknown_without_raising(tmp_path):
    pin = run_pin(pin_config(), tmp_path / "does_not_exist", REFS)
    assert pin["code_sha"] == ""
    assert pin["code_dirty"] is None


@pytest.fixture
def run_dir(pin_repo: Path) -> Path:
    out = pin_repo / "runs" / "current"
    out.mkdir(parents=True)
    (out / "case_01.json").write_text("{}\n", encoding="utf-8")
    return out


def test_run_pin_exclude_ignores_untracked_files_inside_the_excluded_directory(
    pin_repo, run_dir
):
    assert run_pin(pin_config(), pin_repo, REFS)["code_dirty"] is True
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=run_dir)
    assert pin["code_dirty"] is False
    assert pin["code_sha"] == git(pin_repo, "rev-parse", "HEAD").strip()


def test_run_pin_exclude_still_flags_tracked_edits(pin_repo, run_dir):
    (pin_repo / "tracked.py").write_text("x = 2\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=run_dir)
    assert pin["code_dirty"] is True


def test_run_pin_exclude_still_flags_untracked_files_outside_the_excluded_directory(
    pin_repo, run_dir
):
    (pin_repo / "new_file.py").write_text("y = 1\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=run_dir)
    assert pin["code_dirty"] is True


def test_run_pin_exclude_outside_the_repo_is_ignored(pin_repo, run_dir, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=elsewhere)
    assert pin["code_dirty"] is True


def test_run_pin_exclude_nonexistent_path_does_not_raise(pin_repo):
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=pin_repo / "runs" / "missing")
    assert pin["code_sha"] == git(pin_repo, "rev-parse", "HEAD").strip()
    assert pin["code_dirty"] is False


def test_run_pin_exclude_equal_to_the_repo_root_still_flags_tracked_edits(pin_repo):
    (pin_repo / "tracked.py").write_text("x = 2\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=pin_repo)
    assert pin["code_dirty"] is True


def test_run_pin_relative_exclude_resolves_against_the_working_directory(
    pin_repo, run_dir, monkeypatch
):
    monkeypatch.chdir(pin_repo)
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=Path("runs") / "current")
    assert pin["code_dirty"] is False


def test_run_pin_exclude_naming_a_file_hides_only_that_file(pin_repo, run_dir):
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=run_dir / "case_01.json")
    assert pin["code_dirty"] is False
    (run_dir / "case_02.json").write_text("{}\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=run_dir / "case_01.json")
    assert pin["code_dirty"] is True


def test_run_pin_exclude_does_not_hide_a_sibling_directory_sharing_its_prefix(
    pin_repo, run_dir
):
    sibling = pin_repo / "runs2"
    sibling.mkdir()
    (sibling / "case_01.json").write_text("{}\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=pin_repo / "runs")
    assert pin["code_dirty"] is True


@pytest.mark.skipif(sys.platform == "win32", reason="'*' is not valid in Windows file names")
def test_run_pin_exclude_with_glob_characters_in_its_name_matches_only_that_directory(
    pin_repo,
):
    excluded = pin_repo / "a*b"
    lookalike = pin_repo / "ab"
    excluded.mkdir()
    lookalike.mkdir()
    (excluded / "out.json").write_text("{}\n", encoding="utf-8")
    (lookalike / "src.py").write_text("y = 1\n", encoding="utf-8")
    pin = run_pin(pin_config(), pin_repo, REFS, exclude=excluded)
    assert pin["code_dirty"] is True


@pytest.fixture
def git_calls(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake_git(repo_root, *args):
        calls.append(args)
        return "deadbeef\n" if args[0] == "rev-parse" else ""

    monkeypatch.setattr("lgtm.review.provenance._git", fake_git)
    return calls


def status_args(calls):
    (call,) = [c for c in calls if c[0] == "status"]
    return call


def test_run_pin_passes_an_exclude_pathspec_for_a_path_inside_the_repo(
    git_calls, tmp_path
):
    run_pin(pin_config(), tmp_path, REFS, exclude=tmp_path / "runs" / "current")
    args = status_args(git_calls)
    assert "--porcelain" in args
    assert "--" in args
    specs = args[args.index("--") + 1 :]
    assert ":(exclude,literal)runs/current" in specs


@pytest.mark.parametrize("where", ["none", "outside", "repo_root"])
def test_run_pin_passes_no_pathspec_when_nothing_inside_the_repo_is_excluded(
    git_calls, tmp_path, where
):
    repo = tmp_path / "repo"
    repo.mkdir()
    exclude = {"none": None, "outside": tmp_path / "elsewhere", "repo_root": repo}[where]
    run_pin(pin_config(), repo, REFS, exclude=exclude)
    assert "--" not in status_args(git_calls)
