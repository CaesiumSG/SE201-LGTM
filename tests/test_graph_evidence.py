"""Evidence, finding and review-metadata schema fields for graph provenance."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from lgtm.agents.base import AgentFinding, EvidenceItem, parse_agent_output
from lgtm.diff.git_diff import get_pr_diff
from lgtm.reporting.report_builder import ReportBuilder, ReviewMetadata
from lgtm.validation.evidence import EvidenceValidator


class TestEvidenceItemSnapshot:
    def test_defaults_are_unlabelled_and_conflict_free(self):
        item = EvidenceItem(type="code", file="app.py", lines=[1, 2], content="x")
        assert item.snapshot is None
        assert item.snapshot_conflict is False

    @pytest.mark.parametrize("label", ["base", "pr"])
    def test_accepts_snapshot_labels(self, label):
        assert EvidenceItem(file="app.py", snapshot=label).snapshot == label

    @staticmethod
    def _parsed_item(snapshot):
        raw = json.dumps({
            "verdict": "safe",
            "evidence": [{"type": "code", "file": "a.py", "lines": [1, 1],
                          "content": "x", "snapshot": snapshot}],
        })
        finding = parse_agent_output(raw, "f")
        assert len(finding.evidence) == 1
        return finding.evidence[0]

    @pytest.mark.parametrize("given,expected", [(" PR ", "pr"), ("Base", "base")])
    def test_structured_snapshot_is_stripped_and_lowercased(self, given, expected):
        item = self._parsed_item(given)
        assert item.snapshot == expected
        assert item.snapshot_conflict is False

    @pytest.mark.parametrize("given", ["deadbeef", "a" * 40, "main"])
    def test_unknown_snapshot_loads_flags_conflict_and_is_not_a_label(self, given):
        item = self._parsed_item(given)
        assert item.snapshot_conflict is True
        assert item.snapshot != given

    @pytest.mark.parametrize("given", ["", None])
    def test_empty_snapshot_is_unlabelled_without_conflict(self, given):
        item = self._parsed_item(given)
        assert item.snapshot is None
        assert item.snapshot_conflict is False

    def test_conflict_flag_is_settable(self):
        assert EvidenceItem(file="a.py", snapshot_conflict=True).snapshot_conflict is True

    def test_old_serialized_evidence_still_loads(self):
        old = {"type": "code", "file": "a.py", "lines": [1, 2], "source": None, "content": "x"}
        item = EvidenceItem.model_validate(old)
        assert item.snapshot is None and item.snapshot_conflict is False


class TestFindingPrGraphOk:
    def test_default_is_none(self):
        assert AgentFinding(finding_id="f").pr_graph_ok is None

    @pytest.mark.parametrize("value", [True, False])
    def test_pipeline_can_stamp_value(self, value):
        finding = AgentFinding(finding_id="f")
        finding.pr_graph_ok = value
        assert finding.model_dump()["pr_graph_ok"] is value

    @pytest.mark.parametrize("claimed", [True, False])
    def test_model_supplied_value_is_dropped(self, claimed):
        raw = json.dumps({"verdict": "safe", "confidence": 0.5, "pr_graph_ok": claimed})
        assert parse_agent_output(raw, "f").pr_graph_ok is None

    def test_model_supplied_value_dropped_on_unparsable_fallback_too(self):
        assert parse_agent_output("no json", "f").pr_graph_ok is None

    def test_old_serialized_finding_still_loads(self):
        old = {
            "finding_id": "f", "verdict": "safe", "confidence": 0.5,
            "evidence": [{"type": "code", "file": "a.py", "lines": [1, 1], "content": "x"}],
            "evidence_valid": True, "evidence_issues": [],
        }
        finding = AgentFinding.model_validate(old)
        assert finding.pr_graph_ok is None
        assert finding.evidence[0].snapshot is None

    def test_finding_dump_carries_new_keys(self):
        dumped = AgentFinding(
            finding_id="f", evidence=[EvidenceItem(file="a.py")]
        ).model_dump()
        assert dumped["pr_graph_ok"] is None
        assert dumped["evidence"][0]["snapshot"] is None
        assert dumped["evidence"][0]["snapshot_conflict"] is False


class TestReviewMetadataGraphFields:
    def test_defaults_permit_old_records(self):
        meta = ReviewMetadata(repo="r", base="main", pr="pr", mode="lgtm")
        assert meta.graph_state is None
        assert meta.graph_index_seconds is None
        assert meta.base_sha == ""
        assert meta.pr_sha == ""

    def test_fields_carry_values(self):
        meta = ReviewMetadata(
            graph_state="degraded:pr:timeout",
            graph_index_seconds=1.23,
            base_sha="a" * 40,
            pr_sha="b" * 40,
        )
        assert (meta.graph_state, meta.graph_index_seconds) == ("degraded:pr:timeout", 1.23)
        assert (meta.base_sha, meta.pr_sha) == ("a" * 40, "b" * 40)

    def test_json_review_block_defaults(self):
        review = ReportBuilder([], ReviewMetadata(repo="r", base="m", pr="p")).build_json()["review"]
        assert review["graph_state"] is None
        assert review["graph_index_seconds"] is None
        assert review["base_sha"] == ""
        assert review["pr_sha"] == ""

    def test_json_review_block_carries_values_and_original_refs(self):
        meta = ReviewMetadata(
            repo="r", base="main", pr="feature", graph_state="ok",
            graph_index_seconds=0.0, base_sha="a" * 40, pr_sha="b" * 40,
        )
        review = ReportBuilder([], meta).build_json()["review"]
        assert review["base"] == "main" and review["pr"] == "feature"
        assert review["graph_state"] == "ok"
        assert review["graph_index_seconds"] == 0.0
        assert review["base_sha"] == "a" * 40
        assert review["pr_sha"] == "b" * 40

    def test_coverage_is_null_by_default(self):
        assert ReviewMetadata().coverage is None
        review = ReportBuilder([], ReviewMetadata(repo="r", base="m", pr="p")).build_json()["review"]
        assert "coverage" in review
        assert review["coverage"] is None

    def test_json_review_block_carries_supplied_coverage(self):
        coverage = {"sections_total": 4, "sections_reviewed": 3}
        review = ReportBuilder([], ReviewMetadata(repo="r", coverage=coverage)).build_json()["review"]
        assert review["coverage"] == coverage


def _parse_evidence(*entries) -> list[EvidenceItem]:
    raw = json.dumps({"verdict": "safe", "confidence": 0.5, "evidence": list(entries)})
    return parse_agent_output(raw, "f").evidence


class TestEvidenceAliasParsing:
    def test_range_alias_sets_file_lines_and_label(self):
        (item,) = _parse_evidence({"type": "code", "file": "src/app.py:L3-L5 @pr", "content": "x"})
        assert (item.file, item.lines, item.snapshot) == ("src/app.py", [3, 5], "pr")
        assert item.snapshot_conflict is False

    def test_base_alias(self):
        (item,) = _parse_evidence({"type": "code", "file": "app.py:L10-L12 @base", "content": "x"})
        assert (item.file, item.lines, item.snapshot) == ("app.py", [10, 12], "base")

    def test_single_line_alias(self):
        (item,) = _parse_evidence({"type": "code", "file": "app.py:L5 @pr", "content": "x"})
        assert (item.file, item.lines, item.snapshot) == ("app.py", [5, 5], "pr")

    def test_path_only_alias_has_no_range(self):
        (item,) = _parse_evidence({"type": "code", "file": "app.py @pr", "content": "x"})
        assert (item.file, item.lines, item.snapshot) == ("app.py", None, "pr")

    def test_explicit_lines_win_over_alias_range(self):
        (item,) = _parse_evidence(
            {"type": "code", "file": "app.py:L3-L5 @pr", "lines": [7, 9], "content": "x"}
        )
        assert item.lines == [7, 9]
        assert item.file == "app.py"
        assert item.snapshot == "pr"

    def test_agreeing_structured_snapshot_and_alias_have_no_conflict(self):
        (item,) = _parse_evidence(
            {"type": "code", "file": "app.py:L1-L2 @pr", "snapshot": " PR ", "content": "x"}
        )
        assert (item.snapshot, item.snapshot_conflict) == ("pr", False)

    @pytest.mark.parametrize("structured,alias", [("base", "pr"), ("pr", "base")])
    def test_field_and_alias_disagreement_sets_conflict(self, structured, alias):
        (item,) = _parse_evidence(
            {"type": "code", "file": f"app.py:L1-L2 @{alias}", "snapshot": structured, "content": "x"}
        )
        assert item.snapshot_conflict is True

    def test_plain_path_is_untouched_and_unlabelled(self):
        (item,) = _parse_evidence({"type": "code", "file": "app.py", "lines": [1, 2], "content": "x"})
        assert (item.file, item.lines, item.snapshot, item.snapshot_conflict) == (
            "app.py", [1, 2], None, False,
        )

    def test_supplied_sha_is_never_used_as_label(self):
        (item,) = _parse_evidence(
            {"type": "code", "file": "app.py", "snapshot": "a" * 40, "content": "x"}
        )
        assert item.snapshot is None
        assert item.snapshot_conflict is True


class TestToolFailureEvidenceDropped:
    @pytest.mark.parametrize(
        "content",
        [
            "[CODEGRAPH snapshot=pr sha=" + "a" * 40 + ' status=ok query="x"]\nbody',
            "[READ snapshot=base sha=" + "a" * 40 + " path=app.py lines=1-3]\n1: x",
            "[GREP snapshot=pr sha=" + "a" * 40 + ' pattern="x"]',
            "ERROR: file 'app.py' not present in pr snapshot @" + "a" * 40 + ".",
            "stuff status=unavailable reason=timeout more",
            "ERROR: tool call budget exhausted",
            "the tool call budget exhausted earlier",
            "  \n[READ snapshot=pr path=app.py]",
            "\n ERROR: boom",
        ],
    )
    def test_envelope_or_failure_content_is_dropped(self, content):
        evidence = _parse_evidence(
            {"type": "code", "file": "app.py", "lines": [1, 1], "content": content}
        )
        assert evidence == []

    @pytest.mark.parametrize(
        "content",
        [
            "[reader for r in rs]",
            "Error: x",
            "error: x",
            "[readme]",
            "[Grep x",
            "[codegraph_nodes]",
            "x = 'Tool Call Budget Exhausted'",
            "status=Unavailable",
        ],
    )
    def test_drop_rule_is_case_exact_so_lookalike_code_is_kept(self, content):
        evidence = _parse_evidence(
            {"type": "code", "file": "app.py", "lines": [1, 1], "content": content}
        )
        assert [e.content for e in evidence] == [content]

    def test_other_evidence_survives_a_dropped_item(self):
        evidence = _parse_evidence(
            {"type": "code", "file": "app.py", "content": "ERROR: boom"},
            {"type": "code", "file": "app.py", "lines": [1, 1], "content": "real code"},
        )
        assert [e.content for e in evidence] == ["real code"]

    def test_defensive_fallbacks_are_preserved(self):
        evidence = _parse_evidence(
            "not a dict",
            {"file": "a.py", "lines": 4, "content": "x"},
            {"source": "policy.md", "type": "bogus", "content": "p"},
        )
        assert [(e.type, e.lines) for e in evidence] == [("code", [4, 4]), ("policy", None)]
        assert parse_agent_output("no json at all", "f").verdict == "insufficient_evidence"


UNCHANGED = (
    "import os\n"
    "def stable(value):\n"
    "    cleaned = value.strip()\n"
    "    return cleaned.upper()\n"
    "\n"
    "STABLE_LIMIT = 100\n"
)
SHIFTED_BASE = (
    "import os\n"
    "def target(arg):\n"
    "    legacy_helper(config, retries=3, verbose=True)\n"
    "    return compute(arg)\n"
)
SHIFTED_PR = (
    "import os\n"
    "import sys\n"
    "import json\n"
    "def target(arg):\n"
    "    return compute(arg)\n"
)
DELETED = "def removed():\n    return 'gone'\n"
ADDED = "def brand_new(request):\n    token = request.args['token']\n    return token\n"

CAP_MARKER = (
    "[LGTM: verdict downgraded from vulnerable to possible. The PR graph was unavailable "
    "for this finding and no cited evidence validated against the PR snapshot or the diff.]"
)


def _run_git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return done.stdout


@pytest.fixture(scope="module")
def snap(tmp_path_factory):
    """Committed base/pr snapshots (added, deleted, shifted, unchanged) under a dirty working tree."""
    repo = tmp_path_factory.mktemp("snaprepo")
    _run_git(repo, "init", "-q", "-b", "main")
    _run_git(repo, "config", "user.email", "t@t.local")
    _run_git(repo, "config", "user.name", "T")
    _run_git(repo, "config", "commit.gpgsign", "false")
    _run_git(repo, "config", "core.autocrlf", "false")
    (repo / "unchanged.py").write_text(UNCHANGED, encoding="utf-8")
    (repo / "shifted.py").write_text(SHIFTED_BASE, encoding="utf-8")
    (repo / "deleted.py").write_text(DELETED, encoding="utf-8")
    (repo / "policy.md").write_text(
        "# Policy\n\nAll SQL must use bound parameters.\n", encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "base")
    base = _run_git(repo, "rev-parse", "HEAD").strip()
    _run_git(repo, "checkout", "-q", "-b", "pr")
    (repo / "shifted.py").write_text(SHIFTED_PR, encoding="utf-8")
    (repo / "added.py").write_text(ADDED, encoding="utf-8")
    _run_git(repo, "rm", "-q", "deleted.py")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "pr")
    pr = _run_git(repo, "rev-parse", "HEAD").strip()
    _run_git(repo, "checkout", "-q", "main")
    (repo / "unchanged.py").write_text(
        UNCHANGED + "WORKTREE_ONLY_LINE = 'dirty-tree-marker'\n", encoding="utf-8"
    )
    (repo / "shifted.py").write_text(
        SHIFTED_BASE + "    dirty_only_call(secret_token_value)\n", encoding="utf-8"
    )
    (repo / "added.py").write_text(ADDED, encoding="utf-8")
    (repo / "untracked.py").write_text("def only_in_tree():\n    return 1\n", encoding="utf-8")
    return SimpleNamespace(
        repo=repo, shas={"base": base, "pr": pr}, diffs=get_pr_diff(repo, base, pr)
    )


def _validator(snap, shas=None) -> EvidenceValidator:
    return EvidenceValidator(snap.repo, "main", snap.diffs, shas=shas or snap.shas)


def _item(file, lines, content, snapshot, **extra) -> EvidenceItem:
    return EvidenceItem(
        type="code", file=file, lines=lines, content=content, snapshot=snapshot, **extra
    )


def _check(validator, *items, verdict="possible", pr_graph_ok=None, explanation="Because."):
    finding = AgentFinding(
        finding_id="f", verdict=verdict, confidence=0.7, explanation=explanation,
        evidence=list(items), pr_graph_ok=pr_graph_ok,
    )
    return validator.validate_all([finding])[0]


class TestStrictLabelledValidation:
    @pytest.mark.parametrize(
        "item",
        [
            _item("added.py", [2, 3], "token = request.args['token']\nreturn token", "pr"),
            _item("shifted.py", [4, 5], "def target(arg):\n    return compute(arg)", "pr"),
            _item("shifted.py", [2, 4], "legacy_helper(config, retries=3, verbose=True)", "base"),
            _item("deleted.py", [1, 2], "def removed():   return 'gone'", "base"),
            _item("unchanged.py", [2, 4], "cleaned = value.strip()", "base"),
            _item("unchanged.py", [2, 4], "cleaned = value.strip()", "pr"),
            _item("unchanged.py", None, "STABLE_LIMIT = 100", "pr"),
        ],
        ids=["added-pr", "shifted-pr", "shifted-base", "deleted-base", "unchanged-base",
             "unchanged-pr", "no-range"],
    )
    def test_item_cited_at_its_own_snapshot_is_valid(self, snap, item):
        finding = _check(_validator(snap), item)
        assert finding.evidence_issues == []
        assert finding.evidence_valid is True

    @pytest.mark.parametrize(
        "file,label",
        [("added.py", "base"), ("deleted.py", "pr"), ("untracked.py", "base"),
         ("untracked.py", "pr"), ("ghost.py", "pr")],
    )
    def test_file_missing_at_label_is_rejected_even_when_in_working_tree(self, snap, file, label):
        finding = _check(_validator(snap), _item(file, [1, 1], "x", label))
        assert finding.evidence_issues == [f"cited file does not exist at {label} snapshot"]
        assert finding.evidence_valid is False

    def test_dirty_working_tree_lines_are_out_of_range(self, snap):
        finding = _check(
            _validator(snap),
            _item("unchanged.py", [1, 7], "WORKTREE_ONLY_LINE = 'dirty-tree-marker'", "base"),
        )
        assert finding.evidence_valid is False
        assert finding.evidence_issues == [
            "cited lines 1-7 out of range for unchanged.py at base snapshot (6 lines)"
        ]

    def test_dirty_working_tree_snippet_is_not_found(self, snap):
        finding = _check(
            _validator(snap),
            _item("shifted.py", [1, 4], "dirty_only_call(secret_token_value)", "base"),
        )
        assert finding.evidence_valid is False
        assert len(finding.evidence_issues) == 1
        assert finding.evidence_issues[0].startswith(
            "cited code snippet not found in shifted.py at base snapshot: "
        )

    def test_snippet_from_other_snapshot_is_not_found(self, snap):
        legacy = "legacy_helper(config, retries=3, verbose=True)"
        finding = _check(_validator(snap), _item("shifted.py", [2, 5], legacy, "pr"))
        assert finding.evidence_issues == [
            f"cited code snippet not found in shifted.py at pr snapshot: {legacy!r}"
        ]
        assert finding.evidence_valid is False

    def test_snippet_message_shows_first_80_characters(self, snap):
        content = "zq_unrelated_token_" * 10
        finding = _check(_validator(snap), _item("unchanged.py", [1, 2], content, "base"))
        assert finding.evidence_issues == [
            f"cited code snippet not found in unchanged.py at base snapshot: {content[:80]!r}"
        ]

    def test_line_numbers_from_the_other_snapshot_do_not_fit(self, snap):
        finding = _check(
            _validator(snap), _item("shifted.py", [4, 5], "return compute(arg)", "base")
        )
        assert finding.evidence_issues == [
            "cited lines 4-5 out of range for shifted.py at base snapshot (4 lines)"
        ]

    @pytest.mark.parametrize("lines", [[1, 7], [7, 7], [5, 50]])
    def test_range_beyond_end_has_no_slack(self, snap, lines):
        finding = _check(
            _validator(snap), _item("unchanged.py", lines, "STABLE_LIMIT = 100", "base")
        )
        assert finding.evidence_issues == [
            f"cited lines {lines[0]}-{lines[1]} out of range for unchanged.py "
            "at base snapshot (6 lines)"
        ]

    @pytest.mark.parametrize("lines", [[0, 2], [-3, 2], [5, 3], [0, 0]])
    def test_range_must_be_ordered_positive_integers(self, snap, lines):
        finding = _check(
            _validator(snap), _item("unchanged.py", lines, "STABLE_LIMIT = 100", "base")
        )
        assert finding.evidence_issues == [
            "invalid cited line range for unchanged.py at base snapshot"
        ]
        assert finding.evidence_valid is False

    @pytest.mark.parametrize("lines", [[5], [1, 2, 3], []])
    def test_range_with_wrong_arity_is_invalid_and_never_raises(self, snap, lines):
        bad = _item("unchanged.py", lines, "STABLE_LIMIT = 100", "base")
        good = _item("unchanged.py", [6, 6], "STABLE_LIMIT = 100", "base")
        finding = _check(_validator(snap), bad)
        assert finding.evidence_valid is False
        assert finding.evidence_issues == [
            "invalid cited line range for unchanged.py at base snapshot"
        ]
        assert _check(_validator(snap), bad, good).evidence_valid is False

    def test_snippet_outside_cited_range_is_accepted_when_in_file(self, snap):
        finding = _check(
            _validator(snap), _item("unchanged.py", [1, 2], "STABLE_LIMIT = 100", "base")
        )
        assert finding.evidence_issues == []
        assert finding.evidence_valid is True

    @pytest.mark.parametrize(
        "path",
        ["../unchanged.py", "../../etc/passwd", "/unchanged.py", "/etc/passwd",
         "C:/Windows/win.ini", "C:\\Windows\\win.ini", "sub\\..\\unchanged.py",
         "unchanged.py:1-2", "unchanged.py\\"],
    )
    @pytest.mark.parametrize("label", ["base", "pr"])
    def test_unsafe_labelled_paths_are_rejected_as_missing(self, snap, path, label):
        finding = _check(_validator(snap), _item(path, [1, 1], "import os", label))
        assert finding.evidence_issues == [f"cited file does not exist at {label} snapshot"]
        assert finding.evidence_valid is False

    @pytest.mark.parametrize("failure", ["timeout", "oserror", "nonzero"])
    def test_git_failure_reading_blob_gives_issue_without_leaking_stderr(
        self, snap, monkeypatch, failure
    ):
        secret = "fatal: SECRET-STDERR-TEXT /private/path"

        def fake_run(cmd, *args, **kwargs):
            if failure == "timeout":
                raise subprocess.TimeoutExpired(cmd, 1, stderr=secret)
            if failure == "oserror":
                raise OSError(secret)
            return subprocess.CompletedProcess(cmd, 128, stdout="", stderr=secret)

        monkeypatch.setattr("lgtm.agents.tools.subprocess.run", fake_run)
        finding = _check(
            _validator(snap), _item("unchanged.py", [1, 2], "import os", "base")
        )
        assert finding.evidence_valid is False
        assert len(finding.evidence_issues) == 1
        assert "SECRET-STDERR-TEXT" not in finding.evidence_issues[0]
        assert "/private/path" not in finding.evidence_issues[0]

    def test_crlf_committed_file_still_matches_normalized_snippet(self, tmp_path):
        _run_git(tmp_path, "init", "-q", "-b", "main")
        _run_git(tmp_path, "config", "user.email", "t@t.local")
        _run_git(tmp_path, "config", "user.name", "T")
        _run_git(tmp_path, "config", "commit.gpgsign", "false")
        _run_git(tmp_path, "config", "core.autocrlf", "false")
        (tmp_path / "win.py").write_bytes(
            b"def f(x):\r\n    y = x.strip()\r\n    return y\r\n"
        )
        _run_git(tmp_path, "add", "-A")
        _run_git(tmp_path, "commit", "-q", "-m", "crlf")
        sha = _run_git(tmp_path, "rev-parse", "HEAD").strip()
        validator = EvidenceValidator(tmp_path, "main", [], shas={"base": sha, "pr": sha})
        finding = _check(
            validator, _item("win.py", [1, 3], "y = x.strip()\nreturn y", "base")
        )
        assert finding.evidence_issues == []
        assert finding.evidence_valid is True

    def test_whole_file_range_is_in_bounds(self, snap):
        finding = _check(
            _validator(snap), _item("unchanged.py", [1, 6], "STABLE_LIMIT = 100", "base")
        )
        assert finding.evidence_issues == []

    def test_labelled_code_evidence_without_file_is_reported(self, snap):
        finding = _check(
            _validator(snap), EvidenceItem(type="code", file=None, content="x", snapshot="pr")
        )
        assert finding.evidence_issues == ["code evidence has no file path"]

    def test_label_without_frozen_sha_is_unavailable(self, snap):
        only_base = _validator(snap, {"base": snap.shas["base"]})
        finding = _check(only_base, _item("added.py", [1, 1], "def brand_new(request):", "pr"))
        assert finding.evidence_issues == ["snapshot 'pr' is unavailable for this review"]
        assert _check(
            only_base, _item("deleted.py", [1, 1], "def removed():", "base")
        ).evidence_issues == []

    def test_label_missing_from_given_shas_is_unavailable(self, snap):
        validator = EvidenceValidator(
            snap.repo, "main", snap.diffs, shas={"base": snap.shas["base"]}
        )
        finding = _check(validator, _item("added.py", [1, 1], "def brand_new(request):", "pr"))
        assert finding.evidence_issues == ["snapshot 'pr' is unavailable for this review"]

    @pytest.mark.parametrize(
        "file,lines,content",
        [
            ("added.py", [1, 1], "def brand_new(request):"),
            ("untracked.py", [1, 2], "def only_in_tree():"),
            ("ghost.py", [1, 1], "x"),
            ("unchanged.py", [1, 6 + 50], "STABLE_LIMIT = 100"),
        ],
    )
    def test_validator_without_shas_ignores_labels_and_conflicts(self, snap, file, lines, content):
        legacy = EvidenceValidator(snap.repo, "main", snap.diffs)
        plain = _check(legacy, _item(file, lines, content, None))
        labelled = _check(legacy, _item(file, lines, content, "pr"))
        conflicted = _check(legacy, _item(file, lines, content, "base", snapshot_conflict=True))
        assert labelled.evidence_issues == plain.evidence_issues
        assert conflicted.evidence_issues == plain.evidence_issues
        assert labelled.evidence_valid == conflicted.evidence_valid == plain.evidence_valid

    def test_unknown_supplied_label_reports_raw_value_and_never_validates(self, snap):
        (item,) = _parse_evidence(
            {"type": "code", "file": "unchanged.py", "lines": [1, 2], "snapshot": "deadbeef",
             "content": "def stable(value):"}
        )
        finding = _check(_validator(snap), item)
        assert "unknown snapshot label: 'deadbeef'" in finding.evidence_issues
        assert finding.evidence_valid is False

    def test_supplied_sha_is_reported_not_resolved(self, snap):
        sha = snap.shas["pr"]
        (item,) = _parse_evidence(
            {"type": "code", "file": "added.py", "lines": [1, 1], "snapshot": sha,
             "content": "def brand_new(request):"}
        )
        finding = _check(_validator(snap), item)
        assert f"unknown snapshot label: {sha!r}" in finding.evidence_issues
        assert finding.evidence_valid is False

    def test_field_alias_disagreement_is_reported_and_invalid(self, snap):
        (item,) = _parse_evidence(
            {"type": "code", "file": "unchanged.py:L2-L2 @pr", "snapshot": "base",
             "content": "def stable(value):"}
        )
        finding = _check(_validator(snap), item)
        assert "evidence snapshot field and @alias disagree" in finding.evidence_issues
        assert finding.evidence_valid is False

    def test_alias_label_is_validated_strictly(self, snap):
        (item,) = _parse_evidence(
            {"type": "code", "file": "added.py:L1-L1 @base", "content": "def brand_new(request):"}
        )
        finding = _check(_validator(snap), item)
        assert finding.evidence_issues == ["cited file does not exist at base snapshot"]

    def test_policy_evidence_ignores_snapshot_and_conflict(self, snap):
        (conflicted,) = _parse_evidence(
            {"type": "policy", "source": "policy.md", "snapshot": "deadbeef",
             "content": "All SQL must use bound parameters."}
        )
        labelled = EvidenceItem(
            type="policy", source="policy.md", snapshot="pr",
            content="All SQL must use bound parameters.",
        )
        finding = _check(_validator(snap), conflicted, labelled)
        assert finding.evidence_issues == []
        assert finding.evidence_valid is True

    def test_unlabelled_items_keep_legacy_fallbacks_with_frozen_shas(self, snap):
        validator = _validator(snap)
        in_tree = _check(validator, _item("untracked.py", [1, 2], "def only_in_tree():", None))
        assert in_tree.evidence_issues == []
        slack = _check(validator, _item("unchanged.py", [1, 6 + 50], "STABLE_LIMIT = 100", None))
        assert slack.evidence_issues == []
        missing = _check(validator, _item("ghost.py", [1, 1], "x", None))
        assert missing.evidence_issues == ["cited file does not exist: ghost.py"]

    def test_unlabelled_locator_suffix_still_resolves(self, snap):
        finding = _check(
            _validator(snap), _item("unchanged.py:2-4", None, "cleaned = value.strip()", None)
        )
        assert finding.evidence_issues == []


def _evidence_kinds():
    """Name -> (items, exempts the vulnerable verdict from the cap)."""
    return {
        "none": ([], False),
        "valid-pr": ([_item("added.py", [1, 3], "return token", "pr")], True),
        "valid-base": ([_item("deleted.py", [1, 2], "def removed():", "base")], False),
        "valid-policy": (
            [EvidenceItem(type="policy", source="policy.md", content="bound parameters")], False,
        ),
        "unlabelled-in-diff": (
            [_item("added.py", [1, 3], "token = request.args['token']", None)], True,
        ),
        "unlabelled-not-in-diff": (
            [_item("unchanged.py", [2, 4], "cleaned = value.strip()", None)], False,
        ),
        "invalid-pr": (
            [_item("added.py", [1, 3], "os.system('rm -rf /') totally invented", "pr")], False,
        ),
        "pr-label-wrong-snapshot": (
            [_item("deleted.py", [1, 2], "def removed():", "pr")], False,
        ),
        "valid-pr-empty-content": ([_item("added.py", [1, 3], "", "pr")], False),
        "valid-pr-plus-invalid-other": (
            [_item("added.py", [1, 3], "return token", "pr"),
             _item("ghost.py", [1, 1], "x", "base")],
            True,
        ),
        "invalid-other-then-valid-pr": (
            [_item("ghost.py", [1, 1], "x", None),
             _item("added.py", [1, 3], "return token", "pr")],
            True,
        ),
    }


KINDS = list(_evidence_kinds())


class TestPrGroundingCap:
    @pytest.mark.parametrize("kind", KINDS)
    @pytest.mark.parametrize("pr_graph_ok", [True, False, None])
    @pytest.mark.parametrize(
        "verdict", ["vulnerable", "safe", "possible", "insufficient_evidence"]
    )
    def test_downgrade_only_when_graph_down_vulnerable_and_no_pr_or_diff_evidence(
        self, snap, verdict, pr_graph_ok, kind
    ):
        items, exempt = _evidence_kinds()[kind]
        uncapped = _check(_validator(snap), *_evidence_kinds()[kind][0], verdict=verdict)
        finding = _check(
            _validator(snap), *items,
            verdict=verdict, pr_graph_ok=pr_graph_ok, explanation="Original explanation.",
        )
        should_cap = pr_graph_ok is False and verdict == "vulnerable" and not exempt
        assert finding.confidence == 0.7
        assert finding.evidence_valid == uncapped.evidence_valid
        assert finding.evidence_issues == uncapped.evidence_issues
        if should_cap:
            assert finding.verdict == "possible"
            assert finding.explanation == "Original explanation.\n\n" + CAP_MARKER
        else:
            assert finding.verdict == verdict
            assert finding.explanation == "Original explanation."

    def test_valid_pr_item_exempts_while_other_items_issues_are_still_reported(self, snap):
        items, _ = _evidence_kinds()["valid-pr-plus-invalid-other"]
        finding = _check(_validator(snap), *items, verdict="vulnerable", pr_graph_ok=False)
        assert finding.verdict == "vulnerable"
        assert finding.evidence_valid is False
        assert finding.evidence_issues == ["cited file does not exist at base snapshot"]

    def test_marker_is_appended_once_across_repeated_validation(self, snap):
        items, _ = _evidence_kinds()["valid-base"]
        validator = _validator(snap)
        finding = _check(validator, *items, verdict="vulnerable", pr_graph_ok=False)
        validator.validate_all([finding])
        assert finding.verdict == "possible"
        assert finding.explanation.count(CAP_MARKER) == 1

    def test_cap_keeps_invalid_evidence_flags(self, snap):
        items, _ = _evidence_kinds()["invalid-pr"]
        finding = _check(_validator(snap), *items, verdict="vulnerable", pr_graph_ok=False)
        assert finding.verdict == "possible"
        assert finding.evidence_valid is False
        assert len(finding.evidence_issues) == 1
