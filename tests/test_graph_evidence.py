"""Evidence, finding and review-metadata schema fields for graph provenance."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from lgtm.agents.base import AgentFinding, EvidenceItem, parse_agent_output
from lgtm.reporting.report_builder import ReportBuilder, ReviewMetadata


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
