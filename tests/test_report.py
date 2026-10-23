"""Tests for the report builder."""

from __future__ import annotations

import json
import re

import pytest

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.config import LGTMConfig
from lgtm.reporting.report_builder import ReportBuilder, ReviewMetadata


def sample_findings() -> list[AgentFinding]:
    return [
        AgentFinding(
            finding_id="unsup-1", supported=False, provenance_confidence=0.2, judged=True,
            cwe_id="CWE-89", explanation="Parameterized query.", category="sqli",
            agent="sast_triage", file="app.py", line=10,
        ),
        AgentFinding(
            finding_id="sup-1", supported=True, provenance_confidence=0.9, judged=True,
            cwe_id="CWE-639", explanation="Missing ownership check.",
            suggested_fix="Call is_owner_or_admin before returning the order.",
            category="authz", agent="authz_reviewer", file="routes/orders.py", line=55,
            evidence=[
                EvidenceItem(type="code", file="routes/orders.py", lines=[55, 60], content="return jsonify(order)"),
                EvidenceItem(type="policy", source="security-policy.md", content="verify ownership"),
            ],
        ),
        AgentFinding(
            finding_id="nj-1", cwe_id="CWE-89", explanation="Maybe.", category="sqli",
            agent="sast_triage", file="app.py", line=1, not_judged_reason="judge-error",
        ),
    ]


def meta() -> ReviewMetadata:
    return ReviewMetadata(
        repo="/tmp/repo", base="main", pr="feature", mode="lgtm",
        model="qwen2.5-coder:7b", duration_seconds=12.3,
        semgrep_findings_total=5, semgrep_findings_in_diff=2,
    )


NEW_CONFIG_DEFAULTS = {
    "investigator_max_tool_calls": 12,
    "investigator_max_iterations": 16,
    "investigator_diff_chars": 30000,
    "investigator_max_sections": 12,
    "section_max_chars": 12000,
    "max_sections": 24,
}


class TestSectionConfig:
    @pytest.mark.parametrize(("field", "default"), NEW_CONFIG_DEFAULTS.items())
    def test_default_value(self, field, default):
        assert getattr(LGTMConfig(), field) == default

    def test_max_tool_calls_default_is_unchanged(self):
        assert LGTMConfig().max_tool_calls == 5

    @pytest.mark.parametrize("value", [0, -1])
    @pytest.mark.parametrize("field", NEW_CONFIG_DEFAULTS)
    def test_non_positive_value_is_rejected(self, field, value):
        with pytest.raises(ValueError) as exc:
            LGTMConfig(**{field: value})
        assert str(exc.value) == f"{field} must be positive"

    @pytest.mark.parametrize("field", NEW_CONFIG_DEFAULTS)
    def test_value_of_one_is_accepted(self, field):
        assert getattr(LGTMConfig(**{field: 1}), field) == 1


class TestJsonReport:
    def test_structure_and_stats(self):
        payload = ReportBuilder(sample_findings(), meta()).build_json()
        assert payload["tool"] == "lgtm"
        stats = payload["stats"]
        assert stats["total_findings"] == 3
        assert stats["by_cwe"] == {"CWE-89": 2, "CWE-639": 1}

    def test_findings_are_ordered_supported_first(self):
        payload = ReportBuilder(sample_findings(), meta()).build_json()
        assert payload["findings"][0]["finding_id"] == "sup-1"
        assert payload["findings"][0]["supported"] is True

    def test_raw_response_excluded(self):
        findings = sample_findings()
        findings[0].raw_response = "SECRET INTERNAL"
        payload = ReportBuilder(findings, meta()).build_json()
        assert "SECRET INTERNAL" not in json.dumps(payload)

    def test_json_serializable(self):
        json.dumps(ReportBuilder(sample_findings(), meta()).build_json(), default=str)

    def test_stats_omit_endpoints_reviewed(self):
        payload = ReportBuilder(sample_findings(), meta()).build_json()
        assert "endpoints_reviewed" not in payload["stats"]
        assert payload["stats"]["semgrep_findings_total"] == 5
        assert payload["stats"]["semgrep_findings_in_diff"] == 2
        assert payload["stats"]["sast_error"] is None


class TestMarkdownReport:
    def test_contains_key_sections(self):
        md = ReportBuilder(sample_findings(), meta()).build_markdown()
        assert "# LGTM Security Review Report" in md
        assert "## Summary" in md
        assert "## Findings" in md
        assert "CWE-639" in md
        assert "Missing ownership check." in md
        assert "is_owner_or_admin" in md  # suggested fix shown

    def test_empty_findings(self):
        md = ReportBuilder([], meta()).build_markdown()
        assert "No findings" in md

    def test_summary_keeps_semgrep_sentence_without_endpoint_clause(self):
        md = ReportBuilder(sample_findings(), meta()).build_markdown()
        assert "Semgrep: 2 finding(s) in diff (of 5 total)" in md
        assert "endpoint(s) reviewed for authorization" not in md

    def test_semgrep_failure_is_reported_only_when_present(self):
        assert "Semgrep failed" not in ReportBuilder([], meta()).build_markdown()
        failed = meta()
        failed.sast_error = "semgrep exited 2"
        md = ReportBuilder([], failed).build_markdown()
        assert "- Semgrep failed: semgrep exited 2" in md

    def test_supplied_coverage_adds_no_markdown_text(self):
        coverage = {"sections_total": 3, "sections_reviewed": 2}
        with_coverage = ReviewMetadata(
            repo="/tmp/repo", base="main", pr="feature", mode="lgtm",
            model="qwen2.5-coder:7b", duration_seconds=12.3,
            semgrep_findings_total=5, semgrep_findings_in_diff=2,
            coverage=coverage,
        )
        md = ReportBuilder(sample_findings(), with_coverage).build_markdown()
        assert "sections_total" not in md
        assert "sections_reviewed" not in md


class TestWrite:
    def test_writes_both_files(self, tmp_path):
        builder = ReportBuilder(sample_findings(), meta())
        json_path, md_path = builder.write(tmp_path / "out")
        assert json_path.is_file() and md_path.is_file()
        parsed = json.loads(json_path.read_text())
        assert parsed["stats"]["total_findings"] == 3


BASE_SHA = "a1b2c3d" + "0" * 33
PR_SHA = "e4f5a6b" + "1" * 33


def labelled_meta() -> ReviewMetadata:
    return ReviewMetadata(
        repo="/tmp/repo", base="main", pr="feature", mode="lgtm", model="m",
        graph_state="ok", graph_index_seconds=0.0, base_sha=BASE_SHA, pr_sha=PR_SHA,
    )


def finding_with(*evidence: EvidenceItem) -> AgentFinding:
    return AgentFinding(
        finding_id="f1", category="authz", agent="authz_reviewer",
        file="routes.py", line=3, evidence=list(evidence),
    )


class TestLabelledCitations:
    def test_pr_citation_shows_label_short_sha_file_and_range(self):
        item = EvidenceItem(type="code", file="routes/orders.py", lines=[55, 60], content="x", snapshot="pr")
        md = ReportBuilder([finding_with(item)], labelled_meta()).build_markdown()
        assert re.search(r"\[pr e4f5a6b\]\s*`routes/orders\.py`:55-60", md)
        assert "lines 55-60" not in md

    def test_base_citation_uses_base_sha(self):
        item = EvidenceItem(type="code", file="app.py", lines=[2, 2], content="x", snapshot="base")
        md = ReportBuilder([finding_with(item)], labelled_meta()).build_markdown()
        assert re.search(r"\[base a1b2c3d\]\s*`app\.py`:2-2", md)

    def test_absent_range_is_omitted(self):
        item = EvidenceItem(type="code", file="app.py", content="x", snapshot="pr")
        md = ReportBuilder([finding_with(item)], labelled_meta()).build_markdown()
        assert re.search(r"\[pr e4f5a6b\]\s*`app\.py`(?!:\d)", md)

    def test_label_without_recorded_sha_still_renders_for_old_records(self):
        item = EvidenceItem(type="code", file="app.py", lines=[1, 2], content="x", snapshot="pr")
        old_meta = ReviewMetadata(repo="r", base="main", pr="feature")
        md = ReportBuilder([finding_with(item)], old_meta).build_markdown()
        assert re.search(r"\[pr [^\]]+\]\s*`app\.py`:1-2", md)

    def test_unlabelled_citation_rendering_is_unchanged(self):
        item = EvidenceItem(type="code", file="routes/orders.py", lines=[55, 60], content="x")
        md = ReportBuilder([finding_with(item)], labelled_meta()).build_markdown()
        assert "💻 Code — `routes/orders.py` lines 55-60:" in md
        assert "[pr " not in md and "[base " not in md

    def test_policy_citation_rendering_ignores_snapshot(self):
        item = EvidenceItem(type="policy", source="security-policy.md", content="verify", snapshot="pr")
        md = ReportBuilder([finding_with(item)], labelled_meta()).build_markdown()
        assert "📄 Policy — `security-policy.md`:" in md
        assert "[pr " not in md

    def test_old_serialized_records_still_render(self):
        old = {
            "finding_id": "f", "verdict": "vulnerable", "confidence": 0.9, "file": "a.py", "line": 1,
            "evidence": [{"type": "code", "file": "a.py", "lines": [1, 2], "content": "x"}],
        }
        md = ReportBuilder([AgentFinding.model_validate(old)], ReviewMetadata(repo="r")).build_markdown()
        assert "`a.py` lines 1-2" in md


class TestJsonEvidenceKeys:
    def test_evidence_items_carry_snapshot_and_conflict_additively(self):
        items = [
            EvidenceItem(type="code", file="a.py", lines=[1, 2], content="x", snapshot="pr"),
            EvidenceItem(type="code", file="b.py", content="y", snapshot_conflict=True),
            EvidenceItem(type="code", file="c.py", content="z"),
        ]
        payload = ReportBuilder([finding_with(*items)], labelled_meta()).build_json()
        dumped = payload["findings"][0]["evidence"]
        assert [(e["file"], e["lines"], e["content"]) for e in dumped] == [
            ("a.py", [1, 2], "x"), ("b.py", None, "y"), ("c.py", None, "z"),
        ]
        assert [(e["snapshot"], e["snapshot_conflict"]) for e in dumped] == [
            ("pr", False), (None, True), (None, False),
        ]
        assert payload["findings"][0]["pr_graph_ok"] is None
        assert payload["review"]["base_sha"] == BASE_SHA
        assert payload["review"]["pr_sha"] == PR_SHA


SUPPORTED_WORD = r"(?<!un)supported"
CONFIDENCE_SHOWN = r"0\.73|73\s?%"
REMOVED_REPORT_TEXT = (
    "evidence_valid", "evidence_issues", "evidence_grounded", "evidence_grounding_rate",
    "evidence valid", "evidence issues", "fully grounded", "judge_verdict", "by_verdict",
)


def judged_finding(finding_id: str, supported: bool, severity: str = "", confidence: float = 0.73) -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id, supported=supported, severity=severity,
        provenance_confidence=confidence, judged=True, cwe_id="CWE-639",
        explanation=f"Claim for {finding_id}.", category="authz", agent="authz_reviewer",
        file="routes/orders.py", line=55,
    )


def no_source_finding(finding_id: str = "ns-1") -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id, supported=False, judged=True, unsupported_reason="no-cited-source",
        cwe_id="CWE-639", explanation="Claim without a source.", category="authz",
        agent="authz_reviewer", file="routes/nosource.py", line=3,
    )


def not_judged_finding(finding_id: str = "nj-1", reason: str = "request-too-large") -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id, cwe_id="CWE-639", explanation="Unjudged claim text.",
        category="authz", agent="authz_reviewer", file="routes/unjudged.py", line=7,
        not_judged_reason=reason,
        evidence=[EvidenceItem(type="code", file="routes/unjudged.py", lines=[7, 9], content="return jsonify(order)", snapshot="pr")],
    )


def md_section(md: str, finding_id: str) -> str:
    sections = re.split(r"^### ", md, flags=re.MULTILINE)[1:]
    matching = [s for s in sections if f"`{finding_id}`" in s]
    assert len(matching) == 1, f"{finding_id} must appear in exactly one section"
    return matching[0].lower()


def all_candidates(payload: dict) -> dict[str, dict]:
    found: dict[str, dict] = {}

    def walk(node):
        if isinstance(node, dict):
            if "finding_id" in node:
                found[node["finding_id"]] = node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(payload)
    return found


class TestJudgeResultRendering:
    @pytest.mark.parametrize("severity", ["critical", "medium"])
    def test_markdown_shows_supported_confidence_and_severity(self, severity):
        md = ReportBuilder([judged_finding("j1", True, severity)], meta()).build_markdown()
        section = md_section(md, "j1")
        assert re.search(SUPPORTED_WORD, section)
        assert re.search(CONFIDENCE_SHOWN, section)
        assert severity in section

    @pytest.mark.parametrize(("confidence", "shown"), [(0.0, "0%"), (0.05, "5%"), (0.73, "73%"), (1.0, "100%")])
    def test_markdown_shows_the_findings_own_confidence(self, confidence, shown):
        md = ReportBuilder([judged_finding("j1", True, "low", confidence)], meta()).build_markdown()
        assert re.search(rf"(?<![\d.]){re.escape(shown)}", md_section(md, "j1"))

    def test_markdown_shows_no_severity_without_one(self):
        section = md_section(ReportBuilder([judged_finding("j1", True)], meta()).build_markdown(), "j1")
        assert re.search(CONFIDENCE_SHOWN, section)
        assert "severity" not in section
        assert not re.search(r"\b(critical|high|medium|low)\b", section)

    @pytest.mark.parametrize(("supported", "severity"), [(True, "critical"), (True, ""), (False, "medium")])
    def test_json_carries_supported_confidence_and_severity(self, supported, severity):
        payload = ReportBuilder([judged_finding("j1", supported, severity)], meta()).build_json()
        finding = all_candidates(payload)["j1"]
        assert finding["supported"] is supported
        assert finding["judged"] is True
        assert finding["provenance_confidence"] == 0.73
        assert (finding["severity"] or "") == severity

    def test_json_records_per_citation_pr_grounding(self):
        items = [
            EvidenceItem(type="code", file="a.py", lines=[1, 2], content="x", snapshot="pr", grounded_in_pr=True),
            EvidenceItem(type="code", file="b.py", lines=[1, 2], content="y", snapshot="base", grounded_in_pr=False),
        ]
        finding = judged_finding("j1", True)
        finding.evidence = items

        dumped = all_candidates(ReportBuilder([finding], meta()).build_json())["j1"]["evidence"]

        assert [e["grounded_in_pr"] for e in dumped] == [True, False]

    def test_markdown_shows_whether_each_citation_is_grounded_in_the_pr(self):
        def md_for(grounded):
            item = EvidenceItem(type="code", file="a.py", lines=[1, 2], content="x", snapshot="pr", grounded_in_pr=grounded)
            finding = judged_finding("j1", True)
            finding.evidence = [item]
            return md_section(ReportBuilder([finding], labelled_meta()).build_markdown(), "j1")

        assert md_for(True) != md_for(False)


class TestNotJudgedRendering:
    def test_markdown_marks_not_judged_with_claim_and_citations(self):
        md = ReportBuilder([not_judged_finding()], meta()).build_markdown()
        section = md_section(md, "nj-1")
        assert re.search(r"not[\s_-]judged", section)
        assert "unjudged claim text." in section
        assert re.search(r"\[pr [^\]]+\]\s*`routes/unjudged\.py`:7-9", md)

    def test_markdown_shows_no_supported_value_or_confidence_for_not_judged(self):
        section = md_section(ReportBuilder([not_judged_finding()], meta()).build_markdown(), "nj-1")
        assert not re.search(SUPPORTED_WORD, section)
        assert "unsupported" not in section
        assert not re.search(r"confidence\W{0,6}\d", section)

    def test_markdown_keeps_the_candidate_own_severity_when_it_has_one(self):
        finding = not_judged_finding()
        finding.severity = "medium"
        assert "medium" in md_section(ReportBuilder([finding], meta()).build_markdown(), "nj-1")

    def test_json_marks_not_judged_without_fabricated_judge_outputs(self):
        finding = all_candidates(ReportBuilder([not_judged_finding()], meta()).build_json())["nj-1"]
        assert finding["judged"] is False
        assert finding["supported"] is None
        assert finding["provenance_confidence"] is None
        assert finding["explanation"] == "Unjudged claim text."
        assert finding["evidence"][0]["file"] == "routes/unjudged.py"


class TestNotJudgedReason:
    REASONS = {"nj-big": "request-too-large", "nj-down": "judge-unreachable", "nj-bad": "invalid-answer"}

    def findings(self):
        return [not_judged_finding(fid, reason) for fid, reason in self.REASONS.items()]

    def test_json_shows_the_reason_of_every_not_judged_candidate(self):
        candidates = all_candidates(ReportBuilder(self.findings(), meta()).build_json())
        assert {fid: candidates[fid]["not_judged_reason"] for fid in self.REASONS} == self.REASONS

    def test_markdown_shows_the_reason_of_every_not_judged_candidate(self):
        md = ReportBuilder(self.findings(), meta()).build_markdown()
        for fid, reason in self.REASONS.items():
            assert reason in md_section(md, fid)

    def test_request_too_large_is_shown_only_for_the_over_bound_candidate(self):
        md = ReportBuilder(self.findings(), meta()).build_markdown()
        assert "request-too-large" not in md_section(md, "nj-down")
        assert "request-too-large" not in md_section(md, "nj-bad")

    def test_judged_candidate_shows_no_not_judged_reason(self):
        finding = all_candidates(ReportBuilder([judged_finding("j1", True)], meta()).build_json())["j1"]
        assert not finding["not_judged_reason"]


def mixed_findings() -> list[AgentFinding]:
    return [
        judged_finding("u1", False),
        not_judged_finding("nj-1"),
        judged_finding("s1", True, "high"),
        no_source_finding("ns-1"),
        not_judged_finding("nj-2", "judge-unreachable"),
        judged_finding("s2", True, "low"),
    ]


class TestMixedSupportedUnsupportedNotJudged:
    def test_json_counts_sum_to_the_number_of_candidates(self):
        stats = ReportBuilder(mixed_findings(), meta()).build_json()["stats"]
        assert stats["supported"] == 2
        assert stats["unsupported"] == 2
        assert stats["not_judged"] == 2
        assert stats["supported"] + stats["unsupported"] + stats["not_judged"] == 6

    def test_json_lists_every_candidate_with_its_own_supported_value(self):
        candidates = all_candidates(ReportBuilder(mixed_findings(), meta()).build_json())
        assert set(candidates) == {"u1", "nj-1", "s1", "ns-1", "nj-2", "s2"}
        assert {fid: candidates[fid]["supported"] for fid in candidates} == {
            "u1": False, "nj-1": None, "s1": True, "ns-1": False, "nj-2": None, "s2": True,
        }

    def test_json_lists_supported_candidates_before_the_others(self):
        ids = [f["finding_id"] for f in ReportBuilder(mixed_findings(), meta()).build_json()["findings"]]
        assert {ids[0], ids[1]} == {"s1", "s2"}

    def test_markdown_lists_every_candidate_and_marks_unsupported_ones(self):
        md = ReportBuilder(mixed_findings(), meta()).build_markdown()
        for fid in ("u1", "nj-1", "s1", "ns-1", "nj-2", "s2"):
            assert f"`{fid}`" in md
        assert "unsupported" in md_section(md, "u1")
        assert "unsupported" in md_section(md, "ns-1")
        assert "unsupported" not in md_section(md, "s1")
        assert "unsupported" not in md_section(md, "nj-1")

    def test_markdown_summary_counts_each_group_apart(self):
        md = ReportBuilder(mixed_findings(), meta()).build_markdown()
        summary = md.split("## Findings")[0]
        assert re.search(SUPPORTED_WORD + r"\W+2\b", summary)
        assert re.search(r"unsupported\W+2\b", summary)
        assert re.search(r"not[\s_-]judged\W+2\b", summary, re.IGNORECASE)

    def test_candidate_without_cited_source_is_listed_as_unsupported_with_its_reason(self):
        payload = ReportBuilder([no_source_finding()], meta()).build_json()
        finding = all_candidates(payload)["ns-1"]
        assert finding["supported"] is False
        assert finding["unsupported_reason"] == "no-cited-source"
        assert payload["stats"]["unsupported"] == 1
        assert payload["stats"]["not_judged"] == 0


class TestNoValidatorStatistics:
    def test_json_has_no_validator_flags_or_grounded_findings_count(self):
        payload = ReportBuilder(mixed_findings(), meta()).build_json()
        dumped = json.dumps(payload)
        for text in REMOVED_REPORT_TEXT:
            assert text not in dumped

    def test_markdown_has_no_validator_flags_or_grounded_findings_count(self):
        md = ReportBuilder(mixed_findings(), meta()).build_markdown().lower()
        for text in REMOVED_REPORT_TEXT:
            assert text not in md


class TestAgentErrors:
    @pytest.mark.parametrize("source", ["sec-2", "semgrep.rule:app.py:7"])
    def test_markdown_lists_error_naming_section_or_hit(self, source):
        m = meta()
        m.agent_errors = [{"source": source, "message": "answer could not be parsed after retries"}]
        md = ReportBuilder([judged_finding("v1", True, "high")], m).build_markdown()
        assert source in md
        assert "answer could not be parsed after retries" in md
        assert "`v1`" in md

    def test_json_lists_error_outside_findings_and_does_not_count_it(self):
        m = meta()
        m.agent_errors = [{"source": "sec-2", "message": "answer could not be parsed after retries"}]
        payload = ReportBuilder([judged_finding("v1", True, "high")], m).build_json()
        outside_findings = json.dumps({k: v for k, v in payload.items() if k != "findings"})
        assert "sec-2" in outside_findings
        assert "answer could not be parsed after retries" in outside_findings
        assert payload["stats"]["total_findings"] == 1
        assert [f["finding_id"] for f in payload["findings"]] == ["v1"]
        assert payload["stats"]["supported"] == 1

    def test_error_free_review_reports_no_agent_errors(self):
        builder = ReportBuilder([judged_finding("v1", True, "high")], meta())
        assert "agent errors" not in builder.build_markdown().lower()
        assert not builder.build_json()["review"].get("agent_errors")

    def test_review_with_errors_and_no_findings_is_not_reported_as_a_clean_pass(self):
        m = meta()
        m.agent_errors = [{"source": "sec-2", "message": "answer could not be parsed after retries"}]
        md = ReportBuilder([], m).build_markdown()
        assert "sec-2" in md
        assert "passed all configured checks" not in md
