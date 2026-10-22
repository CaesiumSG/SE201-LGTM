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
            finding_id="safe-1",
            verdict="safe",
            cwe_id="CWE-89",
            explanation="Parameterized query.",
            category="sqli",
            agent="sast_triage",
            file="app.py",
            line=10,
            evidence_valid=True,
        ),
        AgentFinding(
            finding_id="vuln-1",
            verdict="vulnerable",
            cwe_id="CWE-639",
            explanation="Missing ownership check.",
            suggested_fix="Call is_owner_or_admin before returning the order.",
            category="authz",
            agent="authz_reviewer",
            file="routes/orders.py",
            line=55,
            evidence=[
                EvidenceItem(type="code", file="routes/orders.py", lines=[55, 60], content="return jsonify(order)"),
                EvidenceItem(type="policy", source="security-policy.md", content="verify ownership"),
            ],
            evidence_valid=True,
        ),
        AgentFinding(
            finding_id="halluc-1",
            verdict="possible",
            cwe_id="CWE-89",
            explanation="Maybe.",
            category="sqli",
            agent="sast_triage",
            file="app.py",
            line=1,
            evidence_valid=False,
            evidence_issues=["cited file does not exist: fake.py"],
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
        assert stats["by_verdict"] == {"safe": 1, "vulnerable": 1, "possible": 1}
        assert stats["by_cwe"] == {"CWE-89": 2, "CWE-639": 1}
        assert stats["evidence_grounded"] == 2
        assert abs(stats["evidence_grounding_rate"] - 2 / 3) < 0.01

    def test_findings_sorted_vulnerable_first(self):
        payload = ReportBuilder(sample_findings(), meta()).build_json()
        verdicts = [f["verdict"] for f in payload["findings"]]
        assert verdicts == ["vulnerable", "possible", "safe"]

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
        assert "## Evidence Grounding" in md
        assert "## Findings" in md
        assert "CWE-639" in md
        assert "Missing ownership check." in md
        assert "is_owner_or_admin" in md  # suggested fix shown
        assert "cited file does not exist: fake.py" in md  # issues shown

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
        file="routes.py", line=3, evidence=list(evidence), evidence_valid=True,
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
            "evidence_valid": True, "evidence_issues": [],
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


JUDGE_VERDICTS = ["vulnerable", "possible", "safe", "insufficient_evidence"]
CONFIDENCE_SHOWN = r"0\.73|73\s?%"


def judged_finding(finding_id: str, verdict: str, severity: str = "", confidence: float = 0.73) -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id, verdict=verdict, severity=severity,
        provenance_confidence=confidence, judged=True, cwe_id="CWE-639",
        explanation=f"Claim for {finding_id}.", category="authz", agent="authz_reviewer",
        file="routes/orders.py", line=55, evidence_valid=True,
    )


def not_judged_finding(finding_id: str = "nj-1") -> AgentFinding:
    return AgentFinding(
        finding_id=finding_id, cwe_id="CWE-639", explanation="Unjudged claim text.",
        category="authz", agent="authz_reviewer", file="routes/unjudged.py", line=7,
        evidence=[EvidenceItem(type="code", file="routes/unjudged.py", lines=[7, 9], content="return jsonify(order)", snapshot="pr")],
        evidence_valid=False, evidence_issues=["cited line range is outside the file"],
    )


class TestJudgeResultRendering:
    @pytest.mark.parametrize(("verdict", "severity"), [("vulnerable", "critical"), ("possible", "medium")])
    def test_markdown_shows_verdict_confidence_and_severity(self, verdict, severity):
        md = ReportBuilder([judged_finding("j1", verdict, severity)], meta()).build_markdown().lower()
        assert verdict in md
        assert re.search(CONFIDENCE_SHOWN, md)
        assert severity in md

    @pytest.mark.parametrize(("confidence", "shown"), [(0.0, "0%"), (0.05, "5%"), (0.73, "73%"), (1.0, "100%")])
    def test_markdown_shows_the_findings_own_confidence(self, confidence, shown):
        md = ReportBuilder([judged_finding("j1", "possible", "low", confidence)], meta()).build_markdown()
        finding_section = " ".join(re.split(r"^### ", md, flags=re.MULTILINE)[1:])
        assert re.search(rf"(?<![\d.]){re.escape(shown)}", finding_section)

    @pytest.mark.parametrize("verdict", ["safe", "insufficient_evidence"])
    def test_markdown_shows_no_severity_without_one(self, verdict):
        md = ReportBuilder([judged_finding("j1", verdict)], meta()).build_markdown().lower()
        assert verdict in md
        assert re.search(CONFIDENCE_SHOWN, md)
        assert "severity" not in md
        assert not re.search(r"\b(critical|high|medium|low)\b", md)

    @pytest.mark.parametrize(("verdict", "severity"), [("vulnerable", "critical"), ("possible", "medium"), ("safe", "")])
    def test_json_carries_verdict_confidence_and_severity(self, verdict, severity):
        payload = ReportBuilder([judged_finding("j1", verdict, severity)], meta()).build_json()
        finding = payload["findings"][0]
        assert finding["verdict"] == verdict
        assert finding["provenance_confidence"] == 0.73
        assert (finding["severity"] or "") == severity


class TestNotJudgedRendering:
    def test_markdown_marks_not_judged_with_claim_citations_and_grounding(self):
        md = ReportBuilder([not_judged_finding()], meta()).build_markdown()
        assert re.search(r"not[\s_-]judged", md, re.IGNORECASE)
        assert "Unjudged claim text." in md
        assert re.search(r"\[pr [^\]]+\]\s*`routes/unjudged\.py`:7-9", md)
        assert "cited line range is outside the file" in md

    def test_markdown_shows_no_verdict_severity_or_confidence_for_not_judged(self):
        md = ReportBuilder([not_judged_finding()], meta()).build_markdown().lower()
        for verdict in JUDGE_VERDICTS:
            assert verdict not in md
        assert "severity" not in md
        assert not re.search(r"\b(critical|high|medium|low)\b", md)
        assert not re.search(r"confidence\W{0,6}\d", md)

    def test_json_marks_not_judged_without_fabricated_judge_outputs(self):
        finding = ReportBuilder([not_judged_finding()], meta()).build_json()["findings"][0]
        assert finding["judged"] is False
        assert finding["verdict"] in ("", None)
        assert finding["severity"] in ("", None)
        assert finding["provenance_confidence"] is None
        assert finding["explanation"] == "Unjudged claim text."
        assert finding["evidence"][0]["file"] == "routes/unjudged.py"
        assert finding["evidence_issues"] == ["cited line range is outside the file"]


def mixed_findings() -> list[AgentFinding]:
    return [
        judged_finding("s1", "safe"),
        not_judged_finding("nj-1"),
        judged_finding("v1", "vulnerable", "high"),
        judged_finding("p1", "possible", "low"),
        not_judged_finding("nj-2"),
    ]


class TestMixedJudgedAndNotJudged:
    def test_json_counts_each_verdict_and_not_judged_separately_and_sum_to_total(self):
        stats = ReportBuilder(mixed_findings(), meta()).build_json()["stats"]
        assert stats["total_findings"] == 5
        assert stats["by_verdict"].get("vulnerable") == 1
        assert stats["by_verdict"].get("possible") == 1
        assert stats["by_verdict"].get("safe") == 1
        assert stats["not_judged"] == 2
        verdict_total = sum(stats["by_verdict"].get(v, 0) for v in JUDGE_VERDICTS)
        assert verdict_total + stats["not_judged"] == stats["total_findings"]

    def test_json_lists_every_candidate_with_judged_ones_ordered_by_final_verdict(self):
        findings = ReportBuilder(mixed_findings(), meta()).build_json()["findings"]
        assert {f["finding_id"] for f in findings} == {"s1", "nj-1", "v1", "p1", "nj-2"}
        judged_order = [f["verdict"] for f in findings if f["judged"]]
        assert judged_order == ["vulnerable", "possible", "safe"]

    def test_markdown_lists_every_candidate_and_counts_not_judged_apart(self):
        md = ReportBuilder(mixed_findings(), meta()).build_markdown()
        for finding_id in ("s1", "nj-1", "v1", "p1", "nj-2"):
            assert f"`{finding_id}`" in md
        assert re.search(r"not[\s_-]judged\W+2\b", md, re.IGNORECASE)
        for verdict in ("vulnerable", "possible", "safe"):
            assert re.search(rf"{verdict}\W+1\b", md)


class TestAgentErrors:
    @pytest.mark.parametrize("source", ["sec-2", "semgrep.rule:app.py:7"])
    def test_markdown_lists_error_naming_section_or_hit(self, source):
        m = meta()
        m.agent_errors = [{"source": source, "message": "answer could not be parsed after retries"}]
        md = ReportBuilder([judged_finding("v1", "vulnerable", "high")], m).build_markdown()
        assert source in md
        assert "answer could not be parsed after retries" in md
        assert "`v1`" in md

    def test_json_lists_error_outside_findings_and_does_not_count_it(self):
        m = meta()
        m.agent_errors = [{"source": "sec-2", "message": "answer could not be parsed after retries"}]
        payload = ReportBuilder([judged_finding("v1", "vulnerable", "high")], m).build_json()
        outside_findings = json.dumps({k: v for k, v in payload.items() if k != "findings"})
        assert "sec-2" in outside_findings
        assert "answer could not be parsed after retries" in outside_findings
        assert payload["stats"]["total_findings"] == 1
        assert [f["finding_id"] for f in payload["findings"]] == ["v1"]
        assert sum(payload["stats"]["by_verdict"].values()) == 1

    def test_error_free_review_reports_no_agent_errors(self):
        builder = ReportBuilder([judged_finding("v1", "vulnerable", "high")], meta())
        assert "agent errors" not in builder.build_markdown().lower()
        assert not builder.build_json()["review"].get("agent_errors")

    def test_review_with_errors_and_no_findings_is_not_reported_as_a_clean_pass(self):
        m = meta()
        m.agent_errors = [{"source": "sec-2", "message": "answer could not be parsed after retries"}]
        md = ReportBuilder([], m).build_markdown()
        assert "sec-2" in md
        assert "passed all configured checks" not in md
