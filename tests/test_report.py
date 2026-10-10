"""Tests for the report builder."""

from __future__ import annotations

import json

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.reporting.report_builder import ReportBuilder, ReviewMetadata


def sample_findings() -> list[AgentFinding]:
    return [
        AgentFinding(
            finding_id="safe-1",
            verdict="safe",
            confidence=0.8,
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
            confidence=0.95,
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
            confidence=0.4,
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
        model="qwen2.5:7b", duration_seconds=12.3,
        semgrep_findings_total=5, semgrep_findings_in_diff=2,
        endpoints_reviewed=1,
    )


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


class TestWrite:
    def test_writes_both_files(self, tmp_path):
        builder = ReportBuilder(sample_findings(), meta())
        json_path, md_path = builder.write(tmp_path / "out")
        assert json_path.is_file() and md_path.is_file()
        parsed = json.loads(json_path.read_text())
        assert parsed["stats"]["total_findings"] == 3
