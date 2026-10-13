"""Tests for the evidence validator."""

from __future__ import annotations

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.diff.git_diff import get_pr_diff
from lgtm.validation.evidence import EvidenceValidator


def make_finding(**kwargs) -> AgentFinding:
    defaults = {"finding_id": "f1", "verdict": "vulnerable", "confidence": 0.9}
    defaults.update(kwargs)
    return AgentFinding(**defaults)


class TestEvidenceValidator:
    def test_valid_code_evidence(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[
                EvidenceItem(
                    type="code",
                    file="app.py",
                    lines=[2, 2],
                    content='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                )
            ]
        )
        validator.validate(finding)
        assert finding.evidence_valid is True
        assert finding.evidence_issues == []

    def test_missing_file_flagged(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[EvidenceItem(type="code", file="ghost.py", content="x")]
        )
        validator.validate(finding)
        assert finding.evidence_valid is False
        assert any("does not exist" in i for i in finding.evidence_issues)

    def test_fabricated_snippet_flagged(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[
                EvidenceItem(
                    type="code",
                    file="app.py",
                    lines=[1, 3],
                    content="os.system('rm -rf /')  # totally made up",
                )
            ]
        )
        validator.validate(finding)
        assert finding.evidence_valid is False
        assert any("snippet not found" in i for i in finding.evidence_issues)

    def test_out_of_range_lines_flagged(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[EvidenceItem(type="code", file="app.py", lines=[500, 600], content="")]
        )
        validator.validate(finding)
        assert finding.evidence_valid is False
        assert any("out of range" in i for i in finding.evidence_issues)

    def test_snippet_from_pr_diff_accepted(self, git_repo):
        diffs = get_pr_diff(git_repo, "main", "pr")
        validator = EvidenceValidator(git_repo, "main", diffs)
        finding = make_finding(
            evidence=[
                EvidenceItem(
                    type="code",
                    file="app.py",
                    content="cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
                )
            ]
        )
        validator.validate(finding)
        assert finding.evidence_valid is True

    def test_policy_evidence_checked(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        good = make_finding(
            evidence=[
                EvidenceItem(
                    type="policy",
                    source="policy.md",
                    content="All SQL must use bound parameters.",
                )
            ]
        )
        validator.validate(good)
        assert good.evidence_valid is True

        bad = make_finding(
            evidence=[
                EvidenceItem(
                    type="policy",
                    source="policy.md",
                    content="Users must rotate passwords every 7 days.",
                )
            ]
        )
        validator.validate(bad)
        assert bad.evidence_valid is False

    def test_missing_policy_doc_flagged(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[EvidenceItem(type="policy", source="imaginary.md", content="rule")]
        )
        validator.validate(finding)
        assert finding.evidence_valid is False

    def test_strong_verdict_without_evidence_flagged(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(verdict="vulnerable", evidence=[])
        validator.validate(finding)
        assert finding.evidence_valid is False
        assert any("without any evidence" in i for i in finding.evidence_issues)

    def test_weak_verdict_without_evidence_ok(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(verdict="insufficient_evidence", evidence=[])
        validator.validate(finding)
        assert finding.evidence_valid is True

    def test_validate_all(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        findings = [make_finding(verdict="possible"), make_finding(verdict="possible")]
        out = validator.validate_all(findings)
        assert len(out) == 2
        assert all(f.evidence_valid is not None for f in out)


class TestValidatorRegressions:
    """False alarms observed in benchmark run 1 (2026-10-10)."""

    def test_snippet_with_elided_line_accepted(self):
        # A near-verbatim snippet that skips one line (ratio ~0.9) used to be
        # rejected because the sliding window stepped past the aligned offset.
        validator = EvidenceValidator.__new__(EvidenceValidator)
        haystack = (
            "from app.auth import require_api_key_scope\n"
            '@orders_bp.route("/report", methods=["GET"])\n'
            '@require_api_key_scope("reports:read")\n'
            "def orders_report():\n"
            '    """Aggregated order report for machine integrations."""\n'
            "    session = get_session()\n"
            "    orders = session.query(Order).all()\n"
            '    return jsonify({"order_count": len(orders), '
            '"revenue": sum(o.total for o in orders)})\n'
        )
        snippet = (
            "def orders_report():\n"
            "    session = get_session()\n"
            "    orders = session.query(Order).all()\n"
            '    return jsonify({"order_count": len(orders), '
            '"revenue": sum(o.total for o in orders)})\n'
        )
        from lgtm.validation.evidence import _normalize

        assert validator._snippet_in_text(snippet, _normalize(haystack))

    def test_locator_suffixes_stripped(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[
                EvidenceItem(type="policy", source="policy.md#section-2",
                             content="Only admins may delete users."),
                EvidenceItem(type="code", file="app.py:get_user",
                             content="def get_user(cursor, user_id):"),
            ]
        )
        validator.validate(finding)
        assert finding.evidence_valid is True, finding.evidence_issues


def test_real_paths_with_colon_or_hash_resolve(git_repo):
    import subprocess

    (git_repo / "docs").mkdir()
    (git_repo / "docs" / "a:b.md").write_text("Rule: admins only.\n", encoding="utf-8")
    (git_repo / "c#.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(git_repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(git_repo), "commit", "-qm", "odd names"], check=True)
    validator = EvidenceValidator(git_repo, "main")
    finding = make_finding(evidence=[
        EvidenceItem(type="policy", source="docs/a:b.md", content="Rule: admins only."),
        EvidenceItem(type="code", file="c#.py", content="x = 1"),
        EvidenceItem(type="code", file="app.py:2:5", content="def get_user(cursor, user_id):"),
    ])
    validator.validate(finding)
    assert finding.evidence_valid is True, finding.evidence_issues


def test_fuzzy_match_is_fast_on_large_files():
    import random
    import time

    from lgtm.validation.evidence import _normalize

    random.seed(0)
    words = ["session", "query", "order", "user", "return", "if", "def", "id"]
    haystack = _normalize("\n".join(
        " ".join(random.choice(words) for _ in range(6)) for _ in range(1000)
    ))
    snippet = " ".join(random.choice(words) for _ in range(140))[:860]
    validator = EvidenceValidator.__new__(EvidenceValidator)
    started = time.monotonic()
    validator._snippet_in_text(snippet, haystack)
    assert time.monotonic() - started < 10  # stride-1 everywhere took ~40s
