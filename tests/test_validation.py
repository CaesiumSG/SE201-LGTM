"""Tests for the evidence validator."""

from __future__ import annotations

import pytest

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.diff.git_diff import get_pr_diff
from lgtm.validation.evidence import EvidenceValidator


def make_finding(**kwargs) -> AgentFinding:
    defaults = {"finding_id": "f1"}
    defaults.update(kwargs)
    return AgentFinding(**defaults)


PR_SNIPPET = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
BASE_SNIPPET = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'


def _frozen_validator(git_repo):
    from tests.conftest import git

    shas = {
        "base": git(git_repo, "rev-parse", "main").strip(),
        "pr": git(git_repo, "rev-parse", "pr").strip(),
    }
    diffs = get_pr_diff(git_repo, shas["base"], shas["pr"])
    return EvidenceValidator(git_repo, "main", diffs, shas=shas)


class TestValidationStageOnlyAnnotatesPrGrounding:
    def test_each_cited_item_records_whether_it_is_grounded_in_the_pr(self, git_repo):
        diffs = get_pr_diff(git_repo, "main", "pr")
        validator = EvidenceValidator(git_repo, "main", diffs)
        finding = make_finding(
            evidence=[
                EvidenceItem(type="code", file="app.py", content=PR_SNIPPET),
                EvidenceItem(type="code", file="app.py", lines=[2, 2], content=BASE_SNIPPET),
                EvidenceItem(type="code", file="ghost.py", content="x"),
            ]
        )

        validator.validate(finding)

        assert [i.grounded_in_pr for i in finding.evidence] == [True, False, False]

    def test_validated_finding_carries_no_validator_flags(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[EvidenceItem(type="code", file="ghost.py", content="fabricated")]
        )

        validator.validate(finding)

        for name in ("evidence_valid", "evidence_issues"):
            assert name not in AgentFinding.model_fields
            assert not hasattr(finding, name)

    def test_validation_stage_leaves_the_kev_verdict_and_severity_unset(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[EvidenceItem(type="code", file="app.py", content=PR_SNIPPET)]
        )
        assert finding.kev_verdict is None and finding.kev_severity is None

        validator.validate_all([finding])

        assert finding.kev_verdict is None and finding.kev_severity is None

    def test_unresolved_citation_is_annotated_not_grounded_and_the_finding_is_kept(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(
            evidence=[EvidenceItem(type="code", file="app.py", lines=[500, 600], content="")]
        )

        out = validator.validate_all([finding])

        assert out == [finding]
        assert finding.evidence[0].grounded_in_pr is False

    @pytest.mark.parametrize("verdict", ["vulnerable", "safe", ""])
    def test_validation_leaves_the_verdict_and_judge_fields_untouched(self, git_repo, verdict):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(verdict=verdict, evidence=[])

        validator.validate(finding)

        assert finding.verdict == verdict
        assert finding.judged is False
        assert finding.supported is None

    def test_candidate_without_evidence_is_validated_and_stays_unjudged(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")
        finding = make_finding(evidence=[])

        validator.validate(finding)

        assert not finding.verdict
        assert finding.judged is False

    def test_validate_all_returns_every_finding(self, git_repo):
        validator = EvidenceValidator(git_repo, "main")

        out = validator.validate_all([make_finding(), make_finding()])

        assert len(out) == 2


class TestReferentialCheckStaysAvailable:
    def test_item_matching_the_pr_snapshot_resolves(self, git_repo):
        validator = _frozen_validator(git_repo)
        item = EvidenceItem(type="code", file="app.py", content=PR_SNIPPET, snapshot="pr")

        assert validator.resolves(item) is True

    def test_missing_file_does_not_resolve(self, git_repo):
        validator = _frozen_validator(git_repo)

        assert validator.resolves(EvidenceItem(type="code", file="ghost.py", content="x", snapshot="pr")) is False

    def test_fabricated_snippet_does_not_resolve(self, git_repo):
        validator = _frozen_validator(git_repo)
        item = EvidenceItem(
            type="code", file="app.py", lines=[1, 3], snapshot="base",
            content="os.system('rm -rf /')  # totally made up",
        )

        assert validator.resolves(item) is False

    def test_out_of_range_lines_do_not_resolve_but_in_range_lines_do(self, git_repo):
        validator = _frozen_validator(git_repo)
        wide = EvidenceItem(type="code", file="app.py", lines=[2, 30], content=BASE_SNIPPET, snapshot="base")
        exact = EvidenceItem(type="code", file="app.py", lines=[2, 2], content=BASE_SNIPPET, snapshot="base")

        assert validator.resolves(wide) is False
        assert validator.resolves(exact) is True

    def test_labelled_working_tree_file_does_not_resolve(self, git_repo):
        (git_repo / "notes.md").write_text("untracked scratch note\n", encoding="utf-8")
        item = EvidenceItem(
            type="code", file="notes.md", lines=[1, 1], content="untracked scratch note", snapshot="base"
        )

        assert _frozen_validator(git_repo).resolves(item) is False

    def test_locator_suffix_on_a_cited_file_is_stripped(self, git_repo):
        item = EvidenceItem(type="code", file="app.py:get_user", content="def get_user(cursor, user_id):")

        code = EvidenceValidator(git_repo, "main").read_cited_code(item)

        assert "def get_user(cursor, user_id):" in code


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
