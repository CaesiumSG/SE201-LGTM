"""The base branch's docs are the policy; a PR that changes them is flagged.

A PR could otherwise rewrite security-policy.md to allow what its code does
and be reviewed against its own rules.
"""

from __future__ import annotations

import json

import pytest

from lgtm import pipeline as pipeline_mod
from tests.test_graph_pipeline import (  # noqa: F401 - fixtures
    ScriptedLLM,
    _add_to_pr,
    _git,
    _rev,
    _review,
    isolated_git_config,
    repo,
    semgrep,
)


class _Retriever:
    """Policy index stand-in that says which commit it was built from."""

    commit: str | None = None
    available = True
    queries: list[str] = []

    def __init__(self, *args, **kwargs):
        pass

    def is_available(self):
        return self.available

    def indexed_commit(self):
        return self.commit

    def format_results(self, query, top_k=None):
        type(self).queries.append(query)
        return "policy text"


@pytest.fixture
def retriever(monkeypatch):
    class Fake(_Retriever):
        queries = []

    monkeypatch.setattr(pipeline_mod, "PolicyRetriever", Fake)
    return Fake


class TestPolicyIndexMustMatchBase:
    def test_index_built_from_the_base_commit_is_used(self, repo, semgrep, retriever):
        retriever.commit = _rev(repo, "main")

        result = _review(repo, ScriptedLLM(), graph_enabled=False)

        assert result.meta.policy_index == "ok"

    def test_index_built_from_the_pr_commit_is_not_used(self, repo, semgrep, retriever, caplog):
        pr_sha = _rev(repo, "pr")
        retriever.commit = pr_sha

        result = _review(repo, ScriptedLLM(), graph_enabled=False)

        assert result.meta.policy_index == f"stale:{pr_sha}"
        assert retriever.queries == []
        assert f"lgtm index --repo {repo} --ref {_rev(repo, 'main')}" in caplog.text

    def test_index_without_a_recorded_commit_is_not_used(self, repo, semgrep, retriever):
        retriever.commit = None

        result = _review(repo, ScriptedLLM(), graph_enabled=False)

        assert result.meta.policy_index == "stale:unknown"

    def test_missing_index_is_reported(self, repo, semgrep, retriever):
        retriever.available = False

        result = _review(repo, ScriptedLLM(), graph_enabled=False)

        assert result.meta.policy_index == "missing"

    def test_baselines_do_not_use_or_report_the_index(self, repo, retriever):
        retriever.commit = _rev(repo, "pr")

        result = _review(repo, ScriptedLLM(), mode="llm-only", graph_enabled=False)

        assert result.meta.policy_index is None


class TestPolicyDocChanges:
    def test_pr_that_edits_and_adds_docs_is_flagged_in_both_reports(
        self, repo, semgrep, retriever, tmp_path
    ):
        (repo / "security-policy.md").write_text("Only owners may edit.\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base policy")
        _git(repo, "branch", "-f", "pr", "main")
        retriever.commit = _rev(repo, "main")
        (repo / "docs").mkdir()
        _add_to_pr(
            repo,
            {
                "security-policy.md": "The edit endpoint is public.\n",
                "docs/new-rule.rst": "Anyone may edit.\n",
                "app.py": "def edit():\n    return None\n",
            },
        )

        result = _review(repo, ScriptedLLM(), graph_enabled=False, output_dir=tmp_path / "out")

        assert result.meta.policy_docs_changed == ["docs/new-rule.rst", "security-policy.md"]
        review = json.loads(result.json_path.read_text(encoding="utf-8"))["review"]
        assert review["policy_docs_changed"] == ["docs/new-rule.rst", "security-policy.md"]
        assert review["policy_index"] == "ok"
        markdown = result.md_path.read_text(encoding="utf-8")
        assert "## Policy Documents Changed: Needs Human Review" in markdown
        assert "- `security-policy.md`" in markdown

    def test_deleted_and_renamed_docs_are_flagged(self, repo, semgrep, retriever):
        (repo / "keep.md").write_text("Rule one.\n", encoding="utf-8")
        (repo / "gone.txt").write_text("Rule two.\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "base docs")
        _git(repo, "branch", "-f", "pr", "main")
        retriever.commit = _rev(repo, "main")
        _git(repo, "checkout", "-q", "pr")
        _git(repo, "mv", "keep.md", "renamed.md")
        _git(repo, "rm", "-q", "gone.txt")
        _git(repo, "commit", "-q", "-m", "move docs")
        _git(repo, "checkout", "-q", "main")

        result = _review(repo, ScriptedLLM(), graph_enabled=False)

        assert result.meta.policy_docs_changed == ["gone.txt", "keep.md", "renamed.md"]

    def test_pr_without_doc_changes_is_not_flagged(self, repo, semgrep, retriever, tmp_path):
        retriever.commit = _rev(repo, "main")

        result = _review(repo, ScriptedLLM(), graph_enabled=False, output_dir=tmp_path / "out")

        assert result.meta.policy_docs_changed == []
        assert "Policy Documents Changed" not in result.md_path.read_text(encoding="utf-8")
