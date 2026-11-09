"""Guard: every model-backed component runs on CodeGraph and the real policy retriever (AC-S6-1..3)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lgtm.graph.session import GraphSession  # noqa: E402
from lgtm.rag.retriever import PolicyRetriever  # noqa: E402
from tests.conftest import BENCH_TOOLBOX_COMPONENTS  # noqa: E402

REQUIRED_TOOLS = {"investigate_base_code", "investigate_pr_code", "search_policy"}
components = pytest.mark.parametrize("component", BENCH_TOOLBOX_COMPONENTS)


@components
def test_toolbox_offers_codegraph_tools_and_search_policy(bench_env, component):
    result = bench_env.run(component)
    assert result.agents.toolboxes, f"{component} built no toolbox: {result.unit.get('reason')}"
    toolbox = result.agents.toolboxes[0]
    if component == "sast-sqli":
        offered = {t.name for t in toolbox.build_tools(graph=False)}
        assert offered == {"read_file", "grep_repo", "search_policy"}
    else:
        assert REQUIRED_TOOLS <= {t.name for t in toolbox.build_tools()}


@components
def test_toolbox_carries_a_live_graph_session_and_the_production_retriever(bench_env, component):
    result = bench_env.run(component)
    toolbox = result.agents.toolboxes[0]
    assert isinstance(toolbox.session, GraphSession)
    assert type(toolbox.retriever) is PolicyRetriever


@components
def test_toolbox_is_bound_to_the_case_clone_at_the_pinned_revisions(bench_env, component):
    result = bench_env.run(component)
    toolbox = result.agents.toolboxes[0]
    assert toolbox.repo == bench_env.repo.resolve()
    assert toolbox.shas == {"base": bench_env.base, "pr": bench_env.pr}


@components
def test_retriever_indexes_the_docs_at_the_unit_pr_ref_not_the_clone_checkout(bench_env, component):
    result = bench_env.run(component)
    toolbox = result.agents.toolboxes[0]
    clone = bench_env.repo.resolve()
    assert bench_env.index_calls == [(clone, bench_env.pr)]
    assert bench_env.indexed[clone].keys() >= {"docs/pr_only.md"}
    assert toolbox.retriever.indexed_ref == bench_env.pr
    assert not toolbox.index_dir.exists()


@components
def test_search_policy_finds_a_doc_present_only_at_pr_ref_and_not_base_or_later_docs(bench_env, component):
    result = bench_env.run(component)
    answer = result.agents.toolboxes[0].search_policy_impl("policy")
    assert "pr_only.md" in answer
    assert "base_only.md" not in answer
    assert "later_only.md" not in answer


@components
def test_failed_index_build_records_a_unit_error_naming_the_index(bench_env, component):
    result = bench_env.run(component, rag=False)
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None
    assert any(word in result.unit["reason"].lower() for word in ("rag", "index"))
    assert result.agents.toolboxes == []


@components
def test_component_with_the_graph_turned_off_does_not_run(bench_env, component):
    result = bench_env.run(component, graph_enabled=False)
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None
    assert result.summary["units_scored"] == 0
