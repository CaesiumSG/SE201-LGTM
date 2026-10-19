"""Mapping of literal CodeGraph 1.6.2 output (no match, stale index, init without an own index)."""

from __future__ import annotations

from pathlib import Path

import pytest

from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.graph.runner import GraphRunner
from lgtm.graph.session import GraphSession
from lgtm.graph.snapshot import resolve_refs
from tests.graph_fakes import kill_pids, make_fake_executable

NO_MATCH_OUTPUT = (
    'No relevant code found for "zzzqqqnomatch"\n'
    "\n"
    "Explore matches symbol/file names and indexed code words lexically, not by meaning.\n"
    "Checked indexed names, signatures, docstrings (FTS prefixes) and live name segments; not all source text.\n"
    "No lexical matches for checked words: `zzzqqqnomatch`.\n"
    "No shared-word symbol candidates found; retry codegraph_explore with literal symbol/file names or code terms.\n"
    "NOTE: dynamic Python edges are best effort; a missing edge does not establish safety.\n"
)

STALE_WARNING = "changed since last index sync — source below is current; the symbol list may be outdated"

_BODY = (
    "**Exploration: alpha_func**\n"
    "\n"
    "Found 2 symbols across 1 file.\n"
    "\n"
    "**Blast radius — what depends on these (update/verify before editing)**\n"
    "\n"
    "- `alpha_func` (m.py:1) — 1 caller in `m.py`; no tests found within 3 caller hops\n"
    "\n"
    "**Source Code**\n"
    "\n"
)
MATCH_OUTPUT = (
    _BODY
    + "**`m.py`** — alpha_func(function), beta_func(function)\n\n"
    + "```python\n1\tdef alpha_func(x):\n2\t    return x+1\n```\n"
)
STALE_OUTPUT = (
    _BODY
    + f"**`m.py`** — alpha_func(function), beta_func(function) · ⚠ {STALE_WARNING}\n\n"
    + "```python\n1\tdef alpha_func(x):\n2\t    return x+1\n```\n"
)

def explore_calls(exe) -> list[dict]:
    return [c for c in exe.calls() if c["argv"][0] == "explore"]


@pytest.fixture
def codegraph(tmp_path):
    made = []

    def build(**behavior):
        exe = make_fake_executable(tmp_path / "bin", **behavior)
        made.append(exe)
        return exe

    yield build
    for exe in made:
        kill_pids(exe.all_pids())


def runner_for(exe) -> GraphRunner:
    return GraphRunner(str(exe.path), init_timeout_s=60, query_timeout_s=60, max_output_chars=6000)


def session_for(git_repo, exe) -> GraphSession:
    shas = resolve_refs(git_repo, "main", "pr")
    return GraphSession(git_repo, shas, LGTMConfig(), runner=runner_for(exe))


def tools_for(git_repo, session) -> dict:
    shas = resolve_refs(git_repo, "main", "pr")
    toolbox = AgentToolbox(git_repo, "main", None, LGTMConfig(), shas=shas, session=session)
    return {t.name: t for t in toolbox.build_tools()}


def header(text: str) -> str:
    return text.splitlines()[0]


class TestRunnerMapsLiteralExploreOutput:
    def test_real_no_match_output_is_a_successful_no_match(self, codegraph, tmp_path):
        exe = codegraph(stdout=NO_MATCH_OUTPUT)

        result = runner_for(exe).explore(tmp_path, "zzzqqqnomatch")

        assert (result.ok, result.reason) == (True, "no_match")

    def test_stale_index_warning_is_a_failed_stale_outcome(self, codegraph, tmp_path):
        exe = codegraph(stdout=STALE_OUTPUT)

        result = runner_for(exe).explore(tmp_path, "alpha_func")

        assert (result.ok, result.reason) == (False, "stale")

    def test_real_match_output_stays_successful(self, codegraph, tmp_path):
        exe = codegraph(stdout=MATCH_OUTPUT)

        result = runner_for(exe).explore(tmp_path, "alpha_func")

        assert (result.ok, result.reason) == (True, None)
        assert "def alpha_func" in result.text


class TestInvestigateToolMapsLiteralExploreOutput:
    def test_real_no_match_reports_no_match_and_does_not_latch(self, codegraph, git_repo):
        exe = codegraph(stdout=NO_MATCH_OUTPUT)
        with session_for(git_repo, exe) as session:
            tools = tools_for(git_repo, session)
            first = tools["investigate_pr_code"].invoke({"query": "zzzqqqnomatch"})
            second = tools["investigate_pr_code"].invoke({"query": "zzzqqqnomatch"})
            state = session.state

        assert "status=no_match" in header(first)
        assert "status=no_match" in header(second)
        assert len(explore_calls(exe)) == 2
        assert state == "ok"

    def test_stale_index_reports_unavailable_and_latches_the_label(self, codegraph, git_repo):
        exe = codegraph(stdout=STALE_OUTPUT)
        with session_for(git_repo, exe) as session:
            tools = tools_for(git_repo, session)
            first = tools["investigate_pr_code"].invoke({"query": "alpha_func"})
            second = tools["investigate_pr_code"].invoke({"query": "alpha_func"})
            state = session.state

        for out in (first, second):
            assert "status=unavailable" in header(out) and "reason=stale" in header(out)
            assert "def alpha_func" not in out
        assert len(explore_calls(exe)) == 1
        assert state == "degraded:pr:stale"

    def test_real_match_output_reports_ok(self, codegraph, git_repo):
        exe = codegraph(stdout=MATCH_OUTPUT)
        with session_for(git_repo, exe) as session:
            tools = tools_for(git_repo, session)
            out = tools["investigate_pr_code"].invoke({"query": "alpha_func"})
            state = session.state

        assert "status=ok" in header(out)
        assert "def alpha_func" in out
        assert state == "ok"


class TestInitWithoutOwnIndexIsAnInitFailure:
    def test_runner_init_that_exits_zero_without_a_codegraph_directory_fails(self, codegraph, tmp_path):
        exe = codegraph(no_index=True)
        root = tmp_path / "export"
        root.mkdir()

        result = runner_for(exe).init(root)

        assert result.ok is False
        assert not (root / ".codegraph").exists()

    def test_missing_codegraph_directory_latches_the_label_and_never_explores(self, codegraph, git_repo):
        exe = codegraph(stdout=MATCH_OUTPUT, no_index=True)
        with session_for(git_repo, exe) as session:
            first = session.explore("pr", "alpha_func")
            second = session.explore("pr", "alpha_func")
            state = session.state

        assert first.ok is False and second.ok is False
        assert state.startswith("degraded:pr:")
        assert [c["argv"][0] for c in exe.calls()] == ["init"]

    def test_failed_init_is_reported_unavailable_by_the_tool_without_exploring(self, codegraph, git_repo):
        exe = codegraph(stdout=MATCH_OUTPUT, no_index=True)
        with session_for(git_repo, exe) as session:
            tools = tools_for(git_repo, session)
            out = tools["investigate_pr_code"].invoke({"query": "alpha_func"})

        assert "status=unavailable" in header(out)
        assert explore_calls(exe) == []

    def test_init_that_creates_its_own_index_proceeds_to_explore(self, codegraph, git_repo):
        exe = codegraph(stdout=MATCH_OUTPUT)
        with session_for(git_repo, exe) as session:
            result = session.explore("base", "alpha_func")
            state = session.state

        assert (result.ok, result.reason) == (True, None)
        assert state == "ok"
        assert [c["argv"][0] for c in exe.calls()] == ["init", "explore"]
