"""Mapping of literal CodeGraph 1.6.2 output (no match, stale index, init without an own index)."""

from __future__ import annotations

from pathlib import Path

import pytest

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
SNIPPET_WITH_NOTICE_TEXT = (
    "```python\n"
    f"1\t# {STALE_WARNING}\n"
    f"2\t# x · ⚠ {STALE_WARNING}\n"
    "3\tNo relevant code found\n"
    "```\n"
)
HEALTHY_OUTPUT_QUOTING_NOTICES = (
    _BODY + "**`m.py`** — alpha_func(function), beta_func(function)\n\n" + SNIPPET_WITH_NOTICE_TEXT
)
STALE_OUTPUT = (
    _BODY
    + f"**`m.py`** — alpha_func(function), beta_func(function) · ⚠ {STALE_WARNING}\n\n"
    + "```python\n1\tdef alpha_func(x):\n2\t    return x+1\n```\n"
)

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


def outcome_of(result) -> tuple[bool, str | None]:
    return (result.ok, result.reason)


class TestRunnerMapsLiteralExploreOutput:
    def test_real_no_match_output_is_a_successful_no_match(self, codegraph, tmp_path):
        exe = codegraph(stdout=NO_MATCH_OUTPUT)

        assert outcome_of(runner_for(exe).explore(tmp_path, "zzzqqqnomatch")) == (True, "no_match")

    def test_real_match_output_stays_successful(self, codegraph, tmp_path):
        exe = codegraph(stdout=MATCH_OUTPUT)

        result = runner_for(exe).explore(tmp_path, "alpha_func")

        assert outcome_of(result) == (True, None)
        assert "def alpha_func" in result.text

    def test_stale_index_notice_is_a_failed_stale_outcome(self, codegraph, tmp_path):
        exe = codegraph(stdout=STALE_OUTPUT)

        assert outcome_of(runner_for(exe).explore(tmp_path, "alpha_func")) == (False, "stale")

    def test_stale_notice_after_the_output_cap_is_still_stale(self, codegraph, tmp_path):
        exe = codegraph(stdout_flood=70000, stdout="\n" + STALE_OUTPUT)

        assert outcome_of(runner_for(exe).explore(tmp_path, "alpha_func")) == (False, "stale")

    def test_stale_notice_straddling_a_read_boundary_is_still_stale(self, codegraph, tmp_path):
        exe = codegraph(stdout_flood=65536 - 10, stdout="\n" + STALE_OUTPUT)

        assert outcome_of(runner_for(exe).explore(tmp_path, "alpha_func")) == (False, "stale")

    def test_source_text_quoting_notice_phrases_does_not_make_a_healthy_explore_stale(self, codegraph, tmp_path):
        exe = codegraph(stdout=HEALTHY_OUTPUT_QUOTING_NOTICES)

        result = runner_for(exe).explore(tmp_path, "alpha_func")

        assert outcome_of(result) == (True, None)
        assert "No relevant code found" in result.text

    @pytest.mark.parametrize("stdout", ["", "\n"])
    def test_empty_successful_stdout_is_a_no_match(self, codegraph, tmp_path, stdout):
        exe = codegraph(stdout=stdout)

        assert outcome_of(runner_for(exe).explore(tmp_path, "alpha_func")) == (True, "no_match")


class TestSessionStateFromLiteralExploreOutput:
    def test_stale_notice_latches_the_label_with_reason_stale(self, codegraph, git_repo):
        exe = codegraph(stdout=STALE_OUTPUT)
        with session_for(git_repo, exe) as session:
            result = session.explore("pr", "alpha_func")
            state = session.state

        assert outcome_of(result) == (False, "stale")
        assert state == "degraded:pr:stale"

    def test_source_text_quoting_notice_phrases_leaves_the_state_ok(self, codegraph, git_repo):
        exe = codegraph(stdout=HEALTHY_OUTPUT_QUOTING_NOTICES)
        with session_for(git_repo, exe) as session:
            first = session.explore("pr", "alpha_func")
            second = session.explore("pr", "alpha_func")
            state = session.state

        assert outcome_of(first) == outcome_of(second) == (True, None)
        assert state == "ok"

    def test_empty_successful_stdout_is_no_match_and_does_not_latch(self, codegraph, git_repo):
        exe = codegraph(stdout="")
        with session_for(git_repo, exe) as session:
            first = session.explore("pr", "alpha_func")
            second = session.explore("pr", "alpha_func")
            state = session.state

        assert outcome_of(first) == outcome_of(second) == (True, "no_match")
        assert state == "ok"
        assert [c["argv"][0] for c in exe.calls()].count("explore") == 2


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
