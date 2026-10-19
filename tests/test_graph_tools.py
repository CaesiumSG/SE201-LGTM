"""Shared per-finding tool-call accounting for both agents (RI-T1)."""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.agents.authz_reviewer import AuthzReviewerAgent, ChangedEndpoint
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.graph.exporter import export_snapshot
from lgtm.graph.format import FOOTER, render_graph
from lgtm.graph.session import GraphSession
from lgtm.graph.snapshot import resolve_refs
from lgtm.sast.semgrep_runner import SemgrepFinding
from tests.graph_fakes import FakeRunner, failure, no_match, outcome, success

EXHAUSTED = (
    "ERROR: tool call budget exhausted. You must now produce your final "
    "JSON answer using the evidence gathered so far."
)
SAFE = json.dumps({"verdict": "safe", "confidence": 0.9, "explanation": "ok"})
POLICY_MARK = "TOOLQ"


def _msg(content="", calls=None):
    return SimpleNamespace(content=content, tool_calls=calls or [])


def _native(name, args, id="c1"):
    return _msg("", [{"name": name, "args": args, "id": id}])


def _batch(*calls):
    return _msg(
        "",
        [{"name": n, "args": a, "id": f"c{i}"} for i, (n, a) in enumerate(calls, 1)],
    )


def _text(name, args):
    return _msg(json.dumps({"name": name, "arguments": args}))


class ScriptedLLM:
    def __init__(self, script):
        self.script = list(script)
        self.seen = []
        self.channels = []

    def bind_tools(self, tools):
        return _Bound(self)

    def invoke(self, messages):
        return self._next(messages, "unbound")

    def _next(self, messages, channel):
        self.seen.append(list(messages))
        self.channels.append(channel)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _Bound:
    def __init__(self, owner):
        self.owner = owner

    def invoke(self, messages):
        return self.owner._next(messages, "bound")


class CountingRetriever:
    """Policy backend double; counts only queries issued by the model's tool calls."""

    def __init__(self, exc=None):
        self.queries = []
        self.exc = exc

    def format_results(self, query, *args, **kwargs):
        self.queries.append(query)
        if self.exc and POLICY_MARK in query:
            raise self.exc
        return f"policy excerpt for {query}"

    def is_available(self):
        return True

    @property
    def tool_queries(self):
        return [q for q in self.queries if POLICY_MARK in q]


@pytest.fixture
def git_commands(monkeypatch):
    """Git subprocess command lines issued while a test runs."""
    recorded: list[list[str]] = []
    real_run = subprocess.run

    def spy(cmd, *args, **kwargs):
        if isinstance(cmd, (list, tuple)) and cmd and cmd[0] == "git":
            recorded.append([str(c) for c in cmd])
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    return recorded


@pytest.fixture
def git_envs(monkeypatch):
    """The env argument of each git subprocess issued while a test runs (None when inherited)."""
    recorded: list[dict | None] = []
    real_run = subprocess.run

    def spy(cmd, *args, **kwargs):
        if isinstance(cmd, (list, tuple)) and cmd and cmd[0] == "git":
            recorded.append(kwargs.get("env"))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    return recorded


def _touched(git_commands, token):
    return [c for c in git_commands if any(token in part for part in c)]


@pytest.fixture(params=["sast_triage", "authz_reviewer"])
def run_agent(request, git_repo):
    """Run one finding through the chosen agent with a scripted LLM."""

    def run(script, retriever=None, **config_kwargs):
        config = LGTMConfig(**config_kwargs)
        toolbox = AgentToolbox(git_repo, "main", retriever, config)
        llm = ScriptedLLM(script)
        if request.param == "sast_triage":
            finding = SemgrepFinding(
                rule_id="r",
                path="app.py",
                start_line=2,
                end_line=2,
                message="m",
                severity="ERROR",
                matched_code="cursor.execute(x)",
            )
            result = SASTTriageAgent(toolbox, config, llm=llm).triage(finding, None)
        else:
            endpoint = ChangedEndpoint(
                file="app.py", route_path="/u", http_methods=["GET"], decorator_line=1
            )
            result = AuthzReviewerAgent(toolbox, config, llm=llm).review(endpoint, None)
        return result, llm

    return run


def _text_result(name, args, result):
    return (
        f"Result of {name}({json.dumps(args)}):\n{result}\n\n"
        "Call another tool, or give your final JSON verdict."
    )


def _tool_messages(llm, call_index):
    return [m for m in llm.seen[call_index] if type(m).__name__ == "ToolMessage"]


class TestFailedCallsSpendSlots:
    def test_five_failed_native_calls_then_sixth_gets_budget_error_without_backend(
        self, run_agent, git_commands
    ):
        script = [_native("read_file", {"path": f"missing{i}.py"}, f"c{i}") for i in range(1, 6)]
        script += [_native("read_file", {"path": "app.py"}, "c6"), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 5
        assert _tool_messages(llm, 6)[-1].content == EXHAUSTED
        assert _touched(git_commands, "app.py") == []
        assert result.verdict == "safe"

    def test_eight_failed_native_calls_saturate_at_five_with_no_extra_backend_work(
        self, run_agent, git_commands
    ):
        script = [_native("read_file", {"path": f"missing{i}.py"}, f"c{i}") for i in range(1, 9)]
        script.append(_msg(SAFE))
        result, llm = run_agent(script)
        assert result.tool_calls_used == 5
        for i in (6, 7, 8):
            assert _touched(git_commands, f"missing{i}.py") == []
        assert [m.content for m in _tool_messages(llm, 8)[-3:]] == [EXHAUSTED] * 3
        assert len(_touched(git_commands, "missing")) == 5

    def test_batched_calls_beyond_five_get_budget_error_without_backend(
        self, run_agent, git_commands
    ):
        batch = _batch(*[("read_file", {"path": f"missing{i}.py"}) for i in range(1, 9)])
        result, llm = run_agent([batch, _msg(SAFE)])
        assert result.tool_calls_used == 5
        results = _tool_messages(llm, 1)
        assert [m.tool_call_id for m in results] == [f"c{i}" for i in range(1, 9)]
        assert [m.content for m in results[5:]] == [EXHAUSTED] * 3
        assert all(m.content != EXHAUSTED for m in results[:5])
        for i in (6, 7, 8):
            assert _touched(git_commands, f"missing{i}.py") == []

    def test_five_failed_text_calls_then_sixth_gets_budget_error_without_backend(
        self, run_agent, git_commands
    ):
        script = [_text("read_file", {"path": f"missing{i}.py"}) for i in range(1, 6)]
        script += [_text("read_file", {"path": "app.py"}), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 5
        assert llm.seen[6][-1].content == _text_result(
            "read_file", {"path": "app.py"}, EXHAUSTED
        )
        assert _touched(git_commands, "app.py") == []

    def test_tagged_text_batch_spends_per_call(self, run_agent):
        tagged = "\n".join(
            f'<tool_call>{{"name": "read_file", "arguments": {{"path": "missing{i}.py"}}}}</tool_call>'
            for i in range(1, 4)
        )
        result, _ = run_agent([_msg(tagged), _msg(SAFE)])
        assert result.tool_calls_used == 3

    def test_tool_exception_spends_once_and_is_not_retried(self, run_agent):
        retriever = CountingRetriever(exc=RuntimeError("backend down"))
        script = [_native("search_policy", {"query": f"{POLICY_MARK} x"}), _msg(SAFE)]
        result, llm = run_agent(script, retriever=retriever)
        assert result.tool_calls_used == 1
        assert len(retriever.tool_queries) == 1
        assert _tool_messages(llm, 1)[-1].content == "ERROR: tool failed: backend down"

    def test_sixth_search_policy_does_not_reach_the_retriever(self, run_agent):
        retriever = CountingRetriever()
        script = [
            _native("search_policy", {"query": f"{POLICY_MARK} {i}"}, f"c{i}")
            for i in range(1, 7)
        ]
        script.append(_msg(SAFE))
        result, llm = run_agent(script, retriever=retriever)
        assert result.tool_calls_used == 5
        assert len(retriever.tool_queries) == 5
        assert _tool_messages(llm, 6)[-1].content == EXHAUSTED


class TestRejectedCallsSpendSlots:
    def test_unknown_native_tool_and_invalid_schema_each_spend_a_slot(self, run_agent):
        script = [
            _native("rm_rf", {}, "c1"),
            _native("read_file", {}, "c2"),
            _msg(SAFE),
        ]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 2
        assert llm.channels == ["bound", "bound", "bound"]
        corrective = [m.content for m in _tool_messages(llm, 2)]
        assert corrective[0].startswith("ERROR: invalid input for tool 'rm_rf': unknown tool;")
        assert corrective[1].startswith("ERROR: invalid input for tool 'read_file': ")
        assert corrective[1].endswith("Fix the arguments and call the tool again.")

    def test_invalid_calls_mixed_in_a_batch_count_with_valid_ones(self, run_agent):
        batch = _batch(
            ("rm_rf", {}),
            ("read_file", {"path": "app.py"}),
            ("read_file", {"path": 5}),
        )
        result, _ = run_agent([batch, _msg(SAFE)])
        assert result.tool_calls_used == 3

    def test_rejected_calls_cannot_exceed_five_and_no_backend_runs_after_budget(
        self, run_agent, git_commands
    ):
        script = [
            _batch(("rm_rf", {}), ("rm_rf", {})),
            _batch(("read_file", {}), ("rm_rf", {})),
            _batch(("read_file", {"start_line": "x"})),
            _batch(("read_file", {"path": "app.py"})),
            _msg(SAFE),
        ]
        result, _ = run_agent(script, max_invalid_tool_inputs=0)
        assert result.tool_calls_used == 5
        assert _touched(git_commands, "app.py") == []

    def test_unknown_text_request_is_rejected_and_counted_not_taken_as_final(
        self, run_agent
    ):
        script = [_text("rm_rf", {"path": "x"}), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 1
        assert result.verdict == "safe"
        assert len(llm.seen) == 2
        assert "ERROR" in llm.seen[1][-1].content

    def test_unknown_tagged_text_request_is_rejected_and_counted(self, run_agent):
        tagged = '<tool_call>{"name": "shell", "arguments": {"cmd": "ls"}}</tool_call>'
        result, llm = run_agent([_msg(tagged), _msg(SAFE)])
        assert result.tool_calls_used == 1
        assert result.verdict == "safe"
        assert len(llm.seen) == 2

    def test_text_call_with_invalid_schema_spends_a_slot(self, run_agent):
        result, _ = run_agent([_text("read_file", {}), _msg(SAFE)])
        assert result.tool_calls_used == 1

    def test_third_invalid_input_still_forces_final_answer_and_all_three_spend(
        self, run_agent
    ):
        script = [_native("bad", {}, f"c{i}") for i in range(1, 4)] + [_msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 3
        assert llm.channels == ["bound", "bound", "bound", "unbound"]
        assert "Produce your final JSON verdict NOW" in llm.seen[3][-1].content
        assert result.verdict == "safe"


class TestNonToolOutputsAreNotCalls:
    def test_verdict_json_is_a_final_answer_not_a_tool_call(self, run_agent):
        verdict = json.dumps(
            {"name": "read_file", "arguments": {"path": "app.py"}, "verdict": "safe",
             "confidence": 0.5, "explanation": "x"}
        )
        result, llm = run_agent([_msg(verdict)])
        assert result.tool_calls_used == 0
        assert result.verdict == "safe"
        assert len(llm.seen) == 1

    def test_prose_mentioning_a_tool_is_not_a_tool_call(self, run_agent):
        script = [_msg("I would read_file app.py next, but I cannot."), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 0
        assert "not a valid JSON object" in llm.seen[1][-1].content
        assert result.verdict == "safe"


    @pytest.mark.parametrize(
        "payload",
        [
            {"name": "x", "explanation": "no verdict here"},
            {"name": "rm_rf", "explanation": "unregistered, no arguments"},
            {"name": "finding-7", "confidence": 0.4},
        ],
        ids=["named_object", "unregistered_name", "named_finding"],
    )
    def test_name_object_without_arguments_is_final_output_not_a_call(
        self, run_agent, payload
    ):
        result, llm = run_agent([_msg(json.dumps(payload))])
        assert result.tool_calls_used == 0
        assert len(llm.seen) == 1
        assert llm.channels == ["bound"]

    def test_prose_naming_an_unregistered_tool_is_not_a_call(self, run_agent):
        script = [_msg("Running rm_rf on the repo would be unsafe."), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 0
        assert "not a valid JSON object" in llm.seen[1][-1].content


class TestSuccessfulCallsAndResilience:
    def test_successful_calls_charge_exactly_once(self, run_agent):
        retriever = CountingRetriever()
        script = [
            _native("read_file", {"path": "app.py"}, "c1"),
            _native("grep_repo", {"pattern": "execute"}, "c2"),
            _native("search_policy", {"query": f"{POLICY_MARK} q"}, "c3"),
            _msg(SAFE),
        ]
        result, _ = run_agent(script, retriever=retriever)
        assert result.tool_calls_used == 3
        assert len(retriever.tool_queries) == 1

    def test_llm_retry_does_not_spend_or_repeat_tool_work(self, run_agent, git_commands):
        script = [
            _native("read_file", {"path": "app.py"}, "c1"),
            RuntimeError("transient"),
            _native("read_file", {"path": "missing.py"}, "c2"),
            _msg(SAFE),
        ]
        result, _ = run_agent(script)
        assert result.tool_calls_used == 2
        assert len(_touched(git_commands, "app.py")) == 1

    def test_json_reasks_after_budget_exhaustion_are_preserved(self, run_agent):
        script = [_native("read_file", {"path": f"m{i}.py"}, f"c{i}") for i in range(1, 7)]
        script += [_msg("prose"), _msg("more prose"), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 5
        assert result.verdict == "safe"
        assert "not a valid JSON object" in llm.seen[-1][-1].content

    @pytest.mark.parametrize("agent", ["sast_triage", "authz_reviewer"])
    def test_budget_is_per_finding(self, git_repo, agent):
        config = LGTMConfig()
        toolbox = AgentToolbox(git_repo, "main", None, config)
        for _ in range(2):
            llm = ScriptedLLM(
                [_native("read_file", {"path": f"m{i}.py"}, f"c{i}") for i in range(1, 6)]
                + [_msg(SAFE)]
            )
            if agent == "sast_triage":
                finding = SemgrepFinding(
                    rule_id="r", path="app.py", start_line=2, end_line=2,
                    message="m", severity="ERROR",
                )
                result = SASTTriageAgent(toolbox, config, llm=llm).triage(finding, None)
            else:
                endpoint = ChangedEndpoint(
                    file="app.py", route_path="/u", http_methods=["GET"], decorator_line=1
                )
                result = AuthzReviewerAgent(toolbox, config, llm=llm).review(endpoint, None)
            assert result.tool_calls_used == 5


class TestBackendSpyCanFail:
    def test_git_spy_records_a_successful_read(self, run_agent, git_commands):
        result, _ = run_agent([_native("read_file", {"path": "app.py"}), _msg(SAFE)])
        assert result.tool_calls_used == 1
        assert _touched(git_commands, "app.py") != []


class TestRejectedCallsAreChargedForPlainToolLists:
    @pytest.fixture(params=["list_copy", "slice"])
    def plain_tools(self, request, monkeypatch):
        original = AgentToolbox.build_tools

        def build(self):
            tools = original(self)
            return list(tools) if request.param == "list_copy" else tools[:]

        monkeypatch.setattr(AgentToolbox, "build_tools", build)

    def test_unknown_and_invalid_calls_spend_and_saturate_at_five(
        self, run_agent, plain_tools, git_commands
    ):
        script = [
            _native("rm_rf", {}, "c1"),
            _native("read_file", {}, "c2"),
            _native("rm_rf", {}, "c3"),
            _native("read_file", {"start_line": "x"}, "c4"),
            _native("shell", {"cmd": "ls"}, "c5"),
            _native("read_file", {"path": "app.py"}, "c6"),
            _msg(SAFE),
        ]
        result, llm = run_agent(script, max_invalid_tool_inputs=0)
        assert result.tool_calls_used == 5
        assert _tool_messages(llm, 6)[-1].content == EXHAUSTED
        assert _touched(git_commands, "app.py") == []

    def test_unknown_text_request_spends_a_slot(self, run_agent, plain_tools):
        result, _ = run_agent([_text("rm_rf", {"path": "x"}), _msg(SAFE)])
        assert result.tool_calls_used == 1


class TestRejectedAttemptAfterBudgetIsSpent:
    @staticmethod
    def _spend_five():
        return [_native("read_file", {"path": f"missing{i}.py"}, f"c{i}") for i in range(1, 6)]

    @pytest.mark.parametrize(
        "name,args",
        [("rm_rf", {}), ("read_file", {}), ("read_file", {"path": 5})],
        ids=["unknown_name", "missing_argument", "wrong_type"],
    )
    def test_native_sixth_attempt_gets_exhausted_response(
        self, run_agent, git_commands, name, args
    ):
        script = self._spend_five() + [_native(name, args, "c6"), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 5
        assert _tool_messages(llm, 6)[-1].content == EXHAUSTED
        assert len(_touched(git_commands, "missing")) == 5

    @pytest.mark.parametrize(
        "name,args",
        [("rm_rf", {"path": "x"}), ("read_file", {})],
        ids=["unknown_name", "missing_argument"],
    )
    def test_text_sixth_attempt_gets_exhausted_response(
        self, run_agent, git_commands, name, args
    ):
        script = self._spend_five() + [_text(name, args), _msg(SAFE)]
        result, llm = run_agent(script)
        assert result.tool_calls_used == 5
        assert llm.seen[6][-1].content == _text_result(name, args, EXHAUSTED)
        assert len(_touched(git_commands, "missing")) == 5

    def test_rejected_calls_after_saturation_still_trigger_the_invalid_input_stop(
        self, run_agent
    ):
        script = self._spend_five()
        script += [_native("rm_rf", {}, f"r{i}") for i in range(1, 4)]
        script.append(_msg(SAFE))
        result, llm = run_agent(script, max_agent_iterations=20)
        assert result.tool_calls_used == 5
        assert result.verdict == "safe"
        assert llm.channels == ["bound"] * 8 + ["unbound"]
        assert "Produce your final JSON verdict NOW" in llm.seen[8][-1].content


# ---------------------------------------------------------------------------
# Snapshot-aware tools
# ---------------------------------------------------------------------------

UNKNOWN_LABEL = "ERROR: unknown snapshot '{value}'. Allowed values: base, pr."
LEGACY_UNKNOWN_LABEL = "ERROR: unknown snapshot '{value}'. Allowed values: base."
LEGACY_PR = "ERROR: snapshot 'pr' is not available in this run. Allowed values: base."
EMPTY_QUERY = "ERROR: query must not be empty."
ESCAPE = "ERROR: path must be repository-relative and remain inside the repository."
MISSING_BINARY_WARNING = (
    "CodeGraph binary not found; investigate_* tools are disabled and agents "
    "will use read_file, grep_repo and search_policy."
)
GRAPH_NAMES = [
    "investigate_base_code",
    "investigate_pr_code",
    "read_file",
    "grep_repo",
    "search_policy",
]
READ_NAMES = ["read_file", "grep_repo", "search_policy"]


def _git(repo, *args):
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def _commit(repo, message):
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


@pytest.fixture
def snap(tmp_path):
    """Two committed snapshots (added, deleted, shifted, unchanged files) and a dirty working tree."""
    repo = tmp_path / "twosnap"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t.local")
    _git(repo, "config", "user.name", "T")
    files = {
        "app.py": "def get_user(cursor, user_id):\n    return cursor.fetchone()\n",
        "keep.py": "KEEP_ONE = 1\nKEEP_TWO = 2\n# --flag value\n",
        "gone.py": "GONE = True\n",
        "shift.py": "alpha = 1\nbeta = 2\ngamma = 3\n",
        "big.txt": "".join(f"row {i}\n" for i in range(1, 301)),
        "wide.txt": "".join(f"w{i} " + "y" * 190 + "\n" for i in range(100)),
        "sub/inner.py": "INNER = 1\n",
        "notes.md": "NOTE base\n",
    }
    for i in range(10):
        files[f"many/f{i}.txt"] = "".join(f"MANYHITS {i}-{j}\n" for j in range(5))
    for name, text in files.items():
        _write(repo / name, text)
    _commit(repo, "base")
    _git(repo, "checkout", "-q", "-b", "pr")
    _write(repo / "app.py", files["app.py"] + "\ndef find_user(cursor, name):\n    return cursor.fetchall()\n")
    (repo / "gone.py").unlink()
    _write(repo / "shift.py", "prelude1\nprelude2\n" + files["shift.py"])
    _write(repo / "new.py", "ADDED = 1\n")
    _commit(repo, "pr")
    _git(repo, "checkout", "-q", "main")
    _write(repo / "app.py", files["app.py"] + "DIRTY_MARK\n")
    _write(repo / "keep.py", "DIRTY_KEEP\n")
    _write(repo / "untracked.py", "UNTRACKED_MARK\n")
    _write(repo / "new.py", "WORKTREE_NEW\n")
    shas = resolve_refs(repo, "main", "pr")
    return SimpleNamespace(repo=repo, shas=shas, base=shas["base"], pr=shas["pr"])


class Rig:
    """A snapshot-aware toolbox over a fake graph runner; owns its session."""

    def __init__(self, snap, runner=None, export=None, retriever=None, **config_kwargs):
        self.snap = snap
        self.runner = runner or FakeRunner()
        self.exports = []
        real_export = export or export_snapshot

        def spy(*args, **kwargs):
            self.exports.append(args)
            return real_export(*args, **kwargs)

        self.config = LGTMConfig(**config_kwargs)
        self.session = GraphSession(
            snap.repo, snap.shas, self.config, runner=self.runner, export=spy
        )
        self.toolbox = AgentToolbox(
            snap.repo, "main", retriever, self.config, shas=snap.shas, session=self.session
        )
        self.tools = {t.name: t for t in self.toolbox.build_tools()}

    def call(self, name, **args):
        assert name in self.tools, f"{name} is not registered (have {list(self.tools)})"
        return self.tools[name].invoke(args)


@pytest.fixture
def rig(snap):
    made = []

    def build(**kwargs):
        r = Rig(snap, **kwargs)
        made.append(r)
        return r

    yield build
    for r in made:
        r.session.close()


def _legacy_tools(snap, **config_kwargs):
    toolbox = AgentToolbox(snap.repo, "main", config=LGTMConfig(**config_kwargs))
    return toolbox, {t.name: t for t in toolbox.build_tools()}


def _broken_base_tools(snap):
    broken = {"base": "0" * 39 + "1", "pr": snap.pr}
    toolbox = AgentToolbox(snap.repo, "main", config=LGTMConfig(), shas=broken, session=None)
    return {t.name: t for t in toolbox.build_tools()}


def _lines(text):
    return text.splitlines()


class TestRegisteredTools:
    def test_toolbox_accepts_frozen_shas_and_session(self, snap):
        session = GraphSession(snap.repo, snap.shas, LGTMConfig(), runner=FakeRunner())
        try:
            toolbox = AgentToolbox(
                snap.repo, "main", None, LGTMConfig(), shas=snap.shas, session=session
            )
            assert [t.name for t in toolbox.build_tools()] == GRAPH_NAMES
        finally:
            session.close()

    def test_graph_run_registers_five_tools_in_contract_order(self, rig):
        assert list(rig().tools) == GRAPH_NAMES

    def test_missing_binary_drops_only_the_two_investigate_tools(self, rig):
        r = rig(runner=FakeRunner(available=False))
        assert list(r.tools) == READ_NAMES
        assert "ADDED = 1" in r.call("read_file", path="new.py", snapshot="pr")

    def test_standalone_legacy_toolbox_stays_base_only(self, snap):
        _, tools = _legacy_tools(snap)
        assert list(tools) == READ_NAMES
        assert tools["read_file"].invoke({"path": "app.py", "snapshot": "pr"}) == LEGACY_PR
        assert tools["grep_repo"].invoke({"pattern": "get_user", "snapshot": "pr"}) == LEGACY_PR
        assert tools["read_file"].invoke({"path": "app.py", "snapshot": "PR"}) == (
            LEGACY_UNKNOWN_LABEL.format(value="PR")
        )

    def test_public_argument_schemas_and_defaults(self, rig):
        tools = rig().tools
        for name in ("investigate_base_code", "investigate_pr_code"):
            assert list(tools[name].args) == ["query"]
            assert tools[name].get_input_schema().model_json_schema()["required"] == ["query"]
        read = tools["read_file"]
        assert list(read.args) == ["path", "start_line", "end_line", "snapshot"]
        assert read.get_input_schema().model_json_schema()["required"] == ["path"]
        assert [read.args[k]["default"] for k in ("start_line", "end_line", "snapshot")] == [0, 0, "base"]
        grep = tools["grep_repo"]
        assert list(grep.args) == ["pattern", "file_glob", "snapshot"]
        assert grep.get_input_schema().model_json_schema()["required"] == ["pattern"]
        assert [grep.args[k]["default"] for k in ("file_glob", "snapshot")] == ["", "base"]
        assert list(tools["search_policy"].args) == ["query"]

    def test_search_policy_output_is_unchanged(self, rig):
        with_index = rig(retriever=CountingRetriever())
        assert with_index.call("search_policy", query="sql rules") == "policy excerpt for sql rules"
        assert rig().call("search_policy", query="sql rules").startswith(
            "ERROR: documentation index is not available."
        )


class TestSnapshotLabelsAtTheToolBoundary:
    BAD = ["PR", "Base", " pr", "pr ", "base\n", "main", "HEAD", "", "origin/pr"]

    @pytest.mark.parametrize("bad", BAD)
    def test_read_file_rejects_uncoerced_labels_without_git(self, rig, git_commands, bad):
        r = rig()
        git_commands.clear()
        assert r.call("read_file", path="app.py", snapshot=bad) == UNKNOWN_LABEL.format(value=bad)
        assert git_commands == []
        assert r.toolbox.calls_used == 1

    @pytest.mark.parametrize("bad", BAD)
    def test_grep_repo_rejects_uncoerced_labels_without_git(self, rig, git_commands, bad):
        r = rig()
        git_commands.clear()
        assert r.call("grep_repo", pattern="get_user", snapshot=bad) == UNKNOWN_LABEL.format(value=bad)
        assert git_commands == []
        assert r.toolbox.calls_used == 1

    def test_full_sha_is_not_accepted_as_a_label(self, rig, snap):
        r = rig()
        assert r.call("read_file", path="app.py", snapshot=snap.pr) == UNKNOWN_LABEL.format(value=snap.pr)
        assert r.call("grep_repo", pattern="x", snapshot=snap.base) == UNKNOWN_LABEL.format(value=snap.base)


class TestGitOnlyReads:
    def test_base_read_is_exact_and_ignores_the_dirty_tree(self, rig, snap):
        r = rig()
        assert r.call("read_file", path="shift.py") == (
            f"[READ snapshot=base sha={snap.base} path=shift.py lines=1-3]\n"
            "1: alpha = 1\n2: beta = 2\n3: gamma = 3\n[END READ]"
        )
        base_app = r.call("read_file", path="app.py")
        assert "DIRTY_MARK" not in base_app and "get_user" in base_app

    def test_pr_read_uses_the_pr_commit_not_the_checkout(self, rig, snap):
        r = rig()
        out = r.call("read_file", path="app.py", snapshot="pr")
        assert _lines(out)[0] == f"[READ snapshot=pr sha={snap.pr} path=app.py lines=1-5]"
        assert "find_user" in out and "DIRTY_MARK" not in out
        assert "find_user" not in r.call("read_file", path="app.py")

    def test_shifted_file_has_different_line_numbers_per_snapshot(self, rig):
        r = rig()
        assert "1: alpha = 1" in r.call("read_file", path="shift.py")
        assert "3: alpha = 1" in r.call("read_file", path="shift.py", snapshot="pr")

    def test_unchanged_file_has_identical_body_in_both_snapshots(self, rig):
        r = rig()
        base = _lines(r.call("read_file", path="sub/inner.py"))
        pr = _lines(r.call("read_file", path="sub/inner.py", snapshot="pr"))
        assert base[1:] == pr[1:] == ["1: INNER = 1", "[END READ]"]

    def test_tracked_changes_and_untracked_files_never_leak_into_reads(self, rig, snap):
        r = rig()
        assert "DIRTY_KEEP" not in r.call("read_file", path="keep.py")
        assert "DIRTY_KEEP" not in r.call("read_file", path="keep.py", snapshot="pr")
        assert r.call("read_file", path="untracked.py") == (
            f"ERROR: file 'untracked.py' not present in base snapshot @{snap.base}."
        )

    def test_added_and_deleted_files_exist_only_in_their_snapshot(self, rig, snap):
        r = rig()
        assert r.call("read_file", path="new.py") == (
            f"ERROR: file 'new.py' not present in base snapshot @{snap.base}."
        )
        assert "ADDED = 1" in r.call("read_file", path="new.py", snapshot="pr")
        assert "GONE = True" in r.call("read_file", path="gone.py")
        assert r.call("read_file", path="gone.py", snapshot="pr") == (
            f"ERROR: file 'gone.py' not present in pr snapshot @{snap.pr}."
        )

    def test_reads_need_neither_export_nor_the_graph_binary(self, rig):
        def boom(*args, **kwargs):
            raise AssertionError("export must not run for Git reads")

        r = rig(runner=FakeRunner(available=False), export=boom)
        assert "ADDED = 1" in r.call("read_file", path="new.py", snapshot="pr")
        assert "get_user" in r.call("grep_repo", pattern="get_user")
        assert r.exports == [] and r.runner.calls == []

    def test_read_is_capped_at_200_lines(self, rig):
        r = rig()
        out = r.call("read_file", path="big.txt")
        assert _lines(out)[0].endswith("path=big.txt lines=1-200]")
        assert "200: row 200" in out and "201: row 201" not in out
        capped = r.call("read_file", path="big.txt", start_line=100, end_line=300)
        assert _lines(capped)[0].endswith("lines=100-299]")
        tail = r.call("read_file", path="big.txt", start_line=250, end_line=300)
        assert _lines(tail)[0].endswith("lines=250-300]")

    def test_read_output_is_capped_at_8000_characters_with_end_marker(self, rig):
        out = rig().call("read_file", path="wide.txt")
        assert len(out) <= 8000
        assert out.startswith("[READ snapshot=base ") and out.endswith("[END READ]")

    def test_read_beyond_end_keeps_the_existing_envelope(self, rig):
        assert rig().call("read_file", path="app.py", start_line=50) == (
            "ERROR: start_line 50 is beyond end of file (2 lines)."
        )

    @pytest.mark.parametrize("label", ["base", "pr"])
    def test_directory_path_is_reported_as_not_present(self, rig, snap, label):
        out = rig().call("read_file", path="sub", snapshot=label)
        assert out == f"ERROR: file 'sub' not present in {label} snapshot @{snap.shas[label]}."

    @pytest.mark.parametrize("start,end", [(-3, 0), (-1, -1), (0, -5)])
    def test_negative_bounds_are_treated_as_unset(self, rig, start, end):
        r = rig()
        whole = r.call("read_file", path="shift.py")
        assert _lines(whole)[0].endswith("path=shift.py lines=1-3]")
        assert r.call("read_file", path="shift.py", start_line=start, end_line=end) == whole

    def test_negative_start_keeps_a_given_end(self, rig):
        out = rig().call("read_file", path="shift.py", start_line=-2, end_line=2)
        assert _lines(out)[0].endswith("path=shift.py lines=1-2]")
        assert "3: gamma" not in out

    def test_end_before_start_is_treated_as_end_unset(self, rig):
        r = rig()
        reversed_range = r.call("read_file", path="shift.py", start_line=2, end_line=1)
        assert reversed_range == r.call("read_file", path="shift.py", start_line=2)
        assert _lines(reversed_range)[0].endswith("lines=2-3]")
        capped = r.call("read_file", path="big.txt", start_line=5, end_line=2)
        assert _lines(capped)[0].endswith("path=big.txt lines=5-204]")

    def test_leading_dash_path_is_a_plain_absent_file(self, rig, snap):
        assert rig().call("read_file", path="-x") == (
            f"ERROR: file '-x' not present in base snapshot @{snap.base}."
        )

    def test_unknown_object_reports_a_generic_failure_without_stderr(self, snap):
        out = _broken_base_tools(snap)["read_file"].invoke({"path": "app.py"})
        assert out == "ERROR: cannot read base snapshot."

    def test_legacy_toolbox_read_header_names_the_base_commit(self, snap):
        _, tools = _legacy_tools(snap)
        header = _lines(tools["read_file"].invoke({"path": "app.py"}))[0]
        assert header == f"[READ snapshot=base sha={snap.base} path=app.py lines=1-2]"


class TestPathAndGlobValidation:
    ESCAPES = [
        "/etc/passwd", "C:/x.py", "C:\\x.py", "c:x.py", "\\\\server\\share\\x.py",
        "//server/share/x.py", "a\x00b.py", "../x.py", "a/../../x.py", "..\\x.py", "..",
        "sub/../app.py", "\\x.py", "C:", "sub/./../x.py",
        "src/a:b.py", "./:!d", "a/:(top)x",
    ]
    GLOB_ESCAPES = [
        "../*.py", "/abs/*", "C:/*", "\\\\srv\\s\\*", "a\x00*", "sub/../../*", "*/../x",
        "\\x*", "sub/../*.py",
    ]
    PATHSPEC_MAGIC = [
        ":(top)*", ":/x", ":!x", ":^x", ":(exclude)sub", ":(icase)APP.PY", ":(attr:foo)*",
        ":(glob)**/*.py", "./:!d", "a/:(top)x", "*:x", "src/a:b.py", "sub/*:x",
    ]

    @pytest.mark.parametrize("path", ESCAPES)
    def test_read_file_rejects_escapes_before_git_and_spends(self, rig, git_commands, path):
        r = rig()
        git_commands.clear()
        assert r.call("read_file", path=path) == ESCAPE
        assert r.call("read_file", path=path, snapshot="pr") == ESCAPE
        assert git_commands == []
        assert r.toolbox.calls_used == 2

    @pytest.mark.parametrize("glob", GLOB_ESCAPES + PATHSPEC_MAGIC)
    def test_grep_repo_rejects_glob_escapes_and_pathspec_magic_before_git(self, rig, git_commands, glob):
        r = rig()
        git_commands.clear()
        for label in ("base", "pr"):
            assert r.call("grep_repo", pattern="get_user", file_glob=glob, snapshot=label) == ESCAPE
        assert git_commands == []
        assert r.toolbox.calls_used == 2

    @pytest.mark.parametrize("path", ESCAPES)
    def test_legacy_read_file_rejects_escapes_before_any_git_call(self, snap, git_commands, path):
        toolbox, tools = _legacy_tools(snap)
        git_commands.clear()
        assert tools["read_file"].invoke({"path": path}) == ESCAPE
        assert git_commands == []
        assert toolbox.calls_used == 1

    @pytest.mark.parametrize("glob", GLOB_ESCAPES + PATHSPEC_MAGIC)
    def test_legacy_grep_repo_rejects_globs_before_any_git_call(self, snap, git_commands, glob):
        toolbox, tools = _legacy_tools(snap)
        git_commands.clear()
        assert tools["grep_repo"].invoke({"pattern": "get_user", "file_glob": glob}) == ESCAPE
        assert git_commands == []
        assert toolbox.calls_used == 1

    def test_safe_relative_globs_are_allowed(self, rig):
        r = rig()
        assert "keep.py:1:KEEP_ONE = 1" in r.call("grep_repo", pattern="KEEP_ONE", file_glob="*.py")
        nested = r.call("grep_repo", pattern="INNER", file_glob="sub/*.py")
        assert "sub/inner.py:1:INNER = 1" in nested
        other = r.call("grep_repo", pattern="INNER", file_glob="*.md")
        assert not any(l.startswith("sub/") for l in _lines(other))


class TestGrep:
    def test_header_relative_matches_and_footer(self, rig, snap):
        out = _lines(rig().call("grep_repo", pattern="get_user"))
        assert out[0] == f'[GREP snapshot=base sha={snap.base} pattern="get_user"]'
        assert "app.py:1:def get_user(cursor, user_id):" in out
        assert out[-1] == "[END GREP]"
        assert not any(line.startswith(snap.base) for line in out[1:])

    def test_pr_grep_sees_pr_only_code_and_base_does_not(self, rig):
        r = rig()
        pr = _lines(r.call("grep_repo", pattern="find_user", snapshot="pr"))
        assert any(l.startswith("app.py:") for l in pr)
        base = _lines(r.call("grep_repo", pattern="find_user"))
        assert not any(l.startswith("app.py:") for l in base)

    def test_dirty_tree_is_never_searched(self, rig):
        r = rig()
        for label in ("base", "pr"):
            hits = r.call(
                "grep_repo", pattern="DIRTY_MARK|UNTRACKED_MARK|DIRTY_KEEP|WORKTREE_NEW", snapshot=label
            )
            assert not any(".py:" in line for line in _lines(hits)[1:])

    OPTION_GLOBS = ["-l", "--count", "-Ocat", "--output=x", "--open-files-in-pager=cat", "--help", "-"]

    def test_pattern_that_looks_like_an_option_is_data(self, rig):
        r = rig()
        assert "keep.py:3:# --flag value" in r.call("grep_repo", pattern="--flag")
        assert not r.call("grep_repo", pattern="-v").startswith("ERROR")

    @pytest.mark.parametrize("glob", OPTION_GLOBS)
    def test_option_like_glob_never_reaches_git_as_an_option(self, rig, git_commands, glob):
        r = rig()
        git_commands.clear()
        out = r.call("grep_repo", pattern="get_user", file_glob=glob)
        greps = [c for c in git_commands if "grep" in c]
        if not greps:
            assert out == ESCAPE
            return
        assert len(greps) == 1
        argv = greps[0]
        positions = [i for i, part in enumerate(argv) if part == glob]
        assert positions, f"glob {glob!r} missing from git argv {argv}"
        assert all(argv[i - 1] == "--" for i in positions), argv

    @pytest.mark.parametrize("glob", ["-l", "--count", "--files-with-matches", "-c"])
    def test_option_like_glob_is_a_pathspec_not_an_output_mode(self, rig, glob):
        out = rig().call("grep_repo", pattern="get_user", file_glob=glob)
        assert out == ESCAPE or "No matches found." in _lines(out)

    def test_result_count_is_capped_at_30(self, rig):
        out = rig().call("grep_repo", pattern="MANYHITS")
        matches = [l for l in _lines(out) if re.match(r"many/f\d\.txt:\d+:", l)]
        assert len(matches) == 30
        assert len(out) <= 8000

    def test_invalid_regex_keeps_its_envelope(self, rig):
        assert rig().call("grep_repo", pattern="([").startswith("ERROR: invalid regex:")

    @pytest.mark.parametrize("pattern", ["(?:a)", "a\x00b", "get_user\nzzz_never"])
    @pytest.mark.parametrize("label", ["base", "pr"])
    def test_pattern_git_cannot_run_as_ere_gets_the_invalid_regex_envelope(self, rig, pattern, label):
        out = rig().call("grep_repo", pattern=pattern, snapshot=label)
        assert out.startswith("ERROR: invalid regex"), out
        assert "cannot read" not in out
        assert "fatal" not in out.lower()

    def test_other_git_failure_has_no_raw_stderr(self, snap):
        out = _broken_base_tools(snap)["grep_repo"].invoke({"pattern": "x"})
        assert out == "ERROR: cannot read base snapshot."


class TestGraphToolOutcomes:
    QUERY = "who calls find_user"

    def test_success_uses_the_provenance_format_for_each_label(self, rig, snap):
        r = rig(runner=FakeRunner(explore={"base": success("BASE-TOKEN"), "pr": success("PR-TOKEN")}))
        base = r.call("investigate_base_code", query=self.QUERY)
        pr = r.call("investigate_pr_code", query=self.QUERY)
        assert _lines(base)[0] == (
            f'[CODEGRAPH snapshot=base sha={snap.base} status=ok query="{self.QUERY}"]'
        )
        assert _lines(pr)[0] == (
            f'[CODEGRAPH snapshot=pr sha={snap.pr} status=ok query="{self.QUERY}"]'
        )
        assert base == render_graph("base", snap.base, "ok", "BASE-TOKEN", query=self.QUERY)
        assert pr == render_graph("pr", snap.pr, "ok", "PR-TOKEN", query=self.QUERY)
        assert _lines(base)[-2:] == [FOOTER, "[END CODEGRAPH]"]
        assert [c["label"] for c in r.runner.calls if c["kind"] == "explore"] == ["base", "pr"]

    def test_truncated_and_incomplete_markers_come_from_the_outcome_and_export(self, rig):
        def partial(*args, **kwargs):
            return dataclasses.replace(export_snapshot(*args, **kwargs), incomplete=True)

        r = rig(
            runner=FakeRunner(explore={"base": outcome(True, None, "BODY", truncated=True, omitted_chars=7)}),
            export=partial,
        )
        first = _lines(r.call("investigate_base_code", query=self.QUERY))[0]
        assert " truncated=true" in first and " incomplete=true" in first
        assert "status=ok" in first

    def test_empty_successful_stdout_is_no_match_and_does_not_latch(self, rig, snap):
        r = rig(runner=FakeRunner(explore={"base": no_match()}))
        for _ in range(2):
            out = r.call("investigate_base_code", query=self.QUERY)
            assert out == render_graph("base", snap.base, "no_match", "", query=self.QUERY)
            assert "No matching symbols found." in out
        assert r.runner.count("explore", "base") == 2
        assert r.session.state == "ok"

    @pytest.mark.parametrize("reason", ["timeout", "nonzero", "stale"])
    def test_query_failure_is_unavailable_and_latches_its_label(self, rig, snap, reason):
        r = rig(runner=FakeRunner(explore={"base": failure(reason)}))
        out = r.call("investigate_base_code", query=self.QUERY)
        assert _lines(out)[0] == (
            f'[CODEGRAPH snapshot=base sha={snap.base} status=unavailable reason={reason} query="{self.QUERY}"]'
        )
        assert out == render_graph("base", snap.base, "unavailable", "", query=self.QUERY, reason=reason)
        assert "read_file" in out and "grep_repo" in out
        assert r.session.state == f"degraded:base:{reason}"

    def test_export_failure_is_unavailable_with_export_failed(self, rig, snap):
        def failing(*args, **kwargs):
            raise OSError("disk full")

        r = rig(export=failing)
        out = r.call("investigate_pr_code", query=self.QUERY)
        assert out == render_graph("pr", snap.pr, "unavailable", "", query=self.QUERY, reason="export_failed")
        assert "disk full" not in out
        assert r.session.state == "degraded:pr:export_failed"

    def test_launch_failure_latches_both_labels(self, rig, snap):
        r = rig(runner=FakeRunner(explore={"base": failure("launch_failed")}))
        base = r.call("investigate_base_code", query=self.QUERY)
        pr = r.call("investigate_pr_code", query=self.QUERY)
        assert "status=unavailable reason=launch_failed" in _lines(base)[0]
        assert pr == render_graph("pr", snap.pr, "unavailable", "", query=self.QUERY, reason="launch_failed")
        assert r.session.state == "degraded:base:launch_failed;degraded:pr:launch_failed"
        assert r.runner.count("explore") == 1

    def test_unexpected_runtime_exception_reports_nonzero(self, rig):
        def explode(label, root):
            raise RuntimeError("secret internals")

        r = rig(runner=FakeRunner(explore={"base": explode}))
        out = r.call("investigate_base_code", query=self.QUERY)
        assert "status=unavailable reason=nonzero" in _lines(out)[0]
        assert "secret internals" not in out

    def test_repeated_latched_call_repeats_identity_spends_budget_and_does_no_work(self, rig):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout")}))
        first = r.call("investigate_base_code", query=self.QUERY)
        work = (r.runner.count("init"), r.runner.count("explore"), len(r.exports))
        again = r.call("investigate_base_code", query=self.QUERY)
        assert again == first
        assert (r.runner.count("init"), r.runner.count("explore"), len(r.exports)) == work
        assert r.toolbox.calls_used == 2

    def test_latch_is_per_label(self, rig):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout")}))
        r.call("investigate_base_code", query=self.QUERY)
        assert "status=ok" in _lines(r.call("investigate_pr_code", query=self.QUERY))[0]
        assert r.session.state == "degraded:base:timeout"

    @pytest.mark.parametrize("name", ["investigate_base_code", "investigate_pr_code"])
    @pytest.mark.parametrize("query", ["", "   ", "\n\t", "\x00\x01"])
    def test_empty_query_is_rejected_spends_and_starts_no_subprocess(self, rig, name, query):
        r = rig()
        assert r.call(name, query=query) == EMPTY_QUERY
        assert r.toolbox.calls_used == 1
        assert r.runner.calls == [] and r.exports == []

    def test_graph_call_spends_exactly_one_and_over_budget_never_reaches_the_runner(self, rig):
        r = rig(max_tool_calls=2)
        r.call("investigate_base_code", query="a")
        r.call("investigate_pr_code", query="b")
        assert r.call("investigate_base_code", query="c") == EXHAUSTED
        assert r.toolbox.calls_used == 2
        assert r.runner.count("explore") == 2

    def test_read_after_budget_is_exhausted_does_not_reach_git(self, rig, git_commands):
        r = rig(max_tool_calls=1)
        r.call("read_file", path="app.py")
        git_commands.clear()
        assert r.call("read_file", path="app.py", snapshot="pr") == EXHAUSTED
        assert git_commands == []


class TestGraphWarnings:
    LATCH = "CodeGraph unavailable for {label} snapshot ({reason}); further graph calls for it are skipped"

    @staticmethod
    def _count(caplog, text):
        return sum(1 for r in caplog.records if r.getMessage() == text)

    def test_missing_binary_warns_once_per_run_across_findings(self, rig, caplog):
        with caplog.at_level(logging.WARNING):
            r = rig(runner=FakeRunner(available=False))
            r.toolbox.build_tools()
            r.toolbox.build_tools()
        assert self._count(caplog, MISSING_BINARY_WARNING) == 1

    def test_available_binary_does_not_warn(self, rig, caplog):
        with caplog.at_level(logging.WARNING):
            rig().toolbox.build_tools()
        assert self._count(caplog, MISSING_BINARY_WARNING) == 0

    def test_first_latch_warns_once_per_label(self, rig, caplog):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout"), "pr": failure("stale")}))
        with caplog.at_level(logging.WARNING):
            for _ in range(3):
                r.call("investigate_base_code", query="q")
            for _ in range(2):
                r.call("investigate_pr_code", query="q")
        assert self._count(caplog, self.LATCH.format(label="base", reason="timeout")) == 1
        assert self._count(caplog, self.LATCH.format(label="pr", reason="stale")) == 1

    def test_no_match_never_warns(self, rig, caplog):
        r = rig(runner=FakeRunner(explore={"base": no_match()}))
        with caplog.at_level(logging.WARNING):
            r.call("investigate_base_code", query="q")
        assert not [m for m in caplog.messages if m.startswith("CodeGraph unavailable")]


class TestLazyGraph:
    def test_git_tools_do_zero_graph_work(self, rig):
        r = rig()
        r.call("read_file", path="app.py")
        r.call("grep_repo", pattern="get_user", snapshot="pr")
        assert r.runner.calls == [] and r.exports == []
        assert r.session.init_seconds == 0.0 and r.session.state == "ok"

    def test_legacy_reads_load_no_graph_runtime(self, snap):
        code = (
            "import sys\n"
            "from lgtm.agents.tools import AgentToolbox\n"
            "toolbox = AgentToolbox(sys.argv[1], 'main')\n"
            "assert toolbox.read_file_impl('app.py').startswith('[READ ')\n"
            "assert toolbox.grep_repo_impl('get_user').startswith('[GREP ')\n"
            "print(sorted(m for m in sys.modules if m.startswith('lgtm.graph')))\n"
        )
        done = subprocess.run(
            [sys.executable, "-I", "-c", code, str(snap.repo)], capture_output=True, text=True
        )
        assert done.returncode == 0, done.stderr
        loaded = set(json.loads(done.stdout.strip().replace("'", '"')))
        assert loaded <= {"lgtm.graph", "lgtm.graph.format"}, loaded

    def test_importing_the_agent_modules_does_not_import_the_graph_package(self):
        code = (
            "import sys\n"
            "import lgtm.agents.tools, lgtm.agents.sast_triage, lgtm.agents.authz_reviewer, lgtm.pipeline\n"
            "print(sorted(m for m in sys.modules if m.startswith('lgtm.graph')))\n"
        )
        done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "[]"


def _raiser(label, root):
    raise RuntimeError("secret internals")


class TestUnexpectedExplorerExceptionLatches:
    QUERY = "who calls find_user"

    def test_first_raise_is_unavailable_nonzero_without_exception_text(self, rig, snap):
        r = rig(runner=FakeRunner(explore={"base": _raiser}))
        out = r.call("investigate_base_code", query=self.QUERY)
        assert out == render_graph("base", snap.base, "unavailable", "", query=self.QUERY, reason="nonzero")
        assert "secret internals" not in out

    def test_repeat_on_same_label_spends_budget_and_does_no_work(self, rig):
        r = rig(runner=FakeRunner(explore={"base": _raiser}))
        first = r.call("investigate_base_code", query=self.QUERY)
        calls = r.runner.count("explore")
        assert r.call("investigate_base_code", query=self.QUERY) == first
        assert r.runner.count("explore") == calls
        assert r.toolbox.calls_used == 2

    def test_other_label_is_unaffected(self, rig):
        r = rig(runner=FakeRunner(explore={"base": _raiser}))
        r.call("investigate_base_code", query=self.QUERY)
        assert "status=ok" in _lines(r.call("investigate_pr_code", query=self.QUERY))[0]

    def test_first_latch_warning_appears_once_for_the_label(self, rig, caplog):
        r = rig(runner=FakeRunner(explore={"base": _raiser}))
        text = "CodeGraph unavailable for base snapshot (nonzero); further graph calls for it are skipped"
        with caplog.at_level(logging.WARNING):
            for _ in range(3):
                r.call("investigate_base_code", query=self.QUERY)
        assert sum(1 for rec in caplog.records if rec.getMessage() == text) == 1

    def test_graph_state_reports_the_exception_latch(self, rig):
        r = rig(runner=FakeRunner(explore={"base": _raiser}))
        assert r.toolbox.graph_state() == "ok"
        r.call("investigate_base_code", query=self.QUERY)
        assert r.toolbox.graph_state() == "degraded:base:nonzero"

    def test_graph_state_orders_session_latch_then_exception_latch(self, rig):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout"), "pr": _raiser}))
        r.call("investigate_base_code", query=self.QUERY)
        r.call("investigate_pr_code", query=self.QUERY)
        assert r.toolbox.graph_state() == "degraded:base:timeout;degraded:pr:nonzero"

    def test_graph_state_orders_exception_latch_then_session_latch(self, rig):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout"), "pr": _raiser}))
        r.call("investigate_pr_code", query=self.QUERY)
        r.call("investigate_base_code", query=self.QUERY)
        assert r.toolbox.graph_state() == "degraded:pr:nonzero;degraded:base:timeout"


class VanishingRunner(FakeRunner):
    """A runner whose binary can disappear (or return) after the toolbox is built."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.present = True

    def available(self):
        return self.present


def _latch_warnings(caplog, label):
    return [m for m in caplog.messages if m.startswith(f"CodeGraph unavailable for {label} snapshot")]


class TestLatchesSurviveFindingsAndToolboxes:
    QUERY = "who calls find_user"

    @pytest.mark.parametrize(
        "script",
        [failure("timeout"), failure("launch_failed"), _raiser],
        ids=["query_failure", "launch_failure", "unexpected_exception"],
    )
    def test_reset_budget_and_rebuilt_tools_keep_the_latch(self, rig, caplog, script):
        r = rig(runner=FakeRunner(explore={"base": script}))
        with caplog.at_level(logging.WARNING):
            first = r.call("investigate_base_code", query=self.QUERY)
            work = (r.runner.count("init"), r.runner.count("explore"), len(r.exports))
            r.toolbox.reset_budget()
            assert r.toolbox.calls_used == 0
            fresh = {t.name: t for t in r.toolbox.build_tools()}
            again = fresh["investigate_base_code"].invoke({"query": self.QUERY})
        assert "status=unavailable" in _lines(first)[0]
        assert again == first
        assert (r.runner.count("init"), r.runner.count("explore"), len(r.exports)) == work
        assert r.toolbox.calls_used == 1
        assert len(_latch_warnings(caplog, "base")) == 1

    def test_second_toolbox_over_the_same_session_inherits_the_session_latch(self, rig, snap):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout")}))
        first = r.call("investigate_base_code", query=self.QUERY)
        other = AgentToolbox(
            snap.repo, "main", None, r.config, shas=snap.shas, session=r.session
        )
        tools = {t.name: t for t in other.build_tools()}
        assert tools["investigate_base_code"].invoke({"query": self.QUERY}) == first
        assert r.runner.count("explore") == 1
        assert other.graph_state() == "degraded:base:timeout"


class TestGraphOutputLimit:
    QUERY = "who calls find_user"

    @staticmethod
    def _body(chars):
        text = "".join(f"symbol_{i} calls target_{i}\n" for i in range(chars))
        return text[:chars]

    @pytest.mark.parametrize("name,label", [("investigate_base_code", "base"), ("investigate_pr_code", "pr")])
    @pytest.mark.parametrize("body_chars", [1024, 5000])
    def test_total_output_including_provenance_respects_the_configured_limit(
        self, rig, name, label, body_chars
    ):
        body = self._body(body_chars)
        r = rig(runner=FakeRunner(explore={label: success(body)}), graph_max_output_chars=1024)
        out = r.call(name, query=self.QUERY)
        assert len(out) <= 1024, len(out)
        assert out.startswith(f"[CODEGRAPH snapshot={label} ") and out.endswith("[END CODEGRAPH]")
        assert "status=ok" in _lines(out)[0]
        assert "truncated=true" in _lines(out)[0]

    def test_truncated_outcome_respects_the_configured_limit(self, rig):
        r = rig(
            runner=FakeRunner(explore={"base": outcome(True, None, self._body(1024), truncated=True, omitted_chars=900)}),
            graph_max_output_chars=1024,
        )
        assert len(r.call("investigate_base_code", query=self.QUERY)) <= 1024

    def test_default_limit_caps_the_total_at_6000(self, rig):
        r = rig(runner=FakeRunner(explore={"base": success(self._body(20000))}))
        out = r.call("investigate_base_code", query=self.QUERY)
        assert 1024 < len(out) <= 6000
        assert out.endswith("[END CODEGRAPH]")


class TestBinaryDisappearsAfterStartup:
    QUERY = "who calls find_user"

    def test_vanished_binary_reports_launch_failed_and_latches(self, rig, snap, caplog):
        runner = VanishingRunner()
        r = rig(runner=runner)
        assert "investigate_base_code" in r.tools
        runner.present = False
        with caplog.at_level(logging.WARNING):
            first = r.call("investigate_base_code", query=self.QUERY)
            runner.present = True
            again = r.call("investigate_base_code", query=self.QUERY)
        expected = render_graph("base", snap.base, "unavailable", "", query=self.QUERY, reason="launch_failed")
        assert first == expected
        assert again == expected
        assert runner.count("init") == 0 and runner.count("explore") == 0
        assert len(_latch_warnings(caplog, "base")) == 1
        pr = r.call("investigate_pr_code", query=self.QUERY)
        assert "status=unavailable reason=launch_failed" in _lines(pr)[0]


class TestGraphState:
    def test_missing_binary_reports_unavailable_missing(self, rig):
        assert rig(runner=FakeRunner(available=False)).toolbox.graph_state() == "unavailable:missing"

    def test_toolbox_without_a_session_reports_ok(self, snap):
        toolbox, _ = _legacy_tools(snap)
        assert toolbox.graph_state() == "ok"

    def test_vanished_binary_reports_only_degraded_launch_failed(self, rig):
        runner = VanishingRunner()
        r = rig(runner=runner)
        runner.present = False
        r.call("investigate_base_code", query="q")
        state = r.toolbox.graph_state()
        assert "unavailable:missing" not in state
        assert state == "degraded:base:launch_failed;degraded:pr:launch_failed"


class TestToolboxConstruction:
    BAD_SHAS = [
        "", "main", "HEAD", "refs/heads/main", "origin/pr", "a" * 39, "a" * 41, "A" * 40,
        "0123456789ABCDEF0123456789abcdef01234567", "g" * 40, "a" * 40 + "\n", " " + "a" * 39,
    ]

    @pytest.mark.parametrize("label", ["base", "pr"])
    @pytest.mark.parametrize("bad", BAD_SHAS)
    def test_non_full_lowercase_hex_sha_is_rejected(self, snap, label, bad):
        shas = {**snap.shas, label: bad}
        with pytest.raises(ValueError):
            AgentToolbox(snap.repo, "main", None, LGTMConfig(), shas=shas, session=None)

    def test_full_lowercase_hex_shas_are_accepted(self, snap):
        AgentToolbox(snap.repo, "main", None, LGTMConfig(), shas=snap.shas, session=None)


class TestGitEnvironment:
    ALLOWED = {
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG",
        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS",
        "GIT_NO_REPLACE_OBJECTS", "GIT_PAGER",
    }
    PRIVATE_CONFIG = {"HOME", "USERPROFILE", "XDG_CONFIG_HOME"}

    def test_git_child_gets_an_allowlisted_environment(self, rig, git_envs, monkeypatch, tmp_path):
        seeded = {
            "GIT_DIR": str(tmp_path / "elsewhere.git"),
            "GIT_WORK_TREE": str(tmp_path),
            "GIT_ASKPASS": "ask-secret",
            "GIT_EXTERNAL_DIFF": "diff-secret",
            "GITHUB_TOKEN": "ghp_secret_token",
            "OPENAI_API_KEY": "sk-secret",
            "OLLAMA_HOST": "ollama-secret",
            "HTTPS_PROXY": "http://user:proxy-secret@proxy.invalid",
        }
        for key, value in seeded.items():
            monkeypatch.setenv(key, value)
        r = rig()
        git_envs.clear()
        assert "get_user" in r.call("read_file", path="app.py")
        assert "get_user" in r.call("grep_repo", pattern="get_user", snapshot="pr")
        assert r.call("read_file", path="missing.py").startswith("ERROR: file 'missing.py' not present")
        assert len(git_envs) >= 3
        for env in git_envs:
            assert env is not None, "git inherited the full process environment"
            names = {k.upper(): k for k in env}
            for key in seeded:
                assert key not in names, f"{key} leaked into the git environment"
            assert not set(seeded.values()) & set(env.values())
            unexpected = {
                k for k in names
                if k not in self.ALLOWED and not k.startswith("LC_")
                and not (k in self.PRIVATE_CONFIG and env[names[k]] != os.environ.get(k))
            }
            assert not unexpected, f"variables outside the allowlist: {sorted(unexpected)}"
            assert env.get("GIT_CONFIG_NOSYSTEM") == "1"


class TestGraphToolsThroughTheAgentLoop:
    QUERY = "who calls find_user"

    @staticmethod
    def _review(kind, r, llm):
        if kind == "sast_triage":
            finding = SemgrepFinding(
                rule_id="r", path="app.py", start_line=2, end_line=2, message="m", severity="ERROR",
            )
            return SASTTriageAgent(r.toolbox, r.config, llm=llm).triage(finding, None)
        endpoint = ChangedEndpoint(file="app.py", route_path="/u", http_methods=["GET"], decorator_line=1)
        return AuthzReviewerAgent(r.toolbox, r.config, llm=llm).review(endpoint, None)

    @pytest.fixture(params=["sast_triage", "authz_reviewer"])
    def kind(self, request):
        return request.param

    def test_native_call_is_charged_once_and_returns_the_pr_envelope(self, rig, snap, kind):
        r = rig(runner=FakeRunner(explore={"pr": success("PR-TOKEN")}))
        llm = ScriptedLLM([_native("investigate_pr_code", {"query": self.QUERY}), _msg(SAFE)])
        result = self._review(kind, r, llm)
        assert result.tool_calls_used == 1
        assert _tool_messages(llm, 1)[-1].content == render_graph(
            "pr", snap.pr, "ok", "PR-TOKEN", query=self.QUERY
        )
        assert r.runner.count("explore", "pr") == 1

    def test_text_request_is_parsed_charged_once_and_answered(self, rig, snap, kind):
        r = rig(runner=FakeRunner(explore={"pr": success("PR-TOKEN")}))
        args = {"query": self.QUERY}
        llm = ScriptedLLM([_text("investigate_pr_code", args), _msg(SAFE)])
        result = self._review(kind, r, llm)
        assert result.tool_calls_used == 1
        assert llm.seen[1][-1].content == _text_result(
            "investigate_pr_code", args,
            render_graph("pr", snap.pr, "ok", "PR-TOKEN", query=self.QUERY),
        )

    def test_batched_graph_and_read_calls_are_each_charged(self, rig, snap, kind):
        r = rig()
        batch = _batch(
            ("investigate_base_code", {"query": self.QUERY}),
            ("investigate_pr_code", {"query": self.QUERY}),
            ("read_file", {"path": "new.py", "snapshot": "pr"}),
        )
        llm = ScriptedLLM([batch, _msg(SAFE)])
        result = self._review(kind, r, llm)
        assert result.tool_calls_used == 3
        results = _tool_messages(llm, 1)
        assert [m.tool_call_id for m in results] == ["c1", "c2", "c3"]
        assert _lines(results[0].content)[0].startswith("[CODEGRAPH snapshot=base ")
        assert _lines(results[1].content)[0].startswith("[CODEGRAPH snapshot=pr ")
        assert _lines(results[2].content)[0].startswith("[READ snapshot=pr ")

    def test_unavailable_result_is_not_retried_within_a_finding(self, rig, snap, kind):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout")}))
        call = {"query": self.QUERY}
        llm = ScriptedLLM([
            _native("investigate_base_code", call, "c1"),
            _native("investigate_base_code", call, "c2"),
            _msg(SAFE),
        ])
        result = self._review(kind, r, llm)
        assert result.tool_calls_used == 2
        first, second = _tool_messages(llm, 2)[-2:]
        assert first.content == second.content == render_graph(
            "base", snap.base, "unavailable", "", query=self.QUERY, reason="timeout"
        )
        assert r.runner.count("explore") == 1

    def test_latch_carries_over_to_the_next_finding(self, rig, snap, kind, caplog):
        r = rig(runner=FakeRunner(explore={"base": failure("timeout")}))
        call = {"query": self.QUERY}
        llm = ScriptedLLM([
            _native("investigate_base_code", call, "c1"), _msg(SAFE),
            _native("investigate_base_code", call, "c2"), _msg(SAFE),
        ])
        with caplog.at_level(logging.WARNING):
            first = self._review(kind, r, llm)
            second = self._review(kind, r, llm)
        assert first.tool_calls_used == 1 and second.tool_calls_used == 1
        assert _tool_messages(llm, 1)[-1].content == _tool_messages(llm, 3)[-1].content
        assert "reason=timeout" in _tool_messages(llm, 3)[-1].content
        assert r.runner.count("explore") == 1
        assert len(_latch_warnings(caplog, "base")) == 1
