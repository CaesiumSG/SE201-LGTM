"""Shared per-finding tool-call accounting for both agents (RI-T1)."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from lgtm.agents.authz_reviewer import AuthzReviewerAgent, ChangedEndpoint
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.sast.semgrep_runner import SemgrepFinding

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
