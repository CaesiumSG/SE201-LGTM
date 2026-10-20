"""Tests for agent tools, output parsing, and the agent loop (LLM mocked)."""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock

import pytest

from lgtm.agents.authz_reviewer import AuthzReviewerAgent
from lgtm.agents.base import extract_json_object, parse_agent_output, run_tool_loop
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import LineChange
from lgtm.review.sections import HunkRef, Section


class TestToolbox:
    def test_read_file_from_base_branch(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        out = toolbox.read_file_impl("app.py")
        assert "get_user" in out
        assert "find_user" not in out  # PR-only code must be invisible
        assert out.splitlines()[1].startswith("1: ")

    def test_read_file_line_range(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        lines = toolbox.read_file_impl("app.py", 2, 2).splitlines()
        assert lines[0].endswith("lines=2-2]")
        assert lines[1].startswith("2: ")
        assert not any(line.startswith("1: ") for line in lines)

    def test_read_missing_file(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        assert "ERROR" in toolbox.read_file_impl("nope.py")

    def test_path_escape_blocked(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        assert "ERROR" in toolbox.read_file_impl("../../etc/passwd")
        assert "ERROR" in toolbox.read_file_impl("/etc/passwd")

    def test_grep_repo_matches_base_only(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        out = toolbox.grep_repo_impl("get_user")
        assert "app.py" in out
        assert "No matches" in toolbox.grep_repo_impl("find_user")

    def test_grep_invalid_regex(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        assert "invalid regex" in toolbox.grep_repo_impl("([")

    def test_search_policy_without_retriever(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main", retriever=None)
        assert "ERROR" in toolbox.search_policy_impl("sql rules")

    def test_tool_call_budget_enforced(self, git_repo):
        config = LGTMConfig(max_tool_calls=2)
        toolbox = AgentToolbox(git_repo, "main", config=config)
        tools = toolbox.build_tools()
        read_file = next(t for t in tools if t.name == "read_file")
        ok1 = read_file.invoke({"path": "app.py"})
        ok2 = read_file.invoke({"path": "app.py"})
        blocked = read_file.invoke({"path": "app.py"})
        assert "get_user" in ok1 and "get_user" in ok2
        assert "budget exhausted" in blocked
        toolbox.reset_budget()
        assert "get_user" in read_file.invoke({"path": "app.py"})


class TestJsonExtraction:
    def test_plain_json(self):
        assert extract_json_object('{"a": 1}') == {"a": 1}

    def test_fenced_json(self):
        text = 'Here is my verdict:\n```json\n{"verdict": "safe"}\n```\nDone.'
        assert extract_json_object(text) == {"verdict": "safe"}

    def test_json_with_prose_and_nesting(self):
        text = 'Analysis... {"a": {"b": [1, 2]}, "s": "brace } in string"} trailing'
        assert extract_json_object(text) == {"a": {"b": [1, 2]}, "s": "brace } in string"}

    def test_no_json(self):
        assert extract_json_object("no json here") is None

    def test_unescaped_docstring_quotes_repaired(self):
        # Exact failure mode observed with qwen2.5-coder:7b: a Python
        # docstring pasted verbatim into a JSON string value.
        text = (
            '{\n'
            '  "verdict": "vulnerable",\n'
            '  "evidence": [\n'
            '    {"type": "code", "file": "a.py",\n'
            '     "content": "def get_order(order_id):\\n    """Fetch one."""\\n    return x"}\n'
            '  ]\n'
            '}'
        )
        data = extract_json_object(text)
        assert data is not None
        assert data["verdict"] == "vulnerable"
        assert 'Fetch one.' in data["evidence"][0]["content"]

    def test_literal_newlines_in_strings_repaired(self):
        text = '{"explanation": "line one\nline two", "verdict": "safe"}'
        data = extract_json_object(text)
        assert data == {"explanation": "line one\nline two", "verdict": "safe"}


class TestParseAgentOutput:
    def test_full_finding(self):
        text = """```json
        {
          "finding_id": "f1",
          "verdict": "vulnerable",
          "confidence": 0.9,
          "cwe_id": "CWE-89",
          "explanation": "f-string into SQL",
          "evidence": [
            {"type": "code", "file": "app.py", "lines": [5, 6], "content": "cursor.execute(...)"},
            {"type": "policy", "source": "policy.md", "content": "All SQL must use bound parameters."}
          ],
          "suggested_fix": "Use placeholders"
        }
        ```"""
        f = parse_agent_output(text, "fallback-id")
        assert f.finding_id == "f1"
        assert f.verdict == "vulnerable"
        assert f.confidence == 0.9
        assert len(f.evidence) == 2
        assert f.evidence[1].type == "policy"

    def test_malformed_output_degrades_gracefully(self):
        f = parse_agent_output("I think it's fine lol", "f2", default_cwe="CWE-89")
        assert f.verdict == "insufficient_evidence"
        assert f.finding_id == "f2"
        assert f.cwe_id == "CWE-89"

    def test_invalid_verdict_normalized(self):
        f = parse_agent_output('{"verdict": "exploitable!!", "confidence": 5}', "f3")
        assert f.verdict == "insufficient_evidence"
        assert f.confidence == 1.0  # clamped

    def test_int_lines_coerced(self):
        f = parse_agent_output(
            '{"verdict": "safe", "evidence": [{"type": "code", "file": "a.py", "lines": 7, "content": "x"}]}',
            "f4",
        )
        assert f.evidence[0].lines == [7, 7]


class _FakeLLM:
    """Mimics a ChatOllama supporting bind_tools + invoke."""

    def __init__(self, scripted_responses):
        self.responses = list(scripted_responses)

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        return self.responses.pop(0)


def _ai_message(content="", tool_calls=None):
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls or []
    return msg


class _RecordingLLM:
    def __init__(self, script):
        self.script = list(script)
        self.seen = []
        self.channels = []

    def bind_tools(self, tools):
        return _BoundView(self)

    def invoke(self, messages):
        return self._next(messages, "unbound")

    def _next(self, messages, channel):
        self.seen.append(list(messages))
        self.channels.append(channel)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class _BoundView:
    def __init__(self, owner):
        self.owner = owner

    def invoke(self, messages):
        return self.owner._next(messages, "bound")


class TestRunToolLoop:
    def test_direct_answer(self):
        llm = _FakeLLM([_ai_message('{"verdict": "safe"}')])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == '{"verdict": "safe"}'

    def test_tool_call_then_answer(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        tools = toolbox.build_tools()
        llm = _FakeLLM([
            _ai_message(
                "",
                tool_calls=[{"name": "read_file", "args": {"path": "app.py"}, "id": "c1"}],
            ),
            _ai_message('{"verdict": "vulnerable"}'),
        ])
        out = run_tool_loop(llm, tools, "sys", "user", LGTMConfig())
        assert out == '{"verdict": "vulnerable"}'
        assert toolbox.calls_used == 1

    def test_unknown_tool_surfaces_error_and_continues(self):
        llm = _FakeLLM([
            _ai_message("", tool_calls=[{"name": "rm_rf", "args": {}, "id": "c1"}]),
            _ai_message('{"verdict": "safe"}'),
        ])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == '{"verdict": "safe"}'


def _hunk(file="app.py", start=10, lines=("a = 1", "b = 2", "c = 3"), deletion=False):
    kind = "del" if deletion else "add"
    changes = [
        LineChange(kind, text, start + i if deletion else None, None if deletion else start + i)
        for i, text in enumerate(lines)
    ]
    return HunkRef(
        hunk_id=f"{file}#{start}", file=file,
        old_start=start, old_count=len(lines) if deletion else 0,
        new_start=0 if deletion else start, new_count=0 if deletion else len(lines),
        change="delete" if deletion else "add", changes=changes,
    )


def _section(hunks=None, **overrides):
    hunks = hunks or [_hunk()]
    fields = dict(
        section_id="s1", origin="investigator", title="Order access",
        files=list(dict.fromkeys(h.file for h in hunks)), hunks=hunks,
    )
    return Section(**{**fields, **overrides})


def _finding(**fields):
    return {
        "verdict": "vulnerable", "cwe_id": "CWE-639", "confidence": 0.8,
        "explanation": "no ownership check", "evidence": [], "suggested_fix": "check owner",
        "file": "app.py", "line": 11, **fields,
    }


def _reply(*findings):
    return _ai_message(json.dumps({"findings": list(findings)}))


class _AlwaysLLM:
    def __init__(self, content=None, exc=None):
        self.content, self.exc = content, exc

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        if self.exc:
            raise self.exc
        return _ai_message(self.content)


def _review(git_repo, llm, section=None, notes="", toolbox=None, **config_kwargs):
    config = LGTMConfig(**config_kwargs)
    toolbox = toolbox or AgentToolbox(git_repo, "main", None, config)
    return AuthzReviewerAgent(toolbox, config, llm=llm).review_section(
        section or _section(), notes
    )


class TestReviewSection:
    def test_each_finding_is_numbered_and_carries_its_own_fields(self, git_repo):
        llm = _FakeLLM([_reply(
            _finding(verdict="vulnerable", cwe_id="CWE-639", line=11),
            _finding(verdict="possible", cwe_id="CWE-862", confidence=0.4, line=12),
        )])
        out = _review(git_repo, llm)
        assert [f.finding_id for f in out] == ["authz:s1:1", "authz:s1:2"]
        assert [f.verdict for f in out] == ["vulnerable", "possible"]
        assert [f.cwe_id for f in out] == ["CWE-639", "CWE-862"]
        assert [f.line for f in out] == [11, 12]
        assert all(f.category == "authz" and f.agent == "authz_reviewer" for f in out)
        assert all(f.file == "app.py" for f in out)

    @pytest.mark.parametrize(
        "findings",
        [[], [{"verdict": "safe", "cwe_id": "CWE-639", "confidence": 0.9, "explanation": "ok"}]],
        ids=["zero_findings", "only_safe_findings"],
    )
    def test_zero_or_only_safe_findings_report_no_issue(self, git_repo, findings):
        out = _review(git_repo, _FakeLLM([_reply(*findings)]))
        assert all(f.verdict == "safe" for f in out)
        assert not any(f.finding_id.endswith(":failed") for f in out)

    def test_empty_file_falls_back_to_the_first_section_file(self, git_repo):
        section = _section([_hunk("orders.py"), _hunk("refunds.py", start=40)])
        out = _review(git_repo, _FakeLLM([_reply(_finding(file=""))]), section)
        assert out[0].file == "orders.py"

    @pytest.mark.parametrize(
        "line", [None, "not a number", 0, -3], ids=["missing", "text", "zero", "negative"]
    )
    def test_missing_or_invalid_line_falls_back_to_first_hunk_new_start(self, git_repo, line):
        section = _section([_hunk(start=10), _hunk(start=50)])
        raw = _finding()
        if line is None:
            del raw["line"]
        else:
            raw["line"] = line
        out = _review(git_repo, _FakeLLM([_reply(raw)]), section)
        assert out[0].line == 10

    def test_deletion_only_section_falls_back_to_old_start(self, git_repo):
        section = _section([_hunk(start=20, lines=("x", "y"), deletion=True)])
        raw = _finding()
        del raw["line"]
        out = _review(git_repo, _FakeLLM([_reply(raw)]), section)
        assert out[0].line == 20

    def test_budget_is_restored_for_each_section_after_an_investigator_override(self, git_repo):
        config = LGTMConfig()
        toolbox = AgentToolbox(git_repo, "main", None, config)
        toolbox.reset_budget(2)
        reads = [
            _ai_message("", [{"name": "read_file", "args": {"path": f"m{i}.py"}, "id": f"c{i}"}])
            for i in range(1, 6)
        ]
        out = _review(git_repo, _FakeLLM(reads + [_reply(_finding())]), toolbox=toolbox)
        assert toolbox.budget == config.max_tool_calls
        assert out[0].tool_calls_used == config.max_tool_calls == 5

    def test_tool_calls_do_not_carry_over_between_sections(self, git_repo):
        config = LGTMConfig()
        toolbox = AgentToolbox(git_repo, "main", None, config)
        used = []
        for _ in range(2):
            read = _ai_message("", [{"name": "read_file", "args": {"path": "app.py"}, "id": "c1"}])
            out = _review(git_repo, _FakeLLM([read, _reply(_finding())]), toolbox=toolbox)
            used.append(out[0].tool_calls_used)
        assert used == [1, 1]

    def test_llm_exception_yields_one_failed_insufficient_evidence_finding(self, git_repo):
        llm = _AlwaysLLM(exc=RuntimeError("boom"))
        out = _review(git_repo, llm, llm_retries=0)
        assert len(out) == 1
        failed = out[0]
        assert failed.finding_id == "authz:s1:failed"
        assert failed.verdict == "insufficient_evidence"
        assert failed.cwe_id == "CWE-862"
        assert failed.confidence == 0.0
        assert failed.explanation == "Section review failed for app.py lines 10-12: boom"
        assert failed.category == "authz" and failed.agent == "authz_reviewer"

    def test_failed_message_names_every_file_in_section_order(self, git_repo):
        section = _section([_hunk("orders.py", start=5), _hunk("refunds.py", start=40)])
        out = _review(git_repo, _AlwaysLLM(exc=RuntimeError("boom")), section, llm_retries=0)
        text = out[0].explanation
        assert text.index("orders.py") < text.index("refunds.py")
        assert text.endswith(": boom")

    def test_failed_message_uses_old_side_lines_for_deletion_only_sections(self, git_repo):
        section = _section([_hunk(start=20, lines=("x", "y"), deletion=True)])
        out = _review(git_repo, _AlwaysLLM(exc=RuntimeError("boom")), section, llm_retries=0)
        assert out[0].explanation == "Section review failed for app.py lines 20-21: boom"

    def test_unparsable_reply_yields_one_failed_insufficient_evidence_finding(self, git_repo):
        llm = _AlwaysLLM(content="The change looks fine to me.")
        out = _review(git_repo, llm)
        assert len(out) == 1
        failed = out[0]
        assert failed.finding_id == "authz:s1:failed"
        assert failed.verdict == "insufficient_evidence"
        assert failed.cwe_id == "CWE-862"
        assert failed.confidence == 0.0
        assert failed.explanation == (
            "Section review returned no parsable findings for app.py lines 10-12"
        )


class TestTextToolCalls:
    """qwen2.5-coder writes tool calls as JSON text instead of native calls."""

    def test_text_tool_call_is_executed(self, git_repo):
        from lgtm.agents.base import parse_text_tool_calls

        assert parse_text_tool_calls(
            '{"name": "read_file", "arguments": {"path": "app.py"}}', {"read_file"}
        ) == [{"name": "read_file", "args": {"path": "app.py"}, "id": "text_call_0"}]

        toolbox = AgentToolbox(git_repo, "main")
        llm = _FakeLLM([
            _ai_message('{"name": "read_file", "arguments": {"path": "app.py"}}'),
            _ai_message('{"verdict": "safe"}'),
        ])
        out = run_tool_loop(llm, toolbox.build_tools(), "sys", "user", LGTMConfig())
        assert out == '{"verdict": "safe"}'
        assert toolbox.calls_used == 1

    def test_tagged_and_unknown_text_calls(self):
        from lgtm.agents.base import parse_text_tool_calls

        tagged = '<tool_call>\n{"name": "grep_repo", "arguments": {"pattern": "x"}}\n</tool_call>'
        assert parse_text_tool_calls(tagged, {"grep_repo"})[0]["name"] == "grep_repo"
        assert parse_text_tool_calls('{"name": "rm_rf", "arguments": {}}', {"read_file"}) == []
        # A final verdict is never mistaken for a tool call
        assert parse_text_tool_calls('{"verdict": "safe", "name": "read_file"}', {"read_file"}) == []


def test_string_arguments_parsed():
    from lgtm.agents.base import parse_text_tool_calls

    calls = parse_text_tool_calls(
        '{"name": "read_file", "arguments": "{\\"path\\": \\"app.py\\"}"}', {"read_file"}
    )
    assert calls and calls[0]["args"] == {"path": "app.py"}


OK = '{"verdict": "safe"}'


def _call(name, args, id="c1"):
    return _ai_message("", tool_calls=[{"name": name, "args": args, "id": id}])


def _kind(message):
    return type(message).__name__


class TestResilienceConfig:
    def test_defaults(self):
        cfg = LGTMConfig()
        assert cfg.llm_retries == 3
        assert cfg.llm_backoff_seconds == (2.0, 4.0, 8.0)
        assert cfg.max_invalid_tool_inputs == 3
        assert cfg.max_answer_reasks == 3

    def test_from_file_accepts_json_lists(self, tmp_path):
        path = tmp_path / "c.json"
        path.write_text('{"llm_backoff_seconds": [1, 2], "llm_retries": 1}', encoding="utf-8")
        cfg = LGTMConfig.from_file(path)
        assert list(cfg.llm_backoff_seconds) == [1, 2]
        assert cfg.llm_retries == 1


class TestLlmRetry:
    def test_retries_then_succeeds_with_backoff(self, sleeps):
        llm = _RecordingLLM([RuntimeError("x"), RuntimeError("x"), _ai_message(OK)])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == OK
        assert sleeps == [2.0, 4.0]

    def test_gives_up_after_three_retries_and_raises(self, sleeps):
        llm = _RecordingLLM([RuntimeError("x") for _ in range(4)])
        with pytest.raises(RuntimeError):
            run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert sleeps == [2.0, 4.0, 8.0]
        assert len(llm.seen) == 4

    def test_forced_final_invoke_is_retried(self, git_repo, sleeps):
        toolbox = AgentToolbox(git_repo, "main")
        llm = _RecordingLLM([
            _call("read_file", {"path": "app.py"}),
            RuntimeError("x"),
            _ai_message(OK),
        ])
        out = run_tool_loop(
            llm, toolbox.build_tools(), "sys", "user", LGTMConfig(max_agent_iterations=1)
        )
        assert out == OK
        assert sleeps == [2.0]
        assert llm.channels == ["bound", "unbound", "unbound"]

    def test_backoff_uses_config_values_and_repeats_last(self, sleeps):
        llm = _RecordingLLM([RuntimeError("x"), RuntimeError("x"), _ai_message(OK)])
        cfg = LGTMConfig(llm_retries=2, llm_backoff_seconds=[1.0])
        out = run_tool_loop(llm, [], "sys", "user", cfg)
        assert out == OK
        assert sleeps == [1.0, 1.0]

    def test_zero_retries_raises_immediately(self, sleeps):
        llm = _RecordingLLM([RuntimeError("x")])
        with pytest.raises(RuntimeError):
            run_tool_loop(llm, [], "sys", "user", LGTMConfig(llm_retries=0))
        assert sleeps == []

    def test_retry_logs_attempt_numbers(self, caplog):
        caplog.set_level(logging.DEBUG, logger="lgtm.agents.base")
        llm = _RecordingLLM([RuntimeError("x"), RuntimeError("x"), _ai_message(OK)])
        run_tool_loop(llm, [], "sys", "user-secret-prompt", LGTMConfig())
        assert "attempt 1 of 4" in caplog.text
        assert "attempt 2 of 4" in caplog.text
        assert "user-secret-prompt" not in caplog.text


class TestToolInputValidation:
    def test_unknown_native_tool_returns_invalid_input_tool_message(self):
        llm = _RecordingLLM([_call("rm_rf", {}), _ai_message(OK)])
        run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        last = llm.seen[1][-1]
        assert _kind(last) == "ToolMessage"
        assert last.tool_call_id == "c1"
        assert last.content == (
            "ERROR: invalid input for tool 'rm_rf': unknown tool; "
            "available tools: none. Fix the arguments and call the tool again."
        )

    def test_missing_argument_spends_budget(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        llm = _RecordingLLM([
            _call("read_file", {}),
            _ai_message("no json"),
            _ai_message(OK),
        ])
        out = run_tool_loop(
            llm, toolbox.build_tools(), "sys", "user", LGTMConfig(require_tool_use=True)
        )
        assert toolbox.calls_used == 1
        last = llm.seen[1][-1]
        assert _kind(last) == "ToolMessage"
        assert last.content.startswith("ERROR: invalid input for tool 'read_file': path")
        assert last.content.endswith("Fix the arguments and call the tool again.")
        assert "call at least one tool" in llm.seen[2][-1].content
        assert out == OK

    def test_text_call_invalid_args_answered_as_human_message(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        llm = _RecordingLLM([
            _ai_message('{"name": "read_file", "arguments": {}}'),
            _ai_message(OK),
        ])
        run_tool_loop(llm, toolbox.build_tools(), "sys", "user", LGTMConfig())
        last = llm.seen[1][-1]
        assert _kind(last) == "HumanMessage"
        assert "ERROR: invalid input for tool 'read_file'" in last.content
        assert toolbox.calls_used == 1

    def test_third_invalid_input_forces_final_answer(self, caplog):
        caplog.set_level(logging.WARNING, logger="lgtm.agents.base")
        llm = _RecordingLLM([
            _call("bad", {}, id="c1"),
            _call("bad", {}, id="c2"),
            _call("bad", {}, id="c3"),
            _ai_message(OK),
        ])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == OK
        assert llm.channels == ["bound", "bound", "bound", "unbound"]
        assert "Produce your final JSON verdict NOW" in llm.seen[3][-1].content
        assert "Invalid tool input (1 of 3)" in caplog.text
        assert "(3 of 3)" in caplog.text

    def test_two_invalid_inputs_keep_tools_available(self):
        llm = _RecordingLLM([
            _call("bad", {}, id="c1"),
            _call("bad", {}, id="c2"),
            _ai_message(OK),
        ])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == OK
        assert llm.channels == ["bound", "bound", "bound"]
        for prompt in llm.seen:
            assert "Produce your final" not in str(
                [getattr(m, "content", "") for m in prompt]
            )

    def test_whole_batch_answered_before_forcing_final(self):
        batch = _ai_message("", tool_calls=[
            {"name": "bad", "args": {}, "id": "c1"},
            {"name": "bad", "args": {}, "id": "c2"},
            {"name": "bad", "args": {}, "id": "c3"},
        ])
        llm = _RecordingLLM([batch, _ai_message(OK)])
        run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert llm.channels == ["bound", "unbound"]
        prompt = llm.seen[1]
        tool_messages = [m for m in prompt if _kind(m) == "ToolMessage"]
        assert [m.tool_call_id for m in tool_messages] == ["c1", "c2", "c3"]
        assert prompt[-4:-1] == tool_messages
        assert _kind(prompt[-1]) == "HumanMessage"
        assert "Produce your final JSON verdict NOW" in prompt[-1].content

    def test_valid_call_after_invalid_still_executes(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        llm = _RecordingLLM([
            _call("bad", {}, id="c1"),
            _call("read_file", {"path": "app.py"}, id="c2"),
            _ai_message(OK),
        ])
        out = run_tool_loop(llm, toolbox.build_tools(), "sys", "user", LGTMConfig())
        assert out == OK
        assert toolbox.calls_used == 2


class TestFinalAnswerReask:
    def test_reasks_with_unbound_llm_until_json(self, caplog):
        caplog.set_level(logging.WARNING, logger="lgtm.agents.base")
        llm = _RecordingLLM([_ai_message("not json"), _ai_message("still no"), _ai_message(OK)])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == OK
        assert llm.channels == ["bound", "unbound", "unbound"]
        assert "not a valid JSON object" in llm.seen[1][-1].content
        assert "re-asking (1 of 3)" in caplog.text
        assert "not a valid JSON object" in llm.seen[2][-1].content
        assert any(m.content == "not json" for m in llm.seen[2])
        assert any(m.content == "still no" for m in llm.seen[2])

    def test_returns_last_content_after_three_failed_reasks(self):
        llm = _RecordingLLM([_ai_message(t) for t in "abcd"])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == "d"
        assert len(llm.seen) == 4
        assert (
            parse_agent_output(out, "f").explanation
            == "Agent did not produce parsable structured output."
        )

    def test_reasks_do_not_consume_iterations(self):
        llm = _RecordingLLM([_ai_message("bad"), _ai_message(OK)])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig(max_agent_iterations=1))
        assert out == OK
        assert "Produce your final" not in llm.seen[1][-1].content

    def test_forced_final_answer_is_validated(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        llm = _RecordingLLM([
            _call("read_file", {"path": "app.py"}),
            _ai_message("bad"),
            _ai_message(OK),
        ])
        out = run_tool_loop(
            llm, toolbox.build_tools(), "sys", "user", LGTMConfig(max_agent_iterations=1)
        )
        assert out == OK
        assert llm.channels == ["bound", "unbound", "unbound"]

    def test_non_object_json_is_reasked(self, sleeps):
        llm = _RecordingLLM([_ai_message("[1, 2]"), RuntimeError("x"), _ai_message(OK)])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == OK
        assert sleeps == [2.0]

    def test_pushback_precedes_reask(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        llm = _RecordingLLM([_ai_message("no json"), _ai_message(OK)])
        out = run_tool_loop(
            llm, toolbox.build_tools(), "sys", "user", LGTMConfig(require_tool_use=True)
        )
        assert out == OK
        assert "call at least one tool" in llm.seen[1][-1].content
        assert llm.channels == ["bound", "bound"]

    def test_reask_cap_is_configurable(self):
        llm = _RecordingLLM([_ai_message("a"), _ai_message("b"), _ai_message("c")])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig(max_answer_reasks=1))
        assert len(llm.seen) == 2
        assert out == "b"
