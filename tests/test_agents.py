"""Tests for agent tools, output parsing, and the agent loop (LLM mocked)."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from lgtm.agents.authz_reviewer import AuthzReviewerAgent
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.base import (
    RunRecord,
    extract_json_object,
    fill_record,
    parse_agent_output,
    run_tool_loop,
)
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import LineChange
from lgtm.graph.snapshot import resolve_refs
from lgtm.review.sections import HunkRef, Section
from lgtm.sast.semgrep_runner import SemgrepFinding


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
        assert not f.verdict
        assert not hasattr(f, "confidence")
        assert len(f.evidence) == 2
        assert f.evidence[1].type == "policy"

    def test_malformed_output_degrades_gracefully(self):
        f = parse_agent_output("I think it's fine lol", "f2", default_cwe="CWE-89")
        assert not f.verdict
        assert f.finding_id == "f2"
        assert f.cwe_id == "CWE-89"

    def test_model_verdict_and_confidence_are_ignored(self):
        f = parse_agent_output('{"verdict": "exploitable!!", "confidence": 5}', "f3")
        assert not f.verdict
        assert not hasattr(f, "confidence")

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
            _finding(cwe_id="CWE-862", line=12),
        )])
        out = _review(git_repo, llm)
        assert [f.finding_id for f in out] == ["authz:s1:1", "authz:s1:2"]
        assert not any(f.verdict for f in out)
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

    @pytest.mark.parametrize("token", ["Infinity", "-Infinity", "NaN", "1e999"])
    @pytest.mark.parametrize("deletion", [False, True], ids=["added", "deletion_only"])
    def test_non_finite_line_falls_back_to_the_contract_line_without_raising(
        self, git_repo, token, deletion
    ):
        hunk = _hunk(start=20, lines=("x", "y"), deletion=True) if deletion else _hunk(start=10)
        raw = json.dumps({"findings": [_finding(line="@@")]}).replace('"@@"', token)
        assert not isinstance(json.loads(raw)["findings"][0]["line"], str)
        out = _review(git_repo, _FakeLLM([_ai_message(raw)]), _section([hunk]))
        assert [f.finding_id for f in out] == ["authz:s1:1"]
        assert out[0].line == (20 if deletion else 10)

    def test_deletion_only_section_falls_back_to_old_start(self, git_repo):
        section = _section([_hunk(start=20, lines=("x", "y"), deletion=True)])
        raw = _finding()
        del raw["line"]
        out = _review(git_repo, _FakeLLM([_reply(raw)]), section)
        assert out[0].line == 20

    def test_deletion_only_hunk_with_context_lines_falls_back_to_old_start(self, git_repo):
        changes = [
            LineChange("context", "ctx", 20, 22),
            LineChange("del", "x", 21, None),
            LineChange("del", "y", 22, None),
            LineChange("del", "z", 23, None),
            LineChange("context", "ctx2", 24, 23),
            LineChange("context", "ctx3", 25, 24),
        ]
        hunk = HunkRef(
            hunk_id="app.py#20", file="app.py", old_start=20, old_count=6,
            new_start=22, new_count=3, change="delete", changes=changes,
        )
        raw = _finding()
        del raw["line"]
        out = _review(git_repo, _FakeLLM([_reply(raw)]), _section([hunk]))
        assert out[0].line == 20

    @staticmethod
    def _assert_no_candidates(out):
        assert out == []

    @pytest.mark.parametrize("token", ["1e999", "Infinity"])
    def test_non_finite_evidence_line_yields_the_unparsable_failure_finding(
        self, git_repo, token
    ):
        evidence = {"type": "code", "file": "app.py", "lines": ["@@", 2], "content": "x = 1"}
        reply = json.dumps({"findings": [_finding(verdict="possible", evidence=[evidence])]})
        reply = reply.replace('"@@"', token)
        assert not isinstance(json.loads(reply)["findings"][0]["evidence"][0]["lines"][0], str)
        self._assert_no_candidates(_review(git_repo, _AlwaysLLM(content=reply)))

    @pytest.mark.parametrize("evidence", [5, True], ids=["int", "bool"])
    def test_non_iterable_evidence_yields_the_unparsable_failure_finding(
        self, git_repo, evidence
    ):
        out = _review(git_repo, _AlwaysLLM(content=_reply(_finding(evidence=evidence)).content))
        self._assert_no_candidates(out)

    @pytest.mark.parametrize("lines", [[0, 0], [-3, -3], [2**31, 2**31]], ids=["zero", "negative", "huge"])
    def test_invalid_evidence_line_citation_drops_the_candidate_after_the_retry_budget(
        self, git_repo, lines
    ):
        evidence = {"type": "code", "file": "app.py", "lines": lines, "content": "a = 1"}
        llm = _SequenceLLM(_reply(_finding(evidence=[evidence])).content)
        assert _review(git_repo, llm, toolbox=_snapshot_toolbox(git_repo)) == []
        assert llm.calls == 4

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

    def test_llm_exception_yields_no_candidate_and_does_not_raise(self, git_repo):
        out = _review(git_repo, _AlwaysLLM(exc=RuntimeError("boom")), llm_retries=0)
        assert out == []

    def test_unparsable_reply_yields_no_candidate_and_does_not_raise(self, git_repo):
        out = _review(git_repo, _AlwaysLLM(content="The change looks fine to me."))
        assert out == []


class _SequenceLLM:
    """Replays replies in order, repeating the last one; counts model calls."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        reply = self.replies[min(self.calls, len(self.replies) - 1)]
        self.calls += 1
        return _ai_message(reply)


NO_RETRY_CONFIG = dict(llm_retries=0, max_answer_reasks=0)
UNPARSABLE = "The change looks fine to me."
SEMGREP_HIT = SemgrepFinding(
    rule_id="py.sqli.fstring", path="app.py", start_line=6, end_line=6,
    message="SQL built from user input", severity="ERROR", cwe=["CWE-89"],
    matched_code="cursor.execute(f\"...\")",
)
PR_SQL_LINE = "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
CODE_ITEM = {
    "type": "code", "file": "app.py", "lines": [6, 6], "content": PR_SQL_LINE, "snapshot": "pr",
}
POLICY_ITEM = {"type": "policy", "source": "policy.md", "content": "Only admins may delete users."}


def _snapshot_toolbox(git_repo, config=None):
    return AgentToolbox(
        git_repo, "main", None, config or LGTMConfig(),
        shas=resolve_refs(git_repo, "main", "pr"),
    )


def _authz_candidates(git_repo, llm):
    config = LGTMConfig(**NO_RETRY_CONFIG)
    return _review(git_repo, llm, toolbox=_snapshot_toolbox(git_repo, config), **NO_RETRY_CONFIG)


def _triage_candidate(git_repo, llm):
    config = LGTMConfig(**NO_RETRY_CONFIG)
    agent = SASTTriageAgent(_snapshot_toolbox(git_repo, config), config, llm=llm)
    return agent.triage(SEMGREP_HIT, None)


def _triage_reply(**fields):
    return json.dumps({
        "verdict": "vulnerable", "confidence": 0.9, "cwe_id": "CWE-89",
        "explanation": "f-string reaches execute", "evidence": [CODE_ITEM, POLICY_ITEM],
        **fields,
    })


def _assert_structured_candidate(candidate, *, cwe, claim):
    assert candidate.cwe_id == cwe
    assert candidate.explanation == claim
    code, policy = candidate.evidence
    assert (code.type, code.file, list(code.lines), code.content, code.snapshot) == (
        "code", "app.py", [6, 6], PR_SQL_LINE, "pr",
    )
    assert (policy.type, policy.source) == ("policy", "policy.md")
    assert not candidate.verdict
    assert "confidence" not in candidate.model_dump()
    assert not candidate.severity
    assert candidate.provenance_confidence is None and candidate.judged is False
    assert code.grounded_in_pr is None


class TestCandidateContract:
    def test_authz_candidate_carries_claim_cwe_and_provenance_with_no_verdict_or_confidence(
        self, git_repo
    ):
        raw = _finding(evidence=[CODE_ITEM, POLICY_ITEM], explanation="no ownership check")
        [candidate] = _authz_candidates(git_repo, _SequenceLLM(_reply(raw).content))
        _assert_structured_candidate(candidate, cwe="CWE-639", claim="no ownership check")

    def test_sast_candidate_carries_the_same_fields_plus_semgrep_rule_severity_and_message(
        self, git_repo
    ):
        candidate = _triage_candidate(git_repo, _SequenceLLM(_triage_reply()))
        _assert_structured_candidate(
            candidate, cwe="CWE-89", claim="f-string reaches execute"
        )
        assert (candidate.semgrep_rule_id, candidate.semgrep_severity, candidate.semgrep_message) == (
            SEMGREP_HIT.rule_id, SEMGREP_HIT.severity, SEMGREP_HIT.message,
        )

    def test_candidate_without_any_model_verdict_or_confidence_is_still_emitted(self, git_repo):
        raw = {k: v for k, v in _finding().items() if k not in ("verdict", "confidence")}
        [candidate] = _authz_candidates(git_repo, _SequenceLLM(_reply(raw).content))
        assert candidate.cwe_id == "CWE-639" and not candidate.verdict


class TestUnparsableAnswerRetry:
    GOOD_AUTHZ = _reply(_finding(explanation="from the retry")).content
    GOOD_TRIAGE = _triage_reply(explanation="from the retry")

    @pytest.mark.parametrize("agent", ["authz", "triage"])
    def test_an_answer_that_never_parses_is_attempted_four_times_and_raises_nothing(
        self, git_repo, agent
    ):
        llm = _SequenceLLM(UNPARSABLE)
        if agent == "authz":
            _authz_candidates(git_repo, llm)
        else:
            _triage_candidate(git_repo, llm)
        assert llm.calls == 4

    @pytest.mark.parametrize("unparsable_attempts", [1, 2, 3])
    def test_authz_uses_the_candidates_of_the_first_attempt_that_parses(
        self, git_repo, unparsable_attempts
    ):
        llm = _SequenceLLM(*[UNPARSABLE] * unparsable_attempts, self.GOOD_AUTHZ)
        out = _authz_candidates(git_repo, llm)
        assert [f.explanation for f in out] == ["from the retry"]
        assert llm.calls == unparsable_attempts + 1

    @pytest.mark.parametrize("unparsable_attempts", [1, 2, 3])
    def test_triage_uses_the_candidate_of_the_first_attempt_that_parses(
        self, git_repo, unparsable_attempts
    ):
        llm = _SequenceLLM(*[UNPARSABLE] * unparsable_attempts, self.GOOD_TRIAGE)
        candidate = _triage_candidate(git_repo, llm)
        assert candidate.explanation == "from the retry"
        assert llm.calls == unparsable_attempts + 1

    def test_a_parsable_first_answer_is_not_retried(self, git_repo):
        llm = _SequenceLLM(self.GOOD_AUTHZ)
        _authz_candidates(git_repo, llm)
        assert llm.calls == 1


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
        assert "Produce your final JSON answer NOW" in llm.seen[3][-1].content
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
        assert "Produce your final JSON answer NOW" in prompt[-1].content

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


@pytest.mark.parametrize("module", ["lgtm.review.sections", "lgtm.review.dedup"])
def test_review_modules_import_in_a_fresh_interpreter(module):
    import lgtm

    root = str(Path(lgtm.__file__).resolve().parent.parent)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([root, os.environ.get("PYTHONPATH", "")])}
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        capture_output=True, text=True, env=env, timeout=120,
    )
    assert result.returncode == 0, result.stderr

def test_build_llm_passes_timeout_and_output_cap(monkeypatch):
    """Regression: llm_timeout existed in config but never reached the client,
    so a runaway generation blocked a benchmark run for over an hour."""
    import langchain_ollama

    from lgtm.agents.base import build_llm
    from lgtm.config import LGTMConfig

    captured = {}

    class FakeChatOllama:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(langchain_ollama, "ChatOllama", FakeChatOllama)
    config = LGTMConfig(ollama_model="m", llm_timeout=42, llm_max_output_tokens=99)
    build_llm(config)

    assert captured["client_kwargs"] == {"timeout": 42}
    assert captured["num_predict"] == 99


def test_real_chat_ollama_accepts_our_kwargs():
    """The installed langchain-ollama must accept the kwargs build_llm passes."""
    from lgtm.agents.base import build_llm
    from lgtm.config import LGTMConfig

    llm = build_llm(LGTMConfig(ollama_model="m"))  # no network: construction only
    assert llm.num_predict == 2048


BASE_DEF_LINE = "def get_user(cursor, user_id):"
GOOD_PR = CODE_ITEM
GOOD_BASE = {
    "type": "code", "file": "app.py", "lines": [1, 1], "content": BASE_DEF_LINE, "snapshot": "base",
}
UNRESOLVED = {
    "file missing": {**GOOD_PR, "file": "nope.py"},
    "lines out of range": {**GOOD_PR, "lines": [90, 91]},
    "snippet mismatch": {**GOOD_PR, "content": "os.system(user_input)"},
    "snippet only in other snapshot": {**GOOD_PR, "snapshot": "base"},
}
BAD = pytest.mark.parametrize("bad", list(UNRESOLVED.values()), ids=list(UNRESOLVED))


def _authz_agent(git_repo, llm):
    config = LGTMConfig(llm_retries=0, max_answer_reasks=0)
    return AuthzReviewerAgent(_snapshot_toolbox(git_repo, config), config, llm=llm)


def _triage_agent(git_repo, llm):
    config = LGTMConfig(llm_retries=0, max_answer_reasks=0)
    return SASTTriageAgent(_snapshot_toolbox(git_repo, config), config, llm=llm)


def _authz_reply(*findings):
    return _reply(*findings).content


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


class TestUnresolvedReferenceReask:
    @BAD
    def test_authz_reasks_inside_the_parse_budget_and_uses_the_first_resolving_attempt(
        self, git_repo, bad
    ):
        llm = _SequenceLLM(
            _authz_reply(_finding(explanation="first", evidence=[bad])),
            _authz_reply(_finding(explanation="second", evidence=[GOOD_PR])),
        )
        agent = _authz_agent(git_repo, llm)
        out = agent.review_section(_section())
        assert [f.explanation for f in out] == ["second"]
        assert [e.content for e in out[0].evidence] == [PR_SQL_LINE]
        assert llm.calls == 2 and agent.errors == []

    @BAD
    def test_triage_reasks_inside_the_parse_budget_and_uses_the_first_resolving_attempt(
        self, git_repo, bad
    ):
        llm = _SequenceLLM(
            _triage_reply(explanation="first", evidence=[bad]),
            _triage_reply(explanation="second", evidence=[GOOD_PR]),
        )
        agent = _triage_agent(git_repo, llm)
        candidate = agent.triage(SEMGREP_HIT, None)
        assert candidate.explanation == "second"
        assert llm.calls == 2 and agent.errors == []

    def test_resolving_references_on_both_snapshots_are_not_reasked(self, git_repo):
        llm = _SequenceLLM(_authz_reply(_finding(evidence=[GOOD_PR, GOOD_BASE])))
        out = _authz_agent(git_repo, llm).review_section(_section())
        assert len(out) == 1 and len(out[0].evidence) == 2 and llm.calls == 1

    def test_unresolved_references_never_exceed_the_unparsable_answer_budget(self, git_repo):
        llm = _SequenceLLM(_authz_reply(_finding(evidence=[UNRESOLVED["file missing"]])))
        _authz_agent(git_repo, llm).review_section(_section())
        assert llm.calls == 4

    def test_triage_unresolved_references_never_exceed_the_unparsable_answer_budget(
        self, git_repo
    ):
        llm = _SequenceLLM(_triage_reply(evidence=[UNRESOLVED["file missing"]]))
        _triage_agent(git_repo, llm).triage(SEMGREP_HIT, None)
        assert llm.calls == 4


class TestUnresolvedReferencesAfterBudget:
    @BAD
    def test_authz_drops_unresolved_items_and_keeps_the_valid_ones(self, git_repo, bad):
        llm = _SequenceLLM(_authz_reply(_finding(evidence=[bad, GOOD_PR, GOOD_BASE])))
        agent = _authz_agent(git_repo, llm)
        [candidate] = agent.review_section(_section())
        assert [(e.file, e.snapshot) for e in candidate.evidence] == [
            ("app.py", "pr"), ("app.py", "base"),
        ]
        assert llm.calls == 4 and agent.errors == []

    @BAD
    def test_triage_drops_unresolved_items_and_keeps_the_valid_ones(self, git_repo, bad):
        llm = _SequenceLLM(_triage_reply(evidence=[bad, GOOD_PR]))
        agent = _triage_agent(git_repo, llm)
        candidate = agent.triage(SEMGREP_HIT, None)
        assert [(e.file, e.snapshot) for e in candidate.evidence] == [("app.py", "pr")]
        assert llm.calls == 4 and agent.errors == []

    @BAD
    def test_authz_candidate_with_no_valid_code_item_is_dropped_and_logged_not_errored(
        self, git_repo, bad, caplog
    ):
        llm = _SequenceLLM(_authz_reply(_finding(evidence=[bad])))
        agent = _authz_agent(git_repo, llm)
        with caplog.at_level(logging.WARNING):
            assert agent.review_section(_section()) == []
        assert any("s1" in m for m in _warnings(caplog))
        assert agent.errors == []

    def test_other_candidates_of_the_section_are_still_reported(self, git_repo):
        llm = _SequenceLLM(_authz_reply(
            _finding(explanation="invented", evidence=[UNRESOLVED["file missing"]]),
            _finding(explanation="grounded", evidence=[GOOD_PR]),
        ))
        agent = _authz_agent(git_repo, llm)
        out = agent.review_section(_section())
        assert [f.explanation for f in out] == ["grounded"]
        assert agent.errors == []

    @BAD
    def test_triage_candidate_with_no_valid_code_item_is_dropped_and_logged_not_errored(
        self, git_repo, bad, caplog
    ):
        llm = _SequenceLLM(_triage_reply(evidence=[bad]))
        agent = _triage_agent(git_repo, llm)
        with caplog.at_level(logging.WARNING):
            assert agent.triage(SEMGREP_HIT, None) is None
        assert any(SEMGREP_HIT.finding_id in m for m in _warnings(caplog))
        assert agent.errors == []

    def test_a_dropped_triage_candidate_does_not_stop_the_next_hit(self, git_repo):
        agent = _triage_agent(
            git_repo, _SequenceLLM(_triage_reply(evidence=[UNRESOLVED["file missing"]]))
        )
        assert agent.triage(SEMGREP_HIT, None) is None
        agent.llm = _SequenceLLM(_triage_reply(evidence=[GOOD_PR]))
        assert agent.triage(SEMGREP_HIT, None) is not None

    def test_unparsable_replies_after_the_budget_remain_the_only_agent_errors(self, git_repo):
        agent = _authz_agent(git_repo, _SequenceLLM(UNPARSABLE))
        assert agent.review_section(_section()) == []
        assert [e["source"] for e in agent.errors] == ["s1"]
        triage = _triage_agent(git_repo, _SequenceLLM(UNPARSABLE))
        assert triage.triage(SEMGREP_HIT, None) is None
        assert [e["source"] for e in triage.errors] == [SEMGREP_HIT.finding_id]


class TestGuardrailExemptions:
    def test_policy_items_are_not_checked_for_resolution(self, git_repo):
        ghost_policy = {"type": "policy", "source": "missing-policy.md", "content": "nothing"}
        llm = _SequenceLLM(_authz_reply(_finding(evidence=[GOOD_PR, ghost_policy])))
        [candidate] = _authz_agent(git_repo, llm).review_section(_section())
        assert [e.type for e in candidate.evidence] == ["code", "policy"]
        assert llm.calls == 1

    def test_candidate_citing_no_code_is_not_reasked_or_dropped(self, git_repo):
        policy_only = {"type": "policy", "source": "policy.md", "content": "x"}
        llm = _SequenceLLM(_authz_reply(_finding(evidence=[policy_only]), _finding(evidence=[])))
        out = _authz_agent(git_repo, llm).review_section(_section())
        assert len(out) == 2 and llm.calls == 1


BASE_SHA, PR_SHA = "a" * 40, "b" * 40


def _function(name, tag):
    """A function whose changed line sits more than three lines from both ends."""
    lines = [f"def {name}():", f'    top = "{tag}_TOP"']
    lines += [f"    before_{i} = {i}" for i in range(10)]
    lines += [f'    target = "{tag}_TARGET"']
    lines += [f"    after_{i} = {i}" for i in range(10)]
    lines += [f'    bottom = "{tag}_BOTTOM"', "    return None", ""]
    return lines


def _padding():
    return [f"def pad_{i}(): return {i}" for i in range(14)]


def _target_line(lines, tag):
    return next(n for n, text in enumerate(lines, 1) if f"{tag}_TARGET" in text)


def _change_hunk(lines, target, kind, file="app.py"):
    """Hunk around line ``target`` of ``lines`` with three context lines on each side.

    ``lines`` is the base file for a removal and the PR file for an addition.
    """
    before = [(n, lines[n - 1]) for n in range(target - 3, target)]
    after = [(n, lines[n - 1]) for n in range(target + 1, target + 4)]
    changes = [LineChange("context", text, n, n) for n, text in before]
    if kind == "del":
        changes.append(LineChange("del", lines[target - 1], target, None))
        changes += [LineChange("context", text, n, n - 1) for n, text in after]
        old_count, new_count = 7, 6
    else:
        changes.append(LineChange("add", lines[target - 1], None, target))
        changes += [LineChange("context", text, n, n) for n, text in after]
        old_count, new_count = 6, 7
    return HunkRef(
        hunk_id=f"{file}#{target}", file=file, old_start=target - 3, old_count=old_count,
        new_start=target - 3, new_count=new_count,
        change="delete" if kind == "del" else "add", changes=changes,
    )


@pytest.fixture
def snapshots(monkeypatch):
    """Committed file contents per snapshot SHA, served through the toolbox's git runner."""
    files: dict[tuple[str, str], str] = {}

    def fake_run_git(repo, args, timeout):
        if args[:2] == ["cat-file", "blob"]:
            sha, _, rel = args[2].partition(":")
            if (sha, rel) in files:
                return subprocess.CompletedProcess(args, 0, stdout=files[(sha, rel)], stderr="")
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="")

    monkeypatch.setattr("lgtm.agents.tools.run_git", fake_run_git)

    def put(base=None, pr=None, path="app.py"):
        for sha, lines in ((BASE_SHA, base), (PR_SHA, pr)):
            if lines is not None:
                files[(sha, path)] = "\n".join(lines) + "\n"

    return put


def _initial_input(section, tmp_path, reply=None, config=None):
    config = config or LGTMConfig()
    toolbox = AgentToolbox(
        tmp_path, "main", None, config, shas={"base": BASE_SHA, "pr": PR_SHA}
    )
    llm = _RecordingLLM([reply or _reply()])
    agent = AuthzReviewerAgent(toolbox, config, llm=llm)
    findings = agent.review_section(section)
    text = "\n".join(str(getattr(m, "content", "")) for m in llm.seen[0])
    return text, findings, agent


class TestEnclosingDefinitionInInitialInput:
    def test_removed_only_hunk_brings_the_whole_enclosing_function_from_the_base_snapshot(
        self, snapshots, tmp_path
    ):
        base = _function("delete_thread", "DEL") + _function("neighbour", "NEAR")
        target = _target_line(base, "DEL")
        pr = _padding() + [line for n, line in enumerate(base, 1) if n != target]
        snapshots(base=base, pr=pr)
        section = _section([_change_hunk(base, target, "del")])

        text, _, _ = _initial_input(section, tmp_path)

        assert "DEL_TOP" in text and "DEL_BOTTOM" in text
        assert "NEAR_TOP" not in text and "NEAR_BOTTOM" not in text

    def test_added_hunk_brings_the_whole_enclosing_function_from_the_pr_snapshot(
        self, snapshots, tmp_path
    ):
        pr = _function("add_thread", "ADD") + _function("neighbour", "NEAR")
        target = _target_line(pr, "ADD")
        base = _padding() + [line for n, line in enumerate(pr, 1) if n != target]
        snapshots(base=base, pr=pr)
        section = _section([_change_hunk(pr, target, "add")])

        text, _, _ = _initial_input(section, tmp_path)

        assert "ADD_TOP" in text and "ADD_BOTTOM" in text
        assert "NEAR_TOP" not in text and "NEAR_BOTTOM" not in text

    def test_each_hunk_of_a_section_brings_its_own_enclosing_function(self, snapshots, tmp_path):
        pr = (
            _function("first", "ONE") + _function("untouched", "MID") + _function("last", "TWO")
        )
        snapshots(base=_padding(), pr=pr)
        section = _section([
            _change_hunk(pr, _target_line(pr, "ONE"), "add"),
            _change_hunk(pr, _target_line(pr, "TWO"), "add"),
        ])

        text, _, _ = _initial_input(section, tmp_path)

        for tag in ("ONE", "TWO"):
            assert f"{tag}_TOP" in text and f"{tag}_BOTTOM" in text
        assert "MID_TOP" not in text and "MID_BOTTOM" not in text

    def test_one_hunk_removing_from_one_function_and_adding_to_another_brings_both(
        self, snapshots, tmp_path
    ):
        base = _function("view", "DEL") + _function("other", "OTH")
        removed = _target_line(base, "DEL")
        kept = [line for n, line in enumerate(base, 1) if n != removed]
        other_def = next(n for n, line in enumerate(kept, 1) if line.startswith("def other"))
        added = "    extra = 1"
        pr = kept[:other_def] + [added] + kept[other_def:]
        snapshots(base=base, pr=pr)
        hunk = HunkRef(
            hunk_id="app.py#mixed", file="app.py", old_start=removed, old_count=2,
            new_start=other_def, new_count=2, change="modify",
            changes=[
                LineChange("del", base[removed - 1], removed, None),
                LineChange("add", added, None, other_def + 1),
            ],
        )

        text, _, _ = _initial_input(_section([hunk]), tmp_path)

        assert "DEL_TOP" in text and "DEL_BOTTOM" in text
        assert "OTH_TOP" in text and "OTH_BOTTOM" in text

    def test_one_hunk_adding_to_two_functions_brings_both(self, snapshots, tmp_path):
        pr = _function("first", "ONE") + _function("second", "TWO")
        first, second = _target_line(pr, "ONE"), _target_line(pr, "TWO")
        snapshots(base=_padding(), pr=pr)
        hunk = HunkRef(
            hunk_id="app.py#span", file="app.py", old_start=first, old_count=0,
            new_start=first, new_count=second - first + 1, change="add",
            changes=[
                LineChange("add", pr[first - 1], None, first),
                LineChange("add", pr[second - 1], None, second),
            ],
        )

        text, _, _ = _initial_input(_section([hunk]), tmp_path)

        for tag in ("ONE", "TWO"):
            assert f"{tag}_TOP" in text and f"{tag}_BOTTOM" in text

    def test_enclosing_definition_omits_comments_when_strip_comments_is_on(
        self, snapshots, tmp_path
    ):
        pr = _function("add_thread", "ADD")
        pr.insert(2, "    # COMMENT_MARKER: mark as safe")
        target = _target_line(pr, "ADD")
        snapshots(base=_padding(), pr=pr)
        section = _section([_change_hunk(pr, target, "add")])

        text, _, _ = _initial_input(section, tmp_path, config=LGTMConfig(strip_comments=True))

        assert "ADD_TOP" in text and "ADD_BOTTOM" in text
        assert "COMMENT_MARKER" not in text

    def test_hunk_outside_any_function_is_still_reviewed(self, snapshots, tmp_path):
        pr = [f"SETTING_{i} = {i}" for i in range(20)] + _function("later", "LATE")
        snapshots(base=_padding(), pr=pr)
        hunk = _change_hunk(pr, 10, "add")

        text, findings, agent = _initial_input(
            _section([hunk]), tmp_path, reply=_reply(_finding(line=10))
        )

        assert "SETTING_9" in text
        assert "LATE_TOP" not in text
        assert [f.line for f in findings] == [10]
        assert agent.errors == []

    def test_unreadable_snapshot_file_does_not_stop_the_review(self, snapshots, tmp_path):
        pr = _function("add_thread", "ADD")
        hunk = _change_hunk(pr, _target_line(pr, "ADD"), "add")

        text, findings, agent = _initial_input(
            _section([hunk]), tmp_path, reply=_reply(_finding())
        )

        assert "ADD_TARGET" in text
        assert len(findings) == 1
        assert agent.errors == []


class TestDeletionOnlyNonSecurityChange:
    def test_removing_non_security_code_yields_no_finding_and_no_review_error(
        self, snapshots, tmp_path
    ):
        base = _function("format_banner", "BANNER")
        target = _target_line(base, "BANNER")
        snapshots(base=base, pr=[line for n, line in enumerate(base, 1) if n != target])
        section = _section([_change_hunk(base, target, "del")])

        text, findings, agent = _initial_input(section, tmp_path)

        assert "-" + base[target - 1] in text
        assert findings == []
        assert agent.errors == []


class TestFillRecordToolCallBudget:
    @pytest.mark.parametrize(
        ("calls", "expected"), [(2, None), (3, None), (4, "tool_calls")]
    )
    def test_limit_hit_only_when_calls_exceed_budget(self, calls, expected):
        toolbox = SimpleNamespace(
            call_log=[{"name": "read_file"} for _ in range(calls)],
            budget=3,
            steps_exhausted=False,
        )
        record = RunRecord(section="s")

        fill_record(record, toolbox, "{}")

        assert record.limit_hit == expected
