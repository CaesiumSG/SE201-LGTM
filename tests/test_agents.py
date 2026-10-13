"""Tests for agent tools, output parsing, and the agent loop (LLM mocked)."""

from __future__ import annotations

from unittest.mock import MagicMock

from lgtm.agents.authz_reviewer import extract_changed_endpoints
from lgtm.agents.base import extract_json_object, parse_agent_output, run_tool_loop
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import parse_unified_diff


class TestToolbox:
    def test_read_file_from_base_branch(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        out = toolbox.read_file_impl("app.py")
        assert "get_user" in out
        assert "find_user" not in out  # PR-only code must be invisible
        assert out.splitlines()[1].startswith("1: ")

    def test_read_file_line_range(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main")
        out = toolbox.read_file_impl("app.py", 2, 2)
        assert "2: " in out and "1: " not in out.split("===")[2]

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

    def test_search_code_without_retriever(self, git_repo):
        toolbox = AgentToolbox(git_repo, "main", retriever=None)
        assert "ERROR" in toolbox.search_code_impl("auth decorator")

    def test_search_code_tool_registered_with_budget(self, git_repo):
        from lgtm.config import LGTMConfig

        toolbox = AgentToolbox(git_repo, "main", config=LGTMConfig(max_tool_calls=1))
        tools = {t.name: t for t in toolbox.build_tools()}
        assert "search_code" in tools
        tools["search_code"].invoke({"query": "x"})
        assert "budget exhausted" in tools["search_code"].invoke({"query": "y"})

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
            _ai_message("done"),
        ])
        out = run_tool_loop(llm, [], "sys", "user", LGTMConfig())
        assert out == "done"


class TestExtractChangedEndpoints:
    DIFF = """\
diff --git a/app/routes/orders.py b/app/routes/orders.py
--- a/app/routes/orders.py
+++ b/app/routes/orders.py
@@ -40,3 +40,12 @@ def existing():
     return x
+
+
+@orders_bp.route("/<int:order_id>", methods=["GET"])
+@require_auth
+def get_order(order_id):
+    return fetch(order_id)
+
+@api.get("/ping")
+def ping():
+    return "pong"
"""

    def test_finds_flask_and_fastapi_routes(self):
        diffs = parse_unified_diff(self.DIFF)
        endpoints = extract_changed_endpoints(diffs)
        routes = {e.route_path: e for e in endpoints}
        assert set(routes) == {"/<int:order_id>", "/ping"}
        assert routes["/<int:order_id>"].http_methods == ["GET"]
        assert routes["/ping"].http_methods == ["GET"]
        assert routes["/<int:order_id>"].file == "app/routes/orders.py"

    def test_ignores_non_python_and_deleted(self):
        diffs = parse_unified_diff(self.DIFF)
        diffs[0].status = "deleted"
        assert extract_changed_endpoints(diffs) == []


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
