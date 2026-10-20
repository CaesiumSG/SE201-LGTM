"""Tests for the deterministic static facts given to agents."""

from __future__ import annotations

from lgtm.agents.base import run_tool_loop
from lgtm.analysis.facts import sql_sink_facts
from lgtm.config import LGTMConfig

SRC = '''\
@bp.route("/maintenance", methods=["POST"])
@require_role("admin")
def run_maintenance():
    user_id = request.json["user_id"]
    cursor.execute("DELETE FROM sessions WHERE user_id = %s" % user_id)
    cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    q = "SELECT * FROM t WHERE name = '" + name + "'"
    cursor.execute(q)
    cursor.execute(f"SELECT * FROM t ORDER BY {sort_by}")
'''


def test_percent_formatting_is_not_a_bound_parameter():
    facts = sql_sink_facts(SRC, 5)
    assert "%-string formatting" in facts and "passed: NO" in facts


def test_bound_parameters_recognized():
    assert "passed: yes" in sql_sink_facts(SRC, 6)


def test_concatenation_resolved_through_variable():
    facts = sql_sink_facts(SRC, 8)
    assert "concatenation with name" in facts


def test_fstring_interpolation():
    assert "f-string interpolating sort_by" in sql_sink_facts(SRC, 9)


def test_unparsable_source_gives_no_facts():
    assert sql_sink_facts("def (:", 1) == ""


class _ScriptedLLM:
    def __init__(self, contents):
        self.contents = list(contents)
        self.seen = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        from unittest.mock import MagicMock

        self.seen.append(list(messages))
        msg = MagicMock()
        msg.content = self.contents.pop(0)
        msg.tool_calls = []
        return msg


def test_require_tool_use_pushes_back_once(git_repo):
    from lgtm.agents.tools import AgentToolbox

    tools = AgentToolbox(git_repo, "main").build_tools()
    llm = _ScriptedLLM(['{"verdict": "vulnerable"}', '{"verdict": "safe"}'])
    out = run_tool_loop(llm, tools, "s", "u", LGTMConfig(require_tool_use=True))
    assert out == '{"verdict": "safe"}'
    assert "call at least one tool" in llm.seen[1][-1].content


def test_no_push_back_by_default(git_repo):
    from lgtm.agents.tools import AgentToolbox

    tools = AgentToolbox(git_repo, "main").build_tools()
    llm = _ScriptedLLM(['{"verdict": "vulnerable"}'])
    assert run_tool_loop(llm, tools, "s", "u", LGTMConfig()) == '{"verdict": "vulnerable"}'


def test_input_source_and_allowlist_facts():
    src = (
        "def sorted_orders():\n"
        '    sort_by = request.args.get("sort_by", "created_at")\n'
        "    if sort_by not in ALLOWED_SORT_COLUMNS:\n"
        "        abort(400)\n"
        '    session.execute(text(f"SELECT * FROM orders ORDER BY {sort_by}"))\n'
    )
    facts = sql_sink_facts(src, 5)
    assert "user-controlled request data" in facts
    assert "membership-checked against `ALLOWED_SORT_COLUMNS`" in facts
