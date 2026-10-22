"""Builds the model-visible text of every agent, tool and retriever scenario.

Each group function returns {scenario name: rendered text}; the lock suite compares
the result with the recorded values in expected.json.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

from langchain_core.messages import BaseMessage, ToolMessage
from langchain_core.tools import tool
from langchain_core.utils.function_calling import convert_to_openai_tool

from lgtm.agents.authz_reviewer import AuthzReviewerAgent
from lgtm.agents.base import run_tool_loop, validate_tool_call
from lgtm.agents.investigator import run_investigator
from lgtm.agents.plain_reviewer import PlainLLMReviewer
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, Hunk, LineChange
from lgtm.graph.session import GraphSession
from lgtm.rag.retriever import PolicyRetriever
from lgtm.review.sections import ContextPointer, HunkRef, Section
from lgtm.sast.semgrep_runner import SemgrepFinding
from tests.conftest import git
from tests.graph_fakes import FakeRunner

_SHA = re.compile(r"[0-9a-f]{40}")
_JSON_VERDICT = '{"verdict": "safe"}'
_AUTHZ_REPLY = '{"findings": []}'
_PLAIN_REPLY = '{"assessments": []}'
_SECTIONS_REPLY = '{"sections": []}'


def _norm(text: str) -> str:
    return _SHA.sub("<SHA>", text)


class RecordingLLM:
    def __init__(self, *script):
        self.script = list(script)
        self.seen: list[list] = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.seen.append(list(messages))
        return self.script.pop(0) if len(self.script) > 1 else self.script[0]


def ai(content="", calls=None):
    return SimpleNamespace(content=content, tool_calls=calls or [])


def call(name, args, call_id="c1"):
    return {"name": name, "args": args, "id": call_id}


def transcript(messages) -> str:
    parts = []
    for message in messages:
        if not isinstance(message, BaseMessage):
            continue
        tag = type(message).__name__
        if isinstance(message, ToolMessage):
            tag += f" id={message.tool_call_id}"
        parts.append(f"<{tag}>\n{message.content}")
    return _norm("\n\n".join(parts))


def first_input(llm: RecordingLLM) -> str:
    return transcript(llm.seen[0])


def final_transcript(llm: RecordingLLM) -> str:
    return transcript(llm.seen[-1])


def build_repo(work: Path) -> tuple[Path, dict[str, str]]:
    repo = work / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@t.local")
    git(repo, "config", "user.name", "T")
    base_app = (
        "def get_user(cursor, user_id):\n"
        '    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        "    return cursor.fetchone()\n"
    )
    files = {
        "app.py": base_app,
        "policy.md": "# Security Policy\n\nAll SQL must use bound parameters.\n",
        "big.txt": "".join(f"line {n}\n" for n in range(1, 251)),
        **{f"g{n}.py": "".join(f"hit {i}\n" for i in range(12)) for n in range(1, 5)},
    }
    for name, body in files.items():
        (repo / name).write_bytes(body.encode())
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    base = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "checkout", "-q", "-b", "pr")
    (repo / "app.py").write_bytes(
        (base_app + "\ndef find_user(cursor, name):\n    return name\n").encode()
    )
    (repo / "pr_only.py").write_bytes(b"x = 1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "pr")
    pr = git(repo, "rev-parse", "HEAD").strip()
    git(repo, "checkout", "-q", "main")
    return repo, {"base": base, "pr": pr}


class FakeRetriever:
    def __init__(self, reply=None, exc=None):
        self.reply, self.exc = reply, exc

    def format_results(self, query, top_k=None):
        if self.exc:
            raise self.exc
        return self.reply if self.reply is not None else f"POLICY-FOR[{query}]"


def legacy_toolbox(repo, retriever=None, **config):
    return AgentToolbox(repo, "main", retriever, LGTMConfig(**config))


def snapshot_toolbox(repo, shas, retriever=None, **config):
    return AgentToolbox(repo, "main", retriever, LGTMConfig(**config), shas=shas)


def graph_toolbox(repo, shas, retriever=None, **config):
    cfg = LGTMConfig(**config)
    session = GraphSession(repo, shas, cfg, runner=FakeRunner())
    return AgentToolbox(repo, "main", retriever, cfg, shas=shas, session=session)


def _tool_schema(tool_obj) -> str:
    return json.dumps(
        {
            "name": tool_obj.name,
            "description": tool_obj.description,
            "openai": convert_to_openai_tool(tool_obj),
        },
        indent=2,
        ensure_ascii=False,
    )


def tool_schemas(work: Path) -> dict[str, str]:
    repo, shas = build_repo(work)
    out: dict[str, str] = {}
    offered = {
        "graph_session": graph_toolbox(repo, shas).build_tools(),
        "graph_not_requested": graph_toolbox(repo, shas).build_tools(graph=False),
        "snapshots_without_session": snapshot_toolbox(repo, shas).build_tools(),
        "legacy_base_only": legacy_toolbox(repo).build_tools(),
    }
    for variant, tools in offered.items():
        out[f"offered/{variant}"] = ", ".join(t.name for t in tools)
    for t in offered["graph_session"]:
        out[f"schema/{t.name}"] = _tool_schema(t)
    return out


def _hunk_ref(file="app.py", start=10, lines=("a = 1", "b = 2", "c = 3")):
    changes = [LineChange("add", text, None, start + i) for i, text in enumerate(lines)]
    return HunkRef(
        hunk_id=f"{file}#{start}", file=file, old_start=start, old_count=0,
        new_start=start, new_count=len(lines), change="add", changes=changes,
    )


def _section(**overrides):
    fields = dict(
        section_id="s1", origin="investigator", title="Order access",
        files=["app.py"], hunks=[_hunk_ref()],
    )
    return Section(**{**fields, **overrides})


def _file_diff(path, kinds=("context", "add", "del"), old_start=10, new_start=12, prefix="L"):
    changes = [LineChange(k, f"{prefix}{i}_{k}") for i, k in enumerate(kinds)]
    hunk = Hunk(old_start, len(kinds), new_start, len(kinds), changes=changes)
    return FileDiff(path=path, status="modified", hunks=[hunk])


def _finding(**overrides):
    fields = dict(
        rule_id="py.sqli", path="app.py", start_line=5, end_line=6,
        message="tainted query", severity="ERROR", matched_code="cursor.execute(q)",
    )
    return SemgrepFinding(**{**fields, **overrides})


def agent_inputs(work: Path) -> dict[str, str]:
    repo, shas = build_repo(work)
    out: dict[str, str] = {}
    diff = _file_diff("app.py")

    def sast(name, toolbox, file_diff=diff, facts="", finding=None, **config):
        llm = RecordingLLM(ai(_JSON_VERDICT))
        agent = SASTTriageAgent(toolbox, LGTMConfig(**config), llm=llm)
        agent.triage(finding or _finding(), file_diff, facts)
        out[f"sast/{name}"] = first_input(llm)

    sast("plain", legacy_toolbox(repo))
    sast("no_diff_snapshots", snapshot_toolbox(repo, shas), file_diff=None, max_tool_calls=3)
    sast("facts_and_policy", legacy_toolbox(repo, FakeRetriever()), facts="FACT-1\nFACT-2",
         static_facts=True)
    sast("facts_only", legacy_toolbox(repo), facts="FACT-1", static_facts=True)
    sast("policy_only_no_facts", legacy_toolbox(repo, FakeRetriever()), static_facts=True)
    sast("policy_retrieval_fails", legacy_toolbox(repo, FakeRetriever(exc=RuntimeError("down"))),
         facts="F", static_facts=True)
    sast("facts_off_ignores_facts", legacy_toolbox(repo, FakeRetriever()), facts="F")
    sast("truncated_fields", legacy_toolbox(repo, FakeRetriever(reply="P" * 3500)),
         file_diff=_file_diff("app.py", kinds=("add",) * 900),
         finding=_finding(matched_code="M" * 1600), static_facts=True)

    def authz(name, toolbox, section=None, notes="", **config):
        llm = RecordingLLM(ai(_AUTHZ_REPLY))
        AuthzReviewerAgent(toolbox, LGTMConfig(**config), llm=llm).review_section(
            section or _section(), notes
        )
        out[f"authz/{name}"] = first_input(llm)

    authz("legacy_no_policy_index", legacy_toolbox(repo))
    authz("snapshots_policy_role_guidance", snapshot_toolbox(repo, shas, FakeRetriever()),
          authz_role_guidance=True, max_tool_calls=3)
    pointers = [
        ContextPointer("auth/\x1bdeco.py", "require_role\x00", 3, 9, "base", "gate\nfor admin"),
        ContextPointer("svc.py", "Orders", 40, 55, "pr", "caller"),
    ]
    authz("graph_siblings_context_notes", graph_toolbox(repo, shas, FakeRetriever()),
          section=_section(
              title="Order\naccess", rationale="r\tx", files=["app.py", "b\x7f.py"],
              context=pointers, part_index=1, part_count=3,
          ),
          notes="note one\nnote\x1b two")
    authz("no_rationale_single_part", legacy_toolbox(repo), section=_section(rationale=""))
    authz("policy_retrieval_fails", legacy_toolbox(repo, FakeRetriever(exc=OSError("x"))))
    authz("policy_truncated", legacy_toolbox(repo, FakeRetriever(reply="Q" * 5200)))

    def plain(name, diffs, **config):
        llm = RecordingLLM(ai(_PLAIN_REPLY))
        PlainLLMReviewer(LGTMConfig(**config), llm=llm).review(diffs)
        out[f"plain/{name}"] = first_input(llm)

    plain("python_files_only", [_file_diff("app.py"), _file_diff("README.md", prefix="DOC"),
                                _file_diff("pkg/views.py", ("add", "add"), prefix="V")])
    plain("truncated_diff", [_file_diff("big.py", kinds=("add",) * 1500)])

    def investigator(name, toolbox, diffs, **config):
        llm = RecordingLLM(ai(_SECTIONS_REPLY))
        run_investigator(diffs, LGTMConfig(**config), toolbox, llm)
        out[f"investigator/{name}"] = first_input(llm)

    small = [_file_diff("app.py"), _file_diff("README.md", prefix="DOC")]
    investigator("full_graph", graph_toolbox(repo, shas), small, investigator_max_tool_calls=2)
    investigator("full_legacy", legacy_toolbox(repo), small)
    investigator("full_control_chars_in_path", snapshot_toolbox(repo, shas),
                 [_file_diff("we\x1bird\n.py")])
    investigator("manifest_only", snapshot_toolbox(repo, shas),
                 [_file_diff("svc/views.py", ("add",) * 8, 4711, 4802),
                  _file_diff("gone.py", ("del",) * 6, 7, 0, prefix="C")],
                 investigator_diff_chars=50)
    return out


def follow_ups(work: Path) -> dict[str, str]:
    repo, shas = build_repo(work)
    out: dict[str, str] = {}
    quiet = dict(llm_retries=0, max_answer_reasks=0, require_tool_use=False)

    def loop(name, llm, tools, **config):
        cfg = LGTMConfig(**{**quiet, **config})
        run_tool_loop(llm, tools, "SYSTEM", "USER", cfg)
        out[name] = final_transcript(llm)

    loop("push_back_before_first_tool", RecordingLLM(ai("no tools"), ai(_JSON_VERDICT)),
         legacy_toolbox(repo).build_tools(), require_tool_use=True)
    loop("text_tool_call_result",
         RecordingLLM(ai('{"name": "read_file", "arguments": {"path": "app.py"}}'),
                      ai(_JSON_VERDICT)),
         legacy_toolbox(repo).build_tools())
    loop("rejected_tool_inputs",
         RecordingLLM(ai("", [call("rm_rf", {}, "c1"), call("read_file", {"path": 5}, "c2"),
                              call("read_file", {}, "c3"), call("grep_repo", "x", "c4")]),
                      ai(_JSON_VERDICT)),
         legacy_toolbox(repo).build_tools(), max_invalid_tool_inputs=99)
    loop("no_tools_given_unknown_tool",
         RecordingLLM(ai("", [call("read_file", {"path": "a"})]), ai(_JSON_VERDICT)), [])

    @tool
    def explode(query: str) -> str:
        """Always fails."""
        raise ValueError("kaboom")

    loop("tool_raises", RecordingLLM(ai("", [call("explode", {"query": "q"})]),
                                     ai(_JSON_VERDICT)), [explode])
    loop("budget_exhausted",
         RecordingLLM(ai("", [call("read_file", {"path": "app.py"}, "c1"),
                              call("read_file", {"path": "app.py"}, "c2"),
                              call("nope", {}, "c3")]), ai(_JSON_VERDICT)),
         snapshot_toolbox(repo, shas, max_tool_calls=1).build_tools(), max_invalid_tool_inputs=99)
    loop("forced_final_at_iteration_cap",
         RecordingLLM(ai("", [call("read_file", {"path": "app.py"})]), ai(_JSON_VERDICT)),
         legacy_toolbox(repo).build_tools(), max_agent_iterations=1)
    loop("forced_final_at_invalid_input_cap",
         RecordingLLM(ai("", [call("nope", {})]), ai(_JSON_VERDICT)),
         legacy_toolbox(repo).build_tools(), max_invalid_tool_inputs=1)
    loop("reask_after_non_json_answer",
         RecordingLLM(ai("prose"), ai("more prose"), ai(_JSON_VERDICT)), [], max_answer_reasks=2)

    reask_config = LGTMConfig(**{**quiet, "max_answer_reasks": 1})
    llm = RecordingLLM(ai("not json"), ai(_PLAIN_REPLY))
    PlainLLMReviewer(reask_config, llm=llm).review([_file_diff("app.py")])
    out["plain_reviewer_reask"] = final_transcript(llm)

    llm = RecordingLLM(ai("not json"), ai(_AUTHZ_REPLY))
    AuthzReviewerAgent(legacy_toolbox(repo), reask_config, llm=llm).review_section(_section())
    out["authz_reviewer_reask"] = final_transcript(llm)

    forced_config = LGTMConfig(**{**quiet, "max_agent_iterations": 1, "max_answer_reasks": 1})
    llm = RecordingLLM(ai("", [call("read_file", {"path": "app.py"})]), ai("not json"),
                       ai(_JSON_VERDICT))
    SASTTriageAgent(legacy_toolbox(repo), forced_config, llm=llm).triage(
        _finding(), _file_diff("app.py")
    )
    out["sast_triage_forced_final_then_reask"] = final_transcript(llm)
    return out


def tool_results(work: Path) -> dict[str, str]:
    repo, shas = build_repo(work)
    out: dict[str, str] = {}
    legacy = legacy_toolbox(repo)
    snap = snapshot_toolbox(repo, shas)
    lost = AgentToolbox(repo, "no-such-ref")

    for name, box, args in [
        ("legacy_full_file", legacy, ("app.py",)),
        ("legacy_line_range", legacy, ("app.py", 2, 2)),
        ("legacy_start_beyond_end", legacy, ("app.py", 99, None)),
        ("legacy_end_before_start", legacy, ("app.py", 3, 1)),
        ("legacy_long_file_cap", legacy, ("big.txt",)),
        ("legacy_missing_file", legacy, ("nope.py",)),
        ("legacy_parent_escape", legacy, ("../x",)),
        ("legacy_absolute_path", legacy, ("/etc/passwd",)),
        ("legacy_pr_snapshot_refused", legacy, ("app.py", None, None, "pr")),
        ("legacy_unknown_snapshot", legacy, ("app.py", None, None, "tag")),
        ("unresolvable_base_ref", lost, ("app.py",)),
        ("snapshots_pr_file", snap, ("app.py", None, None, "pr")),
        ("snapshots_file_missing_in_base", snap, ("pr_only.py",)),
        ("snapshots_unknown_snapshot", snap, ("app.py", None, None, "head")),
    ]:
        out[f"read_file/{name}"] = _norm(box.read_file_impl(*args))

    for name, box, args in [
        ("legacy_match", legacy, ("get_user",)),
        ("legacy_no_match", legacy, ("zzz_absent",)),
        ("legacy_invalid_regex", legacy, ("([",)),
        ("legacy_multiline_pattern", legacy, ("a\nb",)),
        ("legacy_glob_escape", legacy, ("x", "../y")),
        ("legacy_glob_filter", legacy, ("def", "*.py")),
        ("legacy_pr_snapshot_refused", legacy, ("x", None, "pr")),
        ("legacy_unknown_snapshot", legacy, ("x", None, "tag")),
        ("legacy_truncated_at_cap", legacy, ("hit",)),
        ("legacy_git_rejects_pattern", legacy, ("(?i)abc",)),
        ("unresolvable_base_ref", lost, ("x",)),
        ("snapshots_pr_match", snap, ("find_user", None, "pr")),
        ("snapshots_unknown_snapshot", snap, ("x", None, "head")),
    ]:
        out[f"grep_repo/{name}"] = _norm(box.grep_repo_impl(*args))

    out["search_policy/no_index"] = legacy.search_policy_impl("q")
    out["search_policy/index_missing"] = legacy_toolbox(
        repo, FakeRetriever(exc=FileNotFoundError("No RAG index"))
    ).search_policy_impl("q")
    out["search_policy/results_passed_through"] = legacy_toolbox(
        repo, FakeRetriever()
    ).search_policy_impl("q")
    out["search_policy/results_capped"] = legacy_toolbox(
        repo, FakeRetriever(reply="R" * 9000)
    ).search_policy_impl("q")

    spent = graph_toolbox(repo, shas, max_tool_calls=0)
    budget_args = {
        "read_file": {"path": "app.py"},
        "grep_repo": {"pattern": "x"},
        "search_policy": {"query": "q"},
        "investigate_base_code": {"query": "q"},
        "investigate_pr_code": {"query": "q"},
    }
    for t in spent.build_tools():
        out[f"budget/{t.name}"] = t.invoke(budget_args[t.name])

    investigate = {t.name: t for t in graph_toolbox(repo, shas).build_tools()}
    out["investigate/empty_query"] = investigate["investigate_pr_code"].invoke({"query": "   "})

    tools = {t.name: t for t in legacy.build_tools()}
    cases = {
        "unknown_tool": ("rm_rf", {}),
        "name_not_a_string": (7, {}),
        "arguments_not_object": ("read_file", "x"),
        "missing_required": ("read_file", {}),
        "wrong_type": ("read_file", {"path": 5}),
        "long_details_cut": ("rm_rf" * 100, {}),
    }
    for name, (tool_name, args) in cases.items():
        out[f"validate/{name}"] = str(validate_tool_call(tool_name, tools, args))
    out["validate/no_tools_registered"] = str(validate_tool_call("read_file", {}, {}))
    return out


class _FakeCollection:
    def __init__(self, docs, metas, distances):
        self.docs, self.metas, self.distances = docs, metas, distances

    def count(self):
        return len(self.docs)

    def query(self, query_texts, n_results):
        return {
            "documents": [self.docs[:n_results]],
            "metadatas": [self.metas[:n_results]],
            "distances": [self.distances[:n_results]],
        }


def _retriever(repo, collection):
    retriever = PolicyRetriever(repo)
    retriever._get_collection = lambda name=None: collection
    return retriever


def retriever_text(work: Path) -> dict[str, str]:
    repo, _ = build_repo(work)
    out: dict[str, str] = {}
    docs = ["Only admins may delete users.", "SQL must be parameterized.\nNo exceptions.", "Loose."]
    metas = [
        {"source": "policy.md", "start_line": 4, "end_line": 5},
        {"source": "docs/api.md", "start_line": 10, "end_line": 12},
        {},
    ]
    distances = [0.1234, 0.5, 1.7]
    out["no_results"] = _retriever(repo, _FakeCollection([], [], [])).format_results("q")
    out["one_chunk"] = _retriever(
        repo, _FakeCollection(docs[:1], metas[:1], distances[:1])
    ).format_results("q")
    out["several_chunks"] = _retriever(
        repo, _FakeCollection(docs, metas, distances)
    ).format_results("q", top_k=3)
    out["top_k_limits_chunks"] = _retriever(
        repo, _FakeCollection(docs, metas, distances)
    ).format_results("q", top_k=2)
    out["via_search_policy_tool_capped"] = AgentToolbox(
        repo, "main",
        _retriever(repo, _FakeCollection(["Z" * 9000], metas[:1], distances[:1])),
        LGTMConfig(),
    ).search_policy_impl("q")
    return out


GROUPS = {
    "tool_schemas": tool_schemas,
    "agent_inputs": agent_inputs,
    "follow_ups": follow_ups,
    "tool_results": tool_results,
    "retriever_text": retriever_text,
}
