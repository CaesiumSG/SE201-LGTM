"""Investigator evidence: the closing request fits, stops are per call, results are bounded and never repeat held content."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from lgtm.agents import registry
from lgtm.agents.base import fit_closing_request
from lgtm.agents.investigator import run_investigator
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, Hunk, LineChange
from tests.test_investigator import ScriptedLLM, answer, manifest_diffs, sections_json, small_diffs

BASE = "a" * 40
PR = "b" * 40
CHARS_PER_TOKEN = 3
LINE_WIDTH = 150
BIG_LINES = 600
SMALL_LINES = 20
VALID = sections_json("app.py#0")


def body(tag: str, lines: int) -> str:
    return "\n".join(f"{tag}-LINE-{i:04d} ".ljust(LINE_WIDTH, "x") for i in range(lines))


def last_line_marker(tag: str, lines: int) -> str:
    return f"{tag}-LINE-{lines - 1:04d}"


@pytest.fixture
def files(monkeypatch):
    store: dict[str, str] = {}

    def fake_run_git(repo, args, timeout):
        if args[:2] == ["cat-file", "blob"]:
            rel = args[2].split(":", 1)[1]
            if rel in store:
                return subprocess.CompletedProcess(args, 0, stdout=store[rel], stderr="")
            return subprocess.CompletedProcess(args, 128, stdout="", stderr="missing")
        if args[0] == "grep":
            sha = args[-1] if args[-2] != "--" else args[-3]
            lines = [f"{sha}:src/a.py:{n}:" + "g" * 200 for n in range(60)]
            return subprocess.CompletedProcess(args, 0, stdout="\n".join(lines), stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr("lgtm.agents.tools.run_git", fake_run_git)
    return store


@pytest.fixture
def config():
    return LGTMConfig(llm_retries=0, max_answer_reasks=0, require_tool_use=False, llm_window_headroom=1.0)


class StubSession:
    available = True
    state = "ok"

    def __init__(self, text):
        self.text = text

    def explore(self, label, query):
        return SimpleNamespace(ok=True, reason=None, text=self.text, truncated=False, omitted_chars=0)

    def snapshot(self, label):
        return None


def make_toolbox(config, session=None):
    return AgentToolbox("repo", "main", None, config, shas={"base": BASE, "pr": PR}, session=session)


def call(name, **args):
    return {"name": name, "args": args}


def reply(*calls, content=""):
    return AIMessage(
        content=content,
        tool_calls=[{**c, "id": f"call_{i}_{c['name']}"} for i, c in enumerate(calls)],
    )


def read(path, snapshot="base", **rng):
    return call("read_file", path=path, snapshot=snapshot, **rng)


def run(config, toolbox, replies, diffs=None):
    llm = ScriptedLLM(list(replies))
    return run_investigator(diffs or small_diffs(), config, toolbox, llm), llm


def chars(messages):
    return sum(len(str(m.content)) for m in messages)


def tool_texts(request):
    return [str(m.content) for m in request if type(m).__name__ == "ToolMessage"]


def recorded_results(result):
    return [c["result"] for t in result.run_record.turns for c in t["tool_calls"]]


def forced_final():
    return registry.entry("investigator.forced_final")


def final_window(config):
    return (config.llm_context_tokens - config.investigator_final_output_tokens) * CHARS_PER_TOKEN


def default_read(config, path, **kwargs):
    return make_toolbox(config).read_file_impl(path, kwargs.get("start_line"), kwargs.get("end_line"), kwargs.get("snapshot", "base"))


def probe(config, files, replies=None):
    """Prompt size and the size of one oversized read result, from a run with room to spare."""
    files["big.py"] = body("BIG", BIG_LINES)
    result, llm = run(config, make_toolbox(config), [reply(read("big.py")), answer(VALID)])
    assert result.status == "ok"
    return chars(llm.seen[0]), len(tool_texts(llm.seen[1])[0])


def tight(config, prompt_chars, result_chars, slots):
    window = prompt_chars + len(forced_final()) + int(slots * result_chars)
    tokens = -(-window // CHARS_PER_TOKEN) + config.investigator_final_output_tokens
    return LGTMConfig(
        llm_retries=0,
        max_answer_reasks=0,
        require_tool_use=False,
        llm_window_headroom=1.0,
        llm_context_tokens=tokens,
    )


# --- AC-US7-7: one per-call bound ------------------------------------------------


def test_oversized_read_is_cut_with_a_visible_marker_and_a_small_read_is_unchanged(files, config):
    files["big.py"] = body("BIG", BIG_LINES)
    files["small.py"] = body("SMALL", SMALL_LINES)

    _, llm = run(config, make_toolbox(config), [reply(read("big.py"), read("small.py")), answer(VALID)])

    big, small = tool_texts(llm.seen[1])
    assert len(big) < len(files["big.py"])
    assert "[TRUNCATED]" in big
    assert last_line_marker("BIG", BIG_LINES) not in big
    assert small == default_read(config, "small.py")


def largest_full_prompt(config):
    def diffs(n):
        changes = [LineChange(kind="add", content="x" * 200) for _ in range(n)]
        hunk = Hunk(old_start=1, old_count=0, new_start=1, new_count=n, changes=changes)
        return [FileDiff(path="big.py", status="modified", hunks=[hunk])]

    lo, hi = 1, 400
    while lo < hi:
        mid = (lo + hi + 1) // 2
        result, _ = run(config, make_toolbox(config), [answer(VALID)], diffs(mid))
        lo, hi = (mid, hi) if result.input_mode == "full" else (lo, mid - 1)
    _, llm = run(config, make_toolbox(config), [answer(VALID)], diffs(lo))
    return chars(llm.seen[0]) + 250, diffs(lo)


@pytest.mark.parametrize("kind", ["read_file", "grep_repo", "investigate_pr_code"])
def test_one_result_at_the_bound_still_fits_the_forced_final_allowance(files, config, kind):
    files["big.py"] = body("BIG", BIG_LINES)
    calls = {
        "read_file": read("big.py"),
        "grep_repo": call("grep_repo", pattern="g", snapshot="base"),
        "investigate_pr_code": call("investigate_pr_code", query="handler"),
    }
    session = StubSession("G" * 50000)
    prompt_chars, diffs = largest_full_prompt(config)

    _, llm = run(config, make_toolbox(config, session), [reply(calls[kind]), answer(VALID)], diffs)

    result_chars = len(tool_texts(llm.seen[1])[0])
    assert prompt_chars + len(forced_final()) + result_chars <= final_window(config)


# --- AC-US7-5: whole-file reads of changed files at the PR snapshot ----------------


@pytest.mark.parametrize(
    "span",
    [{}, {"start_line": 1, "end_line": BIG_LINES}, {"start_line": 1, "end_line": 9999}, {"end_line": BIG_LINES}],
    ids=["no-range", "exact-range", "range-past-end", "open-start"],
)
def test_whole_file_pr_read_of_a_changed_file_is_not_served_in_full(files, config, span):
    files["app.py"] = body("APP", BIG_LINES)

    _, llm = run(config, make_toolbox(config), [reply(read("app.py", "pr", **span)), answer(VALID)])

    served = tool_texts(llm.seen[1])[0]
    assert last_line_marker("APP", BIG_LINES) not in served
    assert len(served) < len(default_read(config, "app.py", snapshot="pr"))


def test_reads_that_hold_nothing_new_back_are_served_as_before(files, config):
    files["app.py"] = body("APP", SMALL_LINES)
    files["other.py"] = body("OTHER", SMALL_LINES)
    requests = [
        read("app.py", "pr", start_line=1, end_line=SMALL_LINES - 1),
        read("app.py", "base"),
        read("other.py", "pr"),
    ]

    _, llm = run(config, make_toolbox(config), [reply(*requests), answer(VALID)])

    served = tool_texts(llm.seen[1])
    assert served == [
        default_read(config, "app.py", snapshot="pr", start_line=1, end_line=SMALL_LINES - 1),
        default_read(config, "app.py", snapshot="base"),
        default_read(config, "other.py", snapshot="pr"),
    ]


def test_whole_file_pr_read_is_served_when_the_diff_is_not_in_the_prompt(files, config):
    config.investigator_diff_chars = 100
    files["svc/views.py"] = body("VIEWS", SMALL_LINES)

    result, llm = run(
        config, make_toolbox(config), [reply(read("svc/views.py", "pr")), answer(VALID)], manifest_diffs()
    )

    assert result.input_mode == "manifest_only"
    assert tool_texts(llm.seen[1]) == [default_read(config, "svc/views.py", snapshot="pr")]


# --- AC-US7-6: repeated identical calls --------------------------------------------


def test_identical_repeat_is_not_served_again_while_other_arguments_are(files, config):
    files["f.py"] = body("REPEAT", SMALL_LINES)
    replies = [
        reply(read("f.py")),
        reply(read("f.py")),
        reply(read("f.py", start_line=1, end_line=5)),
        answer(VALID),
    ]

    result, llm = run(config, make_toolbox(config), replies)

    first, repeat, other = recorded_results(result)
    assert first == default_read(config, "f.py")
    assert last_line_marker("REPEAT", SMALL_LINES) not in repeat
    assert len(repeat) < len(first)
    assert other == default_read(config, "f.py", start_line=1, end_line=5)
    assert [c["args"] for c in result.run_record.tool_calls][:2] == [result.run_record.tool_calls[0]["args"]] * 2
    assert len(result.run_record.tool_calls) == 3


# --- AC-US7-9: refused, repeated and bounded calls spend budget ----------------------


@pytest.mark.parametrize(
    ("script", "spent"),
    [
        ([read("app.py", "pr")], 1),
        ([read("app.py", "pr"), read("app.py", "pr")], 2),
        ([read("f.py"), read("f.py")], 2),
        ([read("big.py")], 1),
    ],
    ids=["refused", "refused-then-retried", "identical-repeat", "bounded-excerpt"],
)
def test_refused_repeated_and_bounded_calls_each_cost_one_call(files, config, script, spent):
    files["app.py"] = body("APP", BIG_LINES)
    files["f.py"] = body("F", SMALL_LINES)
    files["big.py"] = body("BIG", BIG_LINES)
    config.investigator_max_tool_calls = 10
    toolbox = make_toolbox(config)

    result, _ = run(config, toolbox, [*(reply(c) for c in script), answer(VALID)])

    assert result.tool_calls == spent
    assert toolbox.budget - toolbox.calls_used == 10 - spent
    assert len(result.run_record.tool_calls) == len(script)


def test_a_refused_read_gives_no_free_retry_when_the_budget_is_one_call_away(files, config):
    files["app.py"] = body("APP", BIG_LINES)
    config.investigator_max_tool_calls = 2
    replies = [reply(read("app.py", "pr")), reply(read("app.py", "pr")), answer(VALID)]

    result, llm = run(config, make_toolbox(config), replies)

    assert result.tool_calls == 2
    assert result.run_record.limit_hit == "tool_calls"
    assert str(llm.seen[-1][-1].content) == forced_final()


# --- AC-US7-4: the stop decision is per requested call -----------------------------


def test_calls_that_no_longer_leave_room_get_a_stop_message_and_the_closing_request_follows(files, config):
    prompt_chars, bound = probe(config, files)
    cfg = tight(config, prompt_chars, bound, slots=2.5)
    files.update({f"big{i}.py": body(f"B{i}", BIG_LINES) for i in range(5)})
    turn = reply(*(read(f"big{i}.py") for i in range(5)))
    toolbox = make_toolbox(cfg)

    result, llm = run(cfg, toolbox, [turn, answer(VALID)])

    results = recorded_results(result)
    executed, stopped = results[:2], results[2:]
    assert result.status == "ok"
    assert [len(r) for r in executed] == [bound, bound]
    assert len(stopped) == 3
    assert len(set(stopped)) == 1
    assert stopped[0] not in executed
    assert stopped[0] != toolbox.BUDGET_MESSAGE
    assert all(f"B{i}-LINE" not in stopped[0] for i in range(5))
    assert result.tool_calls == 5
    assert len(result.run_record.tool_calls) == 5
    assert len(llm.seen) == 2
    assert str(llm.seen[1][-1].content) == forced_final()
    assert chars(llm.seen[1]) <= final_window(cfg)


def test_every_call_is_executed_when_room_remains_and_the_loop_continues(files, config):
    for i in range(3):
        files[f"s{i}.py"] = body(f"S{i}", SMALL_LINES)
    turn = reply(*(read(f"s{i}.py") for i in range(3)))

    result, llm = run(config, make_toolbox(config), [turn, reply(read("s0.py", start_line=1, end_line=3)), answer(VALID)])

    assert recorded_results(result)[:3] == [default_read(config, f"s{i}.py") for i in range(3)]
    assert len(llm.seen) == 3
    assert str(llm.seen[1][-1].content) != forced_final()
    assert result.tool_calls == 4


# --- AC-US7-1, AC-US7-2, AC-US7-3: the closing request is fitted -------------------


def fat_turn_run(files, config):
    prompt_chars, bound = probe(config, files)
    cfg = tight(config, prompt_chars, bound, slots=2.5)
    files["old.py"] = body("OLD", BIG_LINES)
    files["new.py"] = body("NEW", BIG_LINES)
    fat = "y" * int(1.8 * bound)
    replies = [reply(read("old.py")), reply(read("new.py"), content=fat), answer(VALID)]
    result, llm = run(cfg, make_toolbox(cfg), replies)
    return cfg, bound, fat, result, llm


def test_closing_request_is_fitted_and_the_run_ends_as_a_normal_completion(files, config):
    cfg, bound, fat, result, llm = fat_turn_run(files, config)

    closing = llm.seen[-1]
    assert result.status == "ok"
    assert result.error is None
    assert [s.section_id for s in result.proposed] == ["s1"]
    assert chars(closing) <= final_window(cfg)
    assert closing[:2] == llm.seen[0][:2]
    assert str(closing[-1].content) == forced_final()
    assert any(str(m.content) == fat for m in closing)
    assert tool_texts(closing)[-1] == recorded_results(result)[-1]
    assert all(len(text) < bound for text in tool_texts(closing)[:-1])


def test_case_record_keeps_every_turn_call_and_result_as_the_agent_saw_it(files, config):
    cfg, bound, fat, result, llm = fat_turn_run(files, config)

    turns = result.run_record.turns
    assert [t["assistant"] for t in turns] == ["", fat, VALID]
    assert [[c["tool"] for c in t["tool_calls"]] for t in turns] == [["read_file"], ["read_file"], []]
    assert [c["tool"] for c in result.run_record.tool_calls] == ["read_file", "read_file"]
    assert turns[0]["tool_calls"][0]["result"] == tool_texts(llm.seen[1])[0]
    assert len(turns[0]["tool_calls"][0]["result"]) == bound
    assert len(turns[0]["tool_calls"][0]["result"]) < len(files["old.py"])
    assert turns[1]["tool_calls"][0]["result"] == tool_texts(llm.seen[-1])[-1]


STOP_RESULTS = {
    "context-full": registry.entry("tools.context_full"),
    "budget-spent": registry.entry("tools.budget_exhausted"),
    "iteration-limit": "ordinary result " * 20,
    "invalid-input-limit": registry.entry("shared.invalid_tool_input").format(name="read_file", details="bad"),
}
OUTPUT_TOKENS = 100
OLD_RESULT_CHARS = 3000


def scripted_history(last_result, older=4):
    messages = [SystemMessage(content="SYSTEM"), HumanMessage(content="USER-WITH-DIFF " * 20)]
    for i in range(older):
        messages += [
            AIMessage(content=f"turn-{i}", tool_calls=[{"name": "read_file", "args": {}, "id": f"old{i}"}]),
            ToolMessage(content=f"OLD-{i} " + "z" * OLD_RESULT_CHARS, tool_call_id=f"old{i}"),
        ]
    messages += [
        AIMessage(content="last-turn", tool_calls=[{"name": "read_file", "args": {}, "id": "recent"}]),
        ToolMessage(content=last_result, tool_call_id="recent"),
        HumanMessage(content=forced_final()),
    ]
    return messages


def closing_config(allowance_chars):
    tokens = -(-allowance_chars // CHARS_PER_TOKEN) + OUTPUT_TOKENS
    return LGTMConfig(llm_context_tokens=tokens, llm_window_headroom=1.0)


@pytest.mark.parametrize("stop", list(STOP_RESULTS))
def test_closing_request_after_each_stop_is_fitted_by_shortening_only_older_results(stop):
    last_result = STOP_RESULTS[stop]
    messages = scripted_history(last_result)
    original = list(messages)
    cfg = closing_config(chars(messages) - 2 * OLD_RESULT_CHARS)

    fitted = fit_closing_request(messages, cfg, OUTPUT_TOKENS)

    assert fitted is True
    assert chars(messages) <= (cfg.llm_context_tokens - OUTPUT_TOKENS) * CHARS_PER_TOKEN
    assert len(messages) == len(original)
    assert [type(m) for m in messages] == [type(m) for m in original]
    assert messages[:2] == original[:2]
    assert messages[-1] == original[-1]
    assert str(messages[-2].content) == last_result
    assert [m.content for m in messages if isinstance(m, AIMessage)] == [m.content for m in original if isinstance(m, AIMessage)]
    older = [m for m in messages if isinstance(m, ToolMessage)][:-1]
    older_before = [m for m in original if isinstance(m, ToolMessage)][:-1]
    assert [m.tool_call_id for m in older] == [m.tool_call_id for m in older_before]
    assert all(len(str(a.content)) <= len(str(b.content)) for a, b in zip(older, older_before))
    assert any(len(str(a.content)) < len(str(b.content)) for a, b in zip(older, older_before))


def test_a_history_that_already_fits_is_left_unchanged():
    messages = scripted_history("ok")
    original = list(messages)
    cfg = closing_config(chars(messages) + 10)

    assert fit_closing_request(messages, cfg, OUTPUT_TOKENS) is True
    assert messages == original


def test_closing_request_that_cannot_fit_after_shortening_every_older_result_is_reported_unfitted():
    messages = scripted_history("R" * 20000)
    cfg = closing_config(5000)

    assert fit_closing_request(messages, cfg, OUTPUT_TOKENS) is False
    assert messages[:2] == scripted_history("R" * 20000)[:2]
    assert str(messages[-2].content) == "R" * 20000
    assert str(messages[-1].content) == forced_final()


def test_a_request_that_cannot_be_fitted_is_not_sent_and_is_an_invalid_answer_without_a_context_error(files, config):
    prompt_chars, bound = probe(config, files)
    cfg = tight(config, prompt_chars, bound, slots=0)
    files["old.py"] = body("OLD", BIG_LINES)

    stop_text = "stop text"
    result, llm = run(cfg, make_toolbox(cfg), [reply(read("old.py"), content=stop_text), answer(VALID)])

    assert result.status == "failed"
    assert result.proposed is None
    assert result.error == registry.entry("tools.closing_not_fitted")
    assert all(chars(request) <= final_window(cfg) or request is llm.seen[0] for request in llm.seen[1:])
    assert len(llm.seen) == 1
    assert len(result.run_record.turns) == 1
    assert [t["assistant"] for t in result.run_record.turns][0] == stop_text
    assert len(result.run_record.tool_calls) == 1
    assert len(recorded_results(result)) == 1


def test_a_stop_turn_text_larger_than_the_room_left_is_trimmed_in_the_closing_request_and_the_run_completes(files, config):
    prompt_chars, bound = probe(config, files)
    cfg = tight(config, prompt_chars, bound, slots=2.5)
    files["old.py"] = body("OLD", BIG_LINES)
    files["new.py"] = body("NEW", BIG_LINES)
    fat = "y" * (3 * bound)
    stop_reply = reply(read("new.py"), content=fat)
    replies = [reply(read("old.py")), stop_reply, answer(VALID)]

    result, llm = run(cfg, make_toolbox(cfg), replies)

    closing = llm.seen[-1]
    sent = [m for m in closing if isinstance(m, AIMessage) and m.tool_calls][-1]
    assert result.status == "ok"
    assert result.error is None
    assert [s.section_id for s in result.proposed] == ["s1"]
    assert chars(closing) <= final_window(cfg)
    assert str(closing[-1].content) == forced_final()
    assert 0 < len(str(sent.content)) < len(fat)
    assert fat.startswith(str(sent.content))
    assert sent.tool_calls == stop_reply.tool_calls
    assert [t["assistant"] for t in result.run_record.turns][1] == fat


# --- AC-US7-8: nothing changes for other callers on the same toolbox ----------------


def test_default_callers_of_a_toolbox_the_investigator_used_get_the_same_results_as_before(files, config):
    files["app.py"] = body("APP", BIG_LINES)
    files["big.py"] = body("BIG", BIG_LINES)
    session = StubSession("G" * 5000)
    toolbox = make_toolbox(config, session)
    fresh = make_toolbox(config, session)
    run(
        config,
        toolbox,
        [reply(read("big.py"), read("big.py"), read("app.py", "pr"), call("investigate_pr_code", query="q")), answer(VALID)],
    )

    toolbox.reset_budget(50)
    fresh.reset_budget(50)
    tools = {t.name: t for t in toolbox.build_tools()}
    fresh_tools = {t.name: t for t in fresh.build_tools()}
    requests = [
        ("read_file", {"path": "big.py"}),
        ("read_file", {"path": "big.py"}),
        ("read_file", {"path": "app.py", "snapshot": "pr"}),
        ("grep_repo", {"pattern": "g"}),
        ("investigate_pr_code", {"query": "q"}),
        ("investigate_pr_code", {"query": "q"}),
    ]

    for name, args in requests:
        assert tools[name].invoke(args) == fresh_tools[name].invoke(args)
    assert last_line_marker("BIG", BIG_LINES) in tools["read_file"].invoke({"path": "big.py"})


# --- repair: whole-file refusal proven against the per-call bound ------------------


def small_pr_read(files, config, **span):
    files["app.py"] = body("APP", SMALL_LINES)
    _, llm = run(config, make_toolbox(config), [reply(read("app.py", "pr", **span)), answer(VALID)])
    return tool_texts(llm.seen[1])[0]


@pytest.mark.parametrize(
    "span",
    [{}, {"start_line": 1, "end_line": SMALL_LINES}, {"start_line": 1, "end_line": SMALL_LINES + 5}, {"end_line": SMALL_LINES}],
    ids=["no-range", "exact-range", "range-past-end", "open-start"],
)
def test_whole_file_pr_read_of_a_small_changed_file_is_refused_not_just_bounded(files, config, span):
    served = small_pr_read(files, config, **span)

    assert served != default_read(config, "app.py", snapshot="pr")
    assert "APP-LINE-0000" not in served
    assert last_line_marker("APP", SMALL_LINES) not in served


@pytest.mark.parametrize(
    "span",
    [{"start_line": 2}, {"start_line": 2, "end_line": SMALL_LINES}, {"start_line": 1, "end_line": SMALL_LINES - 1}],
    ids=["from-second-line", "second-line-to-end", "stops-one-short"],
)
def test_pr_read_that_leaves_part_of_a_changed_file_out_is_served_as_before(files, config, span):
    served = small_pr_read(files, config, **span)

    assert served == default_read(config, "app.py", snapshot="pr", **span)


def test_whole_file_pr_read_of_a_changed_file_outside_the_prompt_diff_is_served(files, config):
    files["README.md"] = body("DOC", SMALL_LINES)

    _, llm = run(config, make_toolbox(config), [reply(read("README.md", "pr")), answer(VALID)])

    assert tool_texts(llm.seen[1]) == [default_read(config, "README.md", snapshot="pr")]


# --- repair: per-call bound for every tool ------------------------------------------

BOUND = 2000


def kind_call(kind):
    return {
        "read_file": read("big.py"),
        "grep_repo": call("grep_repo", pattern="g", snapshot="base"),
        "investigate_pr_code": call("investigate_pr_code", query="handler"),
    }[kind]


def plain_result(config, session, request):
    tools = {t.name: t for t in make_toolbox(config, session).build_tools()}
    return tools[request["name"]].invoke(request["args"])


@pytest.mark.parametrize("kind", ["read_file", "grep_repo", "investigate_pr_code"])
def test_a_result_longer_than_the_configured_bound_is_cut_with_a_marker_for_every_tool(files, config, kind):
    files["big.py"] = body("BIG", BIG_LINES)
    config.investigator_result_chars = BOUND
    session = StubSession("G" * 50000)
    assert len(plain_result(config, session, kind_call(kind))) > BOUND

    _, llm = run(config, make_toolbox(config, session), [reply(kind_call(kind)), answer(VALID)])

    served = tool_texts(llm.seen[1])[0]
    assert len(served) <= BOUND
    assert "[TRUNCATED]" in served


def test_a_graph_result_within_the_configured_bound_is_unchanged(files, config):
    config.investigator_result_chars = BOUND
    session = StubSession("G" * 500)
    request = kind_call("investigate_pr_code")

    _, llm = run(config, make_toolbox(config, session), [reply(request), answer(VALID)])

    assert tool_texts(llm.seen[1]) == [plain_result(config, session, request)]


# --- repair: repeats for every tool; a refused call is not an earlier call ----------


@pytest.mark.parametrize("kind", ["grep_repo", "investigate_pr_code"])
def test_identical_repeat_of_a_non_read_tool_is_answered_with_a_pointer_naming_tool_and_arguments(files, config, kind):
    request = kind_call(kind)
    session = StubSession("G" * 3000)

    result, _ = run(config, make_toolbox(config, session), [reply(request), reply(request), answer(VALID)])

    first, repeat = recorded_results(result)
    assert first not in repeat
    assert len(repeat) < len(first) / 2
    assert kind in repeat
    assert all(str(value) in repeat for value in request["args"].values())


def test_a_refused_read_retried_identically_is_refused_again_without_a_pointer_to_content_never_held(files, config):
    files["app.py"] = body("APP", SMALL_LINES)

    result, _ = run(
        config, make_toolbox(config), [reply(read("app.py", "pr")), reply(read("app.py", "pr")), answer(VALID)]
    )

    refused, retried = recorded_results(result)
    assert refused != default_read(config, "app.py", snapshot="pr")
    assert retried == refused


# --- repair: the stop boundary -------------------------------------------------------


def prompt_chars(config):
    _, llm = run(config, make_toolbox(config), [answer(VALID)])
    return chars(llm.seen[0])


@pytest.mark.parametrize(
    ("fitting", "shortfall", "executed"),
    [(2, 0, 2), (2, 3, 1), (1, 0, 1), (1, 3, 0)],
    ids=["two-fit-exactly", "one-token-short-of-two", "one-fits-exactly", "none-fit-first-call-stops"],
)
def test_a_call_runs_exactly_when_its_result_at_the_bound_still_leaves_the_closing_request_room(
    files, config, fitting, shortfall, executed
):
    base = prompt_chars(config) + len(forced_final())
    bound = next(b for b in range(8000, 8003) if (base + fitting * b) % 3 == 0)
    allowance = base + fitting * bound - shortfall
    cfg = LGTMConfig(
        llm_retries=0,
        max_answer_reasks=0,
        require_tool_use=False,
        llm_window_headroom=1.0,
        investigator_result_chars=bound,
        llm_context_tokens=allowance // 3 + config.investigator_final_output_tokens,
    )
    files.update({f"big{i}.py": body(f"B{i}", BIG_LINES) for i in range(5)})
    turn = reply(*(read(f"big{i}.py") for i in range(fitting)))

    result, llm = run(cfg, make_toolbox(cfg), [turn, answer(VALID)])

    results = recorded_results(result)
    assert [f"B{i}-LINE" in r for i, r in enumerate(results)] == [i < executed for i in range(fitting)]
    assert len(llm.seen) == 2
    assert chars(llm.seen[1]) <= final_window(cfg)


def test_calls_stopped_at_the_exact_boundary_still_leave_a_closing_request_that_fits(files, config):
    base = prompt_chars(config) + len(forced_final())
    bound = next(b for b in range(8000, 8003) if (base + 2 * b) % 3 == 0)
    cfg = LGTMConfig(
        llm_retries=0,
        max_answer_reasks=0,
        require_tool_use=False,
        llm_window_headroom=1.0,
        investigator_result_chars=bound,
        llm_context_tokens=(base + 2 * bound) // 3 + config.investigator_final_output_tokens,
    )
    files.update({f"big{i}.py": body(f"B{i}", BIG_LINES) for i in range(5)})

    result, llm = run(cfg, make_toolbox(cfg), [reply(*(read(f"big{i}.py") for i in range(5))), answer(VALID)])

    assert result.status == "ok"
    assert result.error is None
    assert len(llm.seen) == 2
    assert chars(llm.seen[1]) <= final_window(cfg)


def test_stopped_calls_past_the_remaining_budget_get_the_budget_message_and_the_budget_is_spent(files, config):
    toolbox = make_toolbox(config)
    stop = max(len(registry.entry("tools.context_full")), len(toolbox.BUDGET_MESSAGE))
    base = prompt_chars(config) + len(forced_final()) + 4 * stop
    bound = next(b for b in range(8000, 8003) if (base + b) % 3 == 0)
    cfg = LGTMConfig(
        llm_retries=0,
        max_answer_reasks=0,
        require_tool_use=False,
        llm_window_headroom=1.0,
        investigator_result_chars=bound,
        investigator_max_tool_calls=3,
        llm_context_tokens=(base + bound) // 3 + config.investigator_final_output_tokens,
    )
    files.update({f"big{i}.py": body(f"B{i}", BIG_LINES) for i in range(5)})
    toolbox = make_toolbox(cfg)

    result, _ = run(cfg, toolbox, [reply(*(read(f"big{i}.py") for i in range(5))), answer(VALID)])

    results = recorded_results(result)
    assert "B0-LINE" in results[0]
    assert results[1] == results[2] != toolbox.BUDGET_MESSAGE
    assert results[3] == results[4] == toolbox.BUDGET_MESSAGE
    assert toolbox.calls_used == toolbox.budget == 3


# --- repair: the closing request is fitted after every stop --------------------------


def text_reply(*calls):
    tags = "".join(f"<tool_call>{json.dumps({'name': c['name'], 'arguments': c['args']})}</tool_call>" for c in calls)
    return AIMessage(content=tags)


@pytest.mark.parametrize(
    ("overrides", "second_turn", "limit"),
    [
        ({"investigator_max_tool_calls": 2}, [read("b.py")], "tool_calls"),
        ({"investigator_max_iterations": 2}, [read("b.py")], "steps"),
        ({"max_invalid_tool_inputs": 1}, [call("read_file"), read("b.py")], None),
    ],
    ids=["budget-spent", "iteration-limit", "invalid-input-limit"],
)
def test_text_form_closing_request_after_each_non_context_stop_is_fitted_by_shortening_only_older_results(
    files, overrides, second_turn, limit
):
    files["a.py"] = body("A", BIG_LINES)
    files["b.py"] = body("B", BIG_LINES)
    replies = [text_reply(read("a.py")), text_reply(*second_turn), answer(VALID)]

    def make(**extra):
        return LGTMConfig(
            llm_retries=0,
            max_answer_reasks=0,
            require_tool_use=False,
            llm_window_headroom=1.0,
            **overrides,
            **extra,
        )

    ample = make()
    _, roomy = run(ample, make_toolbox(ample), replies)
    last = len(str(roomy.seen[-1][-2].content))
    assert last > ample.investigator_result_chars
    allowance = chars(roomy.seen[-1]) - last + ample.investigator_result_chars
    cfg = make(llm_context_tokens=-(-allowance // CHARS_PER_TOKEN) + ample.investigator_final_output_tokens)

    result, llm = run(cfg, make_toolbox(cfg), replies)

    closing = llm.seen[-1]
    results = recorded_results(result)
    assert len(llm.seen) == 3
    assert result.status == "ok"
    assert result.error is None
    assert result.run_record.limit_hit == limit
    assert chars(closing) <= final_window(cfg)
    assert closing[:2] == llm.seen[0][:2]
    assert str(closing[-1].content) == forced_final()
    assert results[-1] in str(closing[-2].content)
    assert not any(results[0] in str(m.content) for m in closing)
    assert any(str(m.content) == registry.entry("tools.result_elided") for m in closing)
    assert len(results) == len(second_turn) + 1
