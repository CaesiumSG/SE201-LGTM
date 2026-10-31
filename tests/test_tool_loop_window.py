"""Tool-loop callers stay within the headroom-adjusted context window: investigator, authorization reviewer, SAST triage."""

from __future__ import annotations

import dataclasses
import json
import re

import pytest
from langchain_core.messages import AIMessage

from lgtm.agents import registry
from lgtm.agents.authz_reviewer import AuthzReviewerAgent
from lgtm.agents.base import CHARS_PER_TOKEN, RunRecord, cut_to_fit
from lgtm.agents.investigator import run_investigator
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, Hunk, LineChange
from tests.test_agents import SEMGREP_HIT, _hunk, _section, _snapshot_toolbox
from tests.test_investigator import answer, small_diffs, tool_call_reply
from tests.test_investigator_evidence import (  # noqa: F401 - fixtures
    BIG_LINES,
    SMALL_LINES,
    VALID,
    body,
    chars,
    config,
    default_read,
    files,
    final_window,
    forced_final,
    largest_full_prompt,
    make_toolbox,
    probe,
    read,
    recorded_results,
    reply,
    run,
    tight,
    tool_texts,
)
from tests.test_investigator_final_answer import FillerLLM

HEADROOM_FIELD = "llm_window_headroom"
DEFAULT_HEADROOM = 0.8
OUT_TOKENS = 500


def pinned(cfg, fraction):
    setattr(cfg, HEADROOM_FIELD, fraction)
    return cfg


def whole_chars(target_chars, fraction):
    """Window in chars, a multiple of the char-per-token ratio, whose headroom share is at least ``target_chars``."""
    return -(-int(target_chars / fraction) // CHARS_PER_TOKEN) * CHARS_PER_TOKEN


def investigator_config(window_chars, fraction=None, **overrides):
    cfg = LGTMConfig(
        llm_retries=0,
        max_answer_reasks=0,
        require_tool_use=False,
        llm_max_output_tokens=OUT_TOKENS,
        investigator_final_output_tokens=OUT_TOKENS,
        llm_context_tokens=window_chars // CHARS_PER_TOKEN + OUT_TOKENS,
        **overrides,
    )
    return cfg if fraction is None else pinned(cfg, fraction)


# --- AC-US8-4: the headroom setting ------------------------------------------------------------


def test_headroom_defaults_to_eight_tenths_of_the_usable_window():
    assert getattr(LGTMConfig(), HEADROOM_FIELD) == DEFAULT_HEADROOM


@pytest.mark.parametrize("value", [0.01, 0.5, 0.8, 1, 1.0])
def test_headroom_above_zero_and_at_most_one_is_accepted(value):
    assert getattr(LGTMConfig(**{HEADROOM_FIELD: value}), HEADROOM_FIELD) == value


@pytest.mark.parametrize("value", [0, 0.0, -0.2, 1.0001, 2])
def test_headroom_outside_the_range_is_rejected_when_the_configuration_loads(value, tmp_path):
    with pytest.raises(ValueError):
        LGTMConfig(**{HEADROOM_FIELD: value})
    path = tmp_path / "config.json"
    path.write_text(json.dumps({HEADROOM_FIELD: value}), encoding="utf-8")
    with pytest.raises(ValueError):
        LGTMConfig.from_file(path)


def test_headroom_in_range_is_loaded_from_a_config_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({HEADROOM_FIELD: 0.6}), encoding="utf-8")

    assert getattr(LGTMConfig.from_file(path), HEADROOM_FIELD) == 0.6


# --- AC-US8-1, AC-US8-4 (investigator): rounds are bounded by the fraction -----------------------


def filler_rounds(fraction):
    cfg = investigator_config(
        (12000 - OUT_TOKENS) * CHARS_PER_TOKEN,
        fraction,
        investigator_max_tool_calls=60,
        investigator_max_iterations=60,
    )
    filler = tool_call_reply(1)
    filler.content = "x" * 1000
    llm = FillerLLM(filler, answer(VALID))
    result = run_investigator(small_diffs(), cfg, make_toolbox(cfg), llm)
    window = (cfg.llm_context_tokens - OUT_TOKENS) * CHARS_PER_TOKEN
    return result, llm, window


@pytest.mark.parametrize("fraction", [None, 0.5, 1.0], ids=["default-0.8", "half", "whole-window"])
def test_investigator_requests_fit_the_headroom_adjusted_window_and_the_run_completes(fraction):
    result, llm, window = filler_rounds(fraction)

    share = DEFAULT_HEADROOM if fraction is None else fraction
    assert result.status == "ok"
    assert result.error is None
    assert all(chars(request) <= share * window for request in llm.seen)


def test_investigator_gets_more_tool_rounds_from_a_larger_fraction():
    rounds = {f: len(filler_rounds(f)[1].seen) for f in (0.5, 1.0)}

    assert rounds[0.5] < rounds[1.0]


# --- final-01: the stop turn's own text and its stop messages are reserved -----------------------

SMALL_FILES = ["s0.py", "s1.py", "s2.py", "s3.py", "s4.py"]
RESULT_BOUND = 500


def test_small_results_then_a_stop_at_the_window_edge_never_end_in_closing_not_fitted(files):
    for name in SMALL_FILES:
        files[name] = "a = 1\nb = 2"
    turn_one = reply(*(read(n) for n in SMALL_FILES[:3]))
    turn_two = reply(*(read(n) for n in SMALL_FILES[3:]), content="y" * (OUT_TOKENS * CHARS_PER_TOKEN))
    script = [turn_one, turn_two, answer(VALID)]
    ample = investigator_config(10**6, 1.0, investigator_result_chars=RESULT_BOUND)
    probe_result, probe = run(ample, make_toolbox(ample), script)
    small = [len(r) for r in recorded_results(probe_result)[:3]]
    assert max(small) < RESULT_BOUND
    stop = max(len(registry.entry("tools.context_full")), len(make_toolbox(ample).BUDGET_MESSAGE))
    prompt = chars(probe.seen[0])
    # Window edge: turn one's three results at the per-call bound just fit, nothing more.
    edge = max(
        prompt + sum(small[:j]) + RESULT_BOUND + (2 - j) * stop + len(forced_final()) for j in range(3)
    )
    cfg = investigator_config(whole_chars(edge, 1.0), 1.0, investigator_result_chars=RESULT_BOUND)

    result, llm = run(cfg, make_toolbox(cfg), script)

    assert result.error is None
    assert result.error != registry.entry("tools.closing_not_fitted")
    assert result.status == "ok"
    assert [s.section_id for s in result.proposed] == ["s1"]
    assert all(chars(request) <= final_window(cfg) for request in llm.seen)
    assert str(llm.seen[-1][-1].content) == forced_final()
    assert result.run_record.tool_calls


# --- AC-US8-2 (investigator): cannot fit after headroom -> invalid answer with the reason --------


def test_closing_request_between_eighty_and_a_hundred_percent_is_not_sent_under_the_default_headroom(files):
    files["s0.py"] = "a = 1"
    ample = investigator_config(10**6, 1.0)
    _, first = run(ample, make_toolbox(ample), [answer(VALID)])
    padding = "y"
    script = [reply(read("s0.py"), content=padding), answer(VALID)]
    # The window holds the unshortenable parts (prompt, closing instruction) within the default headroom with
    # a few chars to spare, so the stop message of the refused call is what pushes the closing request over.
    window = whole_chars(chars(first.seen[0]) + len(forced_final()) + 2, DEFAULT_HEADROOM)

    whole = investigator_config(window, 1.0)
    whole_result, whole_llm = run(whole, make_toolbox(whole), script)
    assert whole_result.status == "ok"
    assert 0.8 * window < chars(whole_llm.seen[-1]) <= window

    cfg = investigator_config(window)
    result, llm = run(cfg, make_toolbox(cfg), script)

    assert result.status == "failed"
    assert result.proposed is None
    assert result.error == registry.entry("tools.closing_not_fitted")
    assert all(chars(request) <= DEFAULT_HEADROOM * window for request in llm.seen)
    assert result.run_record.turns[0]["assistant"] == padding
    assert len(result.run_record.tool_calls) == 1


# --- AC-US8-3: the first request is bounded --------------------------------------------------------

HUGE_LINES = 400


def huge_diffs(n):
    changes = [LineChange(kind="add", content="z" * 150) for _ in range(n)]
    hunk = Hunk(old_start=1, old_count=0, new_start=1, new_count=n, changes=changes)
    return [FileDiff(path="app.py", status="modified", hunks=[hunk])]


def first_request_setup(files):
    files["app.py"] = body("APP", SMALL_LINES)
    files["other.py"] = body("OTH", SMALL_LINES)
    bound = 4000
    base = investigator_config(10**6, 1.0, investigator_diff_chars=10**6, investigator_result_chars=bound)
    _, small = run(base, make_toolbox(base), [answer(VALID)], huge_diffs(1))
    _, full = run(base, make_toolbox(base), [answer(VALID)], huge_diffs(HUGE_LINES))
    read_chars = len(default_read(base, "app.py", snapshot="pr"))
    kept = chars(small.seen[0]) + 5000
    window = whole_chars(kept + len(forced_final()) + bound + read_chars + 200, DEFAULT_HEADROOM)
    cfg = investigator_config(window, investigator_diff_chars=10**6, investigator_result_chars=bound)
    return cfg, small.seen[0], full.seen[0], window


def test_a_first_request_over_the_headroom_window_is_cut_with_a_marker_and_keeps_system_and_instructions(files):
    cfg, _, full, window = first_request_setup(files)
    assert chars(full) > DEFAULT_HEADROOM * window

    result, llm = run(cfg, make_toolbox(cfg), [answer(VALID)], huge_diffs(HUGE_LINES))

    sent = llm.seen[0]
    full_user, sent_user = str(full[1].content), str(sent[1].content)
    assert result.status == "ok"
    assert result.error is None
    assert chars(sent) + len(forced_final()) <= DEFAULT_HEADROOM * window
    assert sent[0].content == full[0].content
    assert sent_user[:200] == full_user[:200]
    assert sent_user[-200:] == full_user[-200:]
    assert len(sent_user) < len(full_user)
    new_numbers = set(re.findall(r"\d{2,}", sent_user)) - set(re.findall(r"\d{2,}", full_user))
    assert new_numbers


def test_a_whole_file_read_is_served_when_the_diff_of_that_file_was_cut_from_the_prompt(files):
    cfg, _, _, _ = first_request_setup(files)

    result, llm = run(cfg, make_toolbox(cfg), [reply(read("app.py", "pr")), answer(VALID)], huge_diffs(HUGE_LINES))

    assert tool_texts(llm.seen[1]) == [default_read(cfg, "app.py", snapshot="pr")]
    assert result.status == "ok"


def test_the_run_record_gains_no_field():
    assert {f.name for f in dataclasses.fields(RunRecord)} == {
        "section",
        "tool_calls",
        "raw_answer",
        "limit_hit",
        "turns",
    }


# --- AC-US7-7: one bound result still fits at the default fraction ------------------------------------


def test_one_result_at_the_bound_fits_the_headroom_window_beside_the_largest_prompt(config):
    prompt_chars, _ = largest_full_prompt(config)

    needed = prompt_chars + len(forced_final()) + config.investigator_result_chars
    assert needed <= DEFAULT_HEADROOM * final_window(config)


# --- authorization reviewer and SAST triage ---------------------------------------------------------------


class Script:
    """Records every request as a list of texts; replays the replies, repeating the last."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests: list[list] = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.requests.append(list(messages))
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


AUTHZ_ANSWER = json.dumps({"findings": []})
SAST_ANSWER = json.dumps({"verdict": "safe", "cwe_id": "CWE-89", "explanation": "parameterized", "evidence": []})
READ_APP = {"name": "read_file", "args": {"path": "app.py"}, "id": "c1"}


def run_authz(git_repo, cfg, llm, big=False):
    lines = tuple("z" * 150 for _ in range(HUGE_LINES // 2)) if big else ("a = 1", "b = 2", "c = 3")
    agent = AuthzReviewerAgent(_snapshot_toolbox(git_repo, cfg), cfg, llm=llm)
    findings = agent.review_section(_section([_hunk(lines=lines)]))
    return findings, agent.errors, "s1", agent.run_records


def run_sast(git_repo, cfg, llm, big=False):
    diff = huge_diffs(HUGE_LINES // 2)[0] if big else None
    agent = SASTTriageAgent(_snapshot_toolbox(git_repo, cfg), cfg, llm=llm)
    finding = agent.triage(SEMGREP_HIT, diff)
    return ([] if finding is None else [finding]), agent.errors, SEMGREP_HIT.finding_id, agent.run_records


RUNNERS = {"authz": (run_authz, AUTHZ_ANSWER), "sast": (run_sast, SAST_ANSWER)}


def agent_config(window_chars=None, fraction=None, **overrides):
    cfg = LGTMConfig(llm_retries=0, **overrides)
    if window_chars is not None:
        cfg.llm_context_tokens = window_chars // CHARS_PER_TOKEN + cfg.llm_max_output_tokens
    return cfg if fraction is None else pinned(cfg, fraction)


@pytest.mark.parametrize("agent", list(RUNNERS))
def test_requests_that_fit_the_window_are_identical_to_those_with_ample_room(git_repo, agent):
    run_agent, final = RUNNERS[agent]
    script = (AIMessage(content="", tool_calls=[READ_APP]), AIMessage(content=final))

    def texts(cfg):
        llm = Script(*script)
        run_agent(git_repo, cfg, llm)
        return [[str(m.content) for m in request] for request in llm.requests]

    assert texts(agent_config()) == texts(agent_config(10**7))


@pytest.mark.parametrize("agent", list(RUNNERS))
def test_a_request_between_eighty_and_a_hundred_percent_of_the_window_degrades_with_a_context_reason(git_repo, agent):
    run_agent, final = RUNNERS[agent]
    script = (AIMessage(content="",tool_calls=[READ_APP]), AIMessage(content=final))
    roomy = Script(*script)
    run_agent(git_repo, agent_config(10**7), roomy)
    # The most recent result is kept whole: the window fits the closing request (prompt, result, closing
    # instruction) exactly, which is far above the default headroom share.
    window = whole_chars(chars(roomy.requests[-1]) + len(registry.entry("shared.forced_final")), 1.0)

    whole = Script(*script)
    _, whole_errors, _, _ = run_agent(git_repo, agent_config(window, 1.0), whole)
    assert whole_errors == []
    assert chars(whole.requests[-1]) > DEFAULT_HEADROOM * window

    llm = Script(*script)
    findings, errors, source, records = run_agent(git_repo, agent_config(window), llm)

    assert findings == []
    assert [e["source"] for e in errors] == [source]
    assert "context" in errors[0]["message"].lower()
    assert len(llm.requests) == 1
    assert all(chars(request) <= DEFAULT_HEADROOM * window for request in llm.requests)
    assert len(records) == 1
    assert len(records[0].tool_calls) == 1
    assert [len(t["tool_calls"]) for t in records[0].turns] == [1]


@pytest.mark.parametrize("agent", list(RUNNERS))
def test_a_first_request_over_the_headroom_window_is_bounded_before_any_tool_call(git_repo, agent):
    run_agent, final = RUNNERS[agent]
    small, full = Script(AIMessage(content=final)), Script(AIMessage(content=final))
    run_agent(git_repo, agent_config(10**7), small)
    run_agent(git_repo, agent_config(10**7), full, big=True)
    forced = len(registry.entry("shared.forced_final"))
    kept = chars(small.requests[0]) + (chars(full.requests[0]) - chars(small.requests[0])) // 2
    window = whole_chars(kept + forced, DEFAULT_HEADROOM)
    assert chars(full.requests[0]) > DEFAULT_HEADROOM * window

    llm = Script(AIMessage(content=final))
    findings, errors, _, _ = run_agent(git_repo, agent_config(window), llm, big=True)

    sent = llm.requests[0]
    full_user, sent_user = str(full.requests[0][1].content), str(sent[1].content)
    assert errors == []
    assert chars(sent) + forced <= DEFAULT_HEADROOM * window
    assert sent[0].content == full.requests[0][0].content
    assert sent_user[:200] == full_user[:200]
    assert sent_user[-200:] == full_user[-200:]
    assert set(re.findall(r"\d{2,}", sent_user)) - set(re.findall(r"\d{2,}", full_user))


def test_the_request_built_for_a_retry_is_bounded_like_the_first(git_repo):
    run_agent, final = RUNNERS["authz"]
    ghost = {"type": "code", "file": "ghost_module.py", "lines": [1, 1], "content": "zz", "snapshot": "pr"}
    unresolved = json.dumps({"findings": [{"file": "app.py", "line": 11, "cwe_id": "CWE-862", "evidence": [ghost]}]})
    script = (AIMessage(content=unresolved), AIMessage(content=final))
    small, full = Script(*script), Script(*script)
    run_agent(git_repo, agent_config(10**7), small)
    run_agent(git_repo, agent_config(10**7), full, big=True)
    forced = len(registry.entry("shared.forced_final"))
    kept = chars(small.requests[0]) + (chars(full.requests[0]) - chars(small.requests[0])) // 2
    window = whole_chars(kept + forced + 600, DEFAULT_HEADROOM)

    llm = Script(*script)
    _, errors, _, _ = run_agent(git_repo, agent_config(window), llm, big=True)

    assert errors == []
    assert len(llm.requests) == 2
    assert "ghost_module.py" in str(llm.requests[1][1].content)
    assert all(chars(request) + forced <= DEFAULT_HEADROOM * window for request in llm.requests)


# --- AC-US8-1: only the closing request may lose the stop turn's assistant text ----------------------------


@pytest.mark.parametrize("agent", list(RUNNERS))
def test_a_tool_round_request_over_the_window_does_not_trim_the_previous_assistant_text(git_repo, agent):
    run_agent, final = RUNNERS[agent]
    fat = "y" * 4000
    script = (AIMessage(content=fat), AIMessage(content=final))
    roomy = Script(*script)
    run_agent(git_repo, agent_config(10**7, require_tool_use=True), roomy)
    push = len(roomy.requests[1][-1].content)
    forced = len(registry.entry("shared.forced_final"))
    # The first request fits; the second holds the long text and the push-back, which only trimming that text could fit.
    window = whole_chars(chars(roomy.requests[0]) + forced + push + 200, DEFAULT_HEADROOM)
    assert chars(roomy.requests[1]) > DEFAULT_HEADROOM * window

    llm = Script(*script)
    findings, errors, source, records = run_agent(git_repo, agent_config(window, require_tool_use=True), llm)

    assert findings == []
    assert [e["source"] for e in errors] == [source]
    assert "context" in errors[0]["message"].lower()
    assert len(llm.requests) == 1
    assert [t["assistant"] for t in records[0].turns] == [fat]


# --- AC-US8-1: the closing request's stop-turn text trim ----------------------------------------------------

TEXT_CALL = '<tool_call>{"name": "read_file", "arguments": {"path": "new.py", "snapshot": "base"}}</tool_call>'


def stop_turn_run(files, config, content):
    prompt_chars, bound = probe(config, files)
    cfg = tight(config, prompt_chars, bound, slots=2.5)
    files["old.py"] = body("OLD", BIG_LINES)
    files["new.py"] = body("NEW", BIG_LINES)
    result, llm = run(cfg, make_toolbox(cfg), [reply(read("old.py")), AIMessage(content=content), answer(VALID)])
    return result, llm, cfg


def test_the_trimmed_stop_turn_text_is_the_longest_prefix_that_fits_the_closing_request(files, config):
    prompt_chars, bound = probe(config, files)
    cfg = tight(config, prompt_chars, bound, slots=2.5)
    files["old.py"] = body("OLD", BIG_LINES)
    files["new.py"] = body("NEW", BIG_LINES)
    fat = "y" * (3 * bound)

    result, llm = run(cfg, make_toolbox(cfg), [reply(read("old.py")), reply(read("new.py"), content=fat), answer(VALID)])

    closing = llm.seen[-1]
    sent = str(next(m for m in closing if isinstance(m, AIMessage) and m.tool_calls and m.content).content)
    assert result.status == "ok"
    assert fat.startswith(sent)
    assert chars(closing) == final_window(cfg)


def test_a_text_form_stop_turn_keeps_its_tool_call_markup_whole_when_its_text_is_trimmed(files, config):
    _, bound = probe(config, files)
    # The tail after the markup is shorter than the excess: a plain tail cut would reach into the markup.
    content = "p" * (2 * bound) + TEXT_CALL + "q" * (bound // 2)

    result, llm, cfg = stop_turn_run(files, config, content)

    sent = [str(m.content) for m in llm.seen[-1] if isinstance(m, AIMessage) and "<tool_call>" in str(m.content)]
    assert result.status == "ok"
    assert len(sent) == 1
    assert TEXT_CALL in sent[0]
    assert len(sent[0]) < len(content)
    assert chars(llm.seen[-1]) <= final_window(cfg)
    assert [t["assistant"] for t in result.run_record.turns][1] == content


def test_a_text_form_stop_turn_without_prose_to_trim_never_sends_cut_markup(files, config):
    result, llm, cfg = stop_turn_run(files, config, TEXT_CALL)

    assert all(chars(request) <= final_window(cfg) for request in llm.seen[1:])
    for request in llm.seen:
        texts = [str(m.content) for m in request if isinstance(m, AIMessage) and "<tool_call>" in str(m.content)]
        assert all(TEXT_CALL in text for text in texts)
    assert [t["assistant"] for t in result.run_record.turns][1] == TEXT_CALL


# --- cut_to_fit never exceeds its budget ---------------------------------------------------------------------


def marker_length(cut):
    return len(registry.render("shared.prompt_cut", chars=cut))


@pytest.mark.parametrize("length", [150, 1010, 10100])
def test_cut_to_fit_never_exceeds_its_budget_at_any_budget_including_digit_count_boundaries(length):
    text = "".join(chr(97 + i % 26) for i in range(length))

    for budget in range(0, length + 2):
        cut = cut_to_fit(text, budget)
        assert len(cut) <= budget, (length, budget)
        if budget >= length:
            assert cut == text
        elif budget >= marker_length(length) + 2:
            assert cut[0] == text[0] and cut[-1] == text[-1], (length, budget)


@pytest.mark.parametrize("budget", [0, 1, 5])
def test_cut_to_fit_with_a_budget_smaller_than_the_marker_stays_within_the_budget(budget):
    assert budget < marker_length(10)
    assert len(cut_to_fit("x" * 5000, budget)) <= budget
