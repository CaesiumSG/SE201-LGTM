"""Per-case result JSON of the synthetic and real-world runners: the `trace` key, its content, and unchanged keys."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import PrivateAttr

import lgtm.validation.judge as judge_module
from lgtm.agents.base import (
    AgentFinding,
    EvidenceItem,
    RunRecord,
    answer_until_resolved,
    fill_record,
    is_json_object,
    request_valid_answer,
    run_tool_loop,
)
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.reporting.report_builder import ReviewMetadata
from lgtm.validation.judge import (
    REASON_JUDGE_FAILED,
    REASON_REQUEST_TOO_LARGE,
    REQUEST_FORMATS,
    build_judge_request,
    judge_candidates,
)

ROOT = Path(__file__).resolve().parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


evaluate = _load("case_record_bench_evaluate", ROOT / "benchmark" / "evaluate.py")
er = _load("case_record_rw_evaluate_real", ROOT / "benchmark" / "real_world" / "evaluate_real.py")

TURN_TEXT = "TRACE_TURN_TEXT_SENTINEL"
CASE_ID = "aegra_authz_vulnerable"


def _ai(content, tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls or [])


class _LLM:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.seen: list = []

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.seen = list(messages)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def _real_record(git_repo) -> tuple[RunRecord, str]:
    llm = _LLM(
        _ai(TURN_TEXT, [{"name": "read_file", "args": {"path": "app.py"}, "id": "c1"}]),
        _ai('{"verdict": "safe"}'),
    )
    toolbox = AgentToolbox(git_repo, "main", None, LGTMConfig())
    record = RunRecord(section="authz:s1")
    out = run_tool_loop(llm, toolbox.build_tools(), "sys", "user", toolbox.config)
    fill_record(record, toolbox, out)
    [result] = [m.content for m in llm.seen if type(m).__name__ == "ToolMessage"]
    return record, result


def _kev_finding() -> AgentFinding:
    finding = AgentFinding(
        finding_id="authz:1", category="authz", explanation="no ownership check", file="app.py", line=1,
        evidence=[EvidenceItem(type="code", file="app.py", lines=[1, 1], content="x", snapshot="pr")],
    )
    request = build_judge_request(finding, lambda item: "CODE", model="kev-test", max_chars=200_000)
    answers = {}
    for qid, question in request["questions"].items():
        kind = question["type"]
        if kind == "noul":
            answers[qid] = {"type": "noul", "noul": 0.9}
        elif kind == "score":
            answers[qid] = {"type": "score", "score": 0.5, "legend": list(question["criteria"]),
                            "probabilities": {}, "confidence": 0.5}
        else:
            labels = list(question["criteria"])
            label = next((n for n in labels if n.lower().startswith("y")), labels[0]) if qid == "supported" else labels[0]
            answers[qid] = {"type": "choice", "choice": label, "confidence": 0.8,
                            "probabilities": {n: (0.9 if n == label else 0.1) for n in labels}}
    reply = {"model": "kev-test", "answers": answers, "usage": {"input_tokens": 1, "output_tokens": 0}}
    judge_candidates([finding], lambda item: "CODE", LGTMConfig(), lambda req: judge_module.parse_kev_reply(reply))
    return finding


class _UnserialisableFinding(AgentFinding):
    def model_dump(self, *args, **kwargs):
        raise TypeError("not serialisable")


class _FlakyFinding(AgentFinding):
    """Serialises on every call but the first, so the post-review step fails and the error path still can."""

    _dumps: int = PrivateAttr(default=0)

    def model_dump(self, *args, **kwargs):
        self._dumps += 1
        if self._dumps == 1:
            raise TypeError("not serialisable")
        return super().model_dump(*args, **kwargs)


class _Pipeline:
    review = None

    def __init__(self, repo, config, **kwargs):
        pass

    def run(self, base, pr, output_dir=None):
        return type(self).review


def _run_synthetic(monkeypatch, tmp_path, mode, review):
    pipeline = type("Pipeline", (_Pipeline,), {"review": review})
    monkeypatch.setattr(evaluate, "build_case_repo", lambda tmp, patch: None)
    monkeypatch.setattr(evaluate, "index_repo_docs", lambda tmp, cfg: 0)
    monkeypatch.setattr(evaluate, "run_pin", lambda *a, **k: {"code_sha": "abc"})
    monkeypatch.setattr(evaluate, "ReviewPipeline", pipeline)
    monkeypatch.setattr(evaluate, "record_input_tokens", lambda p, c: {})
    case = {"id": "c", "category": "authz", "split": "dev", "expected_verdict": "vulnerable", "patch_file": "x.patch"}
    return evaluate.evaluate_case(case, LGTMConfig(mode=mode))


def _run_real_world(monkeypatch, tmp_path, mode, review):
    pipeline = type("Pipeline", (_Pipeline,), {"review": review})
    case = next(c for c in er.fetch.load_cases() if c["id"] == CASE_ID)
    monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
    monkeypatch.setattr(er, "ReviewPipeline", pipeline)
    monkeypatch.setattr(er, "ensure_index", lambda *a, **k: {"seconds": 0.0, "chunks": 0, "reused": True})
    monkeypatch.setattr(er, "run_pin", lambda *a, **k: {"code_sha": "abc"})
    monkeypatch.setattr(er.evaluate, "record_input_tokens", lambda p, c: {})
    return er.run_unit(case, mode, tmp_path / "cache", tmp_path / "out", LGTMConfig())


BASE_FINDING_KEYS = {
    "agent", "category", "cwe_id", "evidence", "explanation", "file", "finding_id", "judged", "kev_severity",
    "kev_verdict", "line", "not_judged_reason", "pr_graph_ok", "provenance_confidence", "semgrep_message",
    "semgrep_rule_id", "semgrep_severity", "severity", "suggested_fix", "supported", "tool_calls_used",
    "unsupported_reason", "verdict",
}
# lgtm.usage.record_fields: real token counts, written by every runner.
TOKEN_KEYS = {
    "estimated_input_tokens", "input_tokens", "judge_calls", "judge_input_tokens", "llm_calls",
    "llm_calls_without_usage", "output_tokens", "tokens_by_stage", "total_tokens",
}
BASE_TOP_KEYS = {
    _run_synthetic: TOKEN_KEYS | {
        "alarms_outside_target", "base_sha", "case_label", "case_label_grounded", "category", "correct",
        "coverage_gap", "est_tokens", "expected", "findings", "graph_index_seconds", "graph_state", "grounded",
        "grounding_rate", "id", "infra_failure_ids", "infra_failures", "latency_seconds", "mode", "n_findings",
        "off_category", "outcome", "outcome_grounded", "pin", "pr_sha", "predicted", "predicted_grounded",
        "run_records", "sast_error", "scope", "semgrep_findings_total", "split", "target_sections",
        "triage_errors", "verdicts",
    },
    _run_real_world: TOKEN_KEYS | {
        "alarms_outside_target", "base_sha", "case_label", "case_label_grounded", "case_scope", "case_seconds",
        "category", "correct", "coverage_gap", "diff_added", "diff_deleted", "diff_files", "diff_max_file_chars",
        "diff_py_chars", "est_tokens", "expected", "file", "findings", "graph_index_seconds", "graph_state",
        "grounded", "grounding_rate", "id", "index_chunks", "index_reused", "index_seconds", "index_skip_reason",
        "index_skipped", "infra_failure_ids", "infra_failures", "latency_seconds", "mode", "n_findings",
        "off_category", "outcome", "outcome_grounded", "pin", "pr_sha", "predicted", "predicted_grounded",
        "project", "run_records", "sast_error", "scope", "semgrep_findings_in_diff", "semgrep_findings_total",
        "split", "target_sections", "triage_errors", "verdicts",
    },
}


def _reasoning_keys(row):
    return [k for f in row["findings"] for k in f if "reasoning" in k]


RUNNERS = pytest.mark.parametrize("runner", [_run_synthetic, _run_real_world], ids=["synthetic", "real-world"])


def _review(findings, records):
    return SimpleNamespace(findings=findings, meta=ReviewMetadata(), run_records=records)


@RUNNERS
class TestTraceInLgtmResults:
    def test_trace_holds_the_turns_tool_results_and_kev_results_without_reasoning(self, runner, monkeypatch, tmp_path, git_repo):
        record, tool_result = _real_record(git_repo)

        row = runner(monkeypatch, tmp_path, "lgtm", _review([_kev_finding()], [record]))

        trace = json.dumps(row["trace"])
        assert TURN_TEXT in trace
        assert json.dumps(tool_result)[1:-1] in trace
        kev = row["trace"]["kev"][0]
        assert kev["judged"] is True
        assert kev["kev_verdict"] and kev["kev_severity"]
        assert kev["supported"] is True
        assert not any("reasoning" in k for k in kev)
        assert _reasoning_keys(row) == []

    def test_trace_key_is_present_and_the_row_is_json_when_no_agent_ran(self, runner, monkeypatch, tmp_path):
        row = runner(monkeypatch, tmp_path, "lgtm", _review([], []))

        assert "trace" in row
        json.dumps(row)

    def test_scores_and_existing_keys_are_unchanged_by_the_trace(self, runner, monkeypatch, tmp_path, git_repo):
        record, _ = _real_record(git_repo)

        row = runner(monkeypatch, tmp_path, "lgtm", _review([_kev_finding()], [record]))

        assert row["n_findings"] == 1
        assert row["verdicts"] == ["vulnerable"]
        assert row["outcome"] == "TP"
        assert row["findings"][0]["finding_id"] == "authz:1"
        assert row["findings"][0]["explanation"] == "no ownership check"
        assert [r["section"] for r in row["run_records"]] == ["authz:s1"]
        assert row["run_records"][0]["tool_calls"][0]["tool"] == "read_file"
        assert row["mode"] == "lgtm"

    def test_a_failure_after_the_review_keeps_trace_findings_and_the_error(
        self, runner, monkeypatch, tmp_path, git_repo
    ):
        record, _ = _real_record(git_repo)

        partial = _FlakyFinding(
            finding_id="part:1", category="authz", explanation="x", file="app.py", line=1
        )
        row = runner(monkeypatch, tmp_path, "lgtm", _review([partial], [record]))

        assert row["outcome"] == "ERROR"
        assert row["error"]
        json.dumps(row)
        assert {"id", "category", "expected", "mode", "findings", "n_findings", "verdicts", "pin"} <= set(row)
        assert row["mode"] == "lgtm"
        assert row["findings"] == []
        assert [f["finding_id"] for f in row["trace"]["findings"]] == ["part:1"]
        assert [r["section"] for r in row["run_records"]] == ["authz:s1"]
        assert row["run_records"][0]["tool_calls"][0]["tool"] == "read_file"
        assert TURN_TEXT in json.dumps(row["trace"]["runs"])

    def test_an_error_row_with_an_unjudged_partial_finding_counts_as_an_error_and_not_in_kev_metrics(
        self, runner, monkeypatch, tmp_path
    ):
        partial = _FlakyFinding(
            finding_id="part:1", category="authz", explanation="x", file="app.py", line=1
        )
        error_row = runner(monkeypatch, tmp_path, "lgtm", _review([partial], []))
        assert error_row["outcome"] == "ERROR" and error_row["trace"]["findings"]
        ok_row = runner(monkeypatch, tmp_path, "lgtm", _review([_kev_finding()], []))
        error_row["id"] = "err"
        ok_row["id"] = "ok"

        summary = evaluate.summarize([error_row, ok_row])
        assert summary["errors"] == 1
        assert [c["id"] for c in summary["error_cases"]] == ["err"]
        assert summary["kev"]["judged"] == 1
        assert summary["kev"]["not_judged"] == {}

        out = tmp_path / "lgtm"
        out.mkdir()
        for r in (error_row, ok_row):
            (out / f"{r['id']}.json").write_text(json.dumps(r), encoding="utf-8")
        written = er.write_dir_summary(out, "lgtm", {"err", "ok"}, "m")["summary"]
        assert written["errors"] == 1
        assert [c["id"] for c in written["error_cases"]] == ["err"]
        assert written["kev"]["judged"] == 1
        assert written["kev"]["not_judged"] == {}


class TestRunRecordIsolation:
    def test_a_later_run_without_a_new_record_does_not_append_to_an_earlier_record(self, git_repo):
        earlier, _ = _real_record(git_repo)
        turns_before = list(earlier.turns)
        assert turns_before

        llm = _LLM(_ai("LATER_RUN_TEXT"))
        toolbox = AgentToolbox(git_repo, "main", None, LGTMConfig())
        run_tool_loop(llm, toolbox.build_tools(), "sys", "user", toolbox.config)

        assert earlier.turns == turns_before


class _ScriptLLM(_LLM):
    def invoke(self, messages):
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _texts(record):
    return [t["assistant"] for t in record.turns]


class TestEveryModelTurnIsRecorded:
    def test_a_reask_attempt_that_raises_keeps_its_turns_after_the_earlier_attempt(self, git_repo):
        config = LGTMConfig(llm_retries=0)
        toolbox = AgentToolbox(git_repo, "main", None, config)
        llm = _ScriptLLM(
            _ai('{"n": "ATTEMPT_ONE"}'),
            _ai("ATTEMPT_TWO", [{"name": "read_file", "args": {"path": "app.py"}, "id": "c1"}]),
            RuntimeError("model down"),
        )
        record = RunRecord(section="authz:s1")

        with pytest.raises(RuntimeError, match="model down"):
            answer_until_resolved(
                lambda note="": fill_record(
                    record, toolbox, run_tool_loop(llm, toolbox.build_tools(), "sys", "user", config)
                ),
                lambda raw: None,
                toolbox,
            )

        assert _texts(record) == ['{"n": "ATTEMPT_ONE"}', "ATTEMPT_TWO"]
        assert record.turns[1]["tool_calls"][0]["tool"] == "read_file"

    def test_an_invalid_json_reply_and_the_valid_reply_after_it_are_both_recorded_in_order(self, git_repo):
        config = LGTMConfig()
        toolbox = AgentToolbox(git_repo, "main", None, config)
        record = RunRecord(section="authz:s1")
        llm = _LLM(_ai("NOT_JSON_REPLY"), _ai('{"verdict": "safe"}'))

        out = run_tool_loop(llm, toolbox.build_tools(), "sys", "user", config)
        fill_record(record, toolbox, out)

        assert _texts(record) == ["NOT_JSON_REPLY", '{"verdict": "safe"}']

    def test_request_valid_answer_reports_each_reask_reply_to_on_turn(self):
        seen = []
        llm = _LLM(_ai("STILL_NOT_JSON"), _ai('{"ok": 1}'))

        out = request_valid_answer(llm, [], "NOT_JSON", LGTMConfig(), is_json_object, seen.append)

        assert out == '{"ok": 1}'
        assert seen == ["STILL_NOT_JSON", '{"ok": 1}']

    def test_a_run_that_spends_its_tool_budget_records_the_forced_final_turn(self, git_repo):
        config = LGTMConfig(max_tool_calls=1)
        toolbox = AgentToolbox(git_repo, "main", None, config)
        record = RunRecord(section="authz:s1")
        llm = _LLM(
            _ai("CALL_TURN", [{"name": "read_file", "args": {"path": "app.py"}, "id": "c1"}]),
            _ai('{"verdict": "FORCED_FINAL"}'),
        )

        out = run_tool_loop(llm, toolbox.build_tools(), "sys", "user", config)
        fill_record(record, toolbox, out)

        assert record.limit_hit == "tool_calls"
        assert _texts(record) == ["CALL_TURN", '{"verdict": "FORCED_FINAL"}']


class TestUnjudgedFindingInTrace:
    @pytest.mark.parametrize("reason", [REASON_JUDGE_FAILED, REASON_REQUEST_TOO_LARGE])
    def test_trace_records_the_unjudged_state_and_reason_without_reasoning(self, monkeypatch, tmp_path, reason):
        finding = AgentFinding(
            finding_id="authz:2", category="authz", explanation="no ownership check", file="app.py", line=1,
            evidence=[EvidenceItem(type="code", file="app.py", lines=[1, 1], content="x", snapshot="pr")],
        )
        if reason == REASON_JUDGE_FAILED:
            def judge(request):
                raise RuntimeError("kev unreachable")
            read = lambda item: "CODE"  # noqa: E731
        else:
            judge = lambda request: {}  # noqa: E731
            read = lambda item: "x" * 100_000  # noqa: E731
        judge_candidates([finding], read, LGTMConfig(), judge)
        agreeing = _kev_finding()

        for runner in (_run_synthetic, _run_real_world):
            row = runner(monkeypatch, tmp_path, "lgtm", _review([finding, agreeing], []))

            by_id = {k["finding_id"]: k for k in row["trace"]["kev"]}
            unjudged = by_id["authz:2"]
            assert unjudged["judged"] is False
            assert unjudged["not_judged_reason"] == reason
            assert unjudged["kev_verdict"] is None
            assert not any("reasoning" in k for k in unjudged)
            assert by_id["authz:1"]["judged"] is True
            assert by_id["authz:1"]["not_judged_reason"] in ("", None)


class TestKevPromptHasNoReasoningRequest:
    @pytest.mark.parametrize("request_format", REQUEST_FORMATS)
    def test_questions_carry_no_added_reasoning_request(self, request_format):
        finding = AgentFinding(
            finding_id="authz:1", category="authz", explanation="no ownership check", file="app.py", line=1,
            evidence=[EvidenceItem(type="code", file="app.py", lines=[1, 1], content="x", snapshot="pr")],
        )
        request = build_judge_request(
            finding, lambda item: "CODE", model="kev-test", max_chars=200_000, request_format=request_format
        )

        for question in request["questions"].values():
            assert "reasoning" not in question["instructions"].lower()
        if request_format == "current":
            instructions = {q["instructions"] for q in request["questions"].values()}
            assert any(i.startswith("Does the cited code support the claimed security flaw?\n") for i in instructions)
            assert any(
                i.startswith("Is the claimed security flaw a real vulnerability in the cited code?\n")
                for i in instructions
            )


@RUNNERS
class TestLlmOnlyResultsAreUnchanged:
    def test_llm_only_result_has_no_trace_or_kev_content(self, runner, monkeypatch, tmp_path):
        finding = AgentFinding(
            finding_id="plain:1", category="authz", explanation="no ownership check", verdict="vulnerable",
            supported=True, file="app.py", line=1,
        )

        row = runner(monkeypatch, tmp_path, "llm-only", _review([finding], []))

        assert "trace" not in row
        assert set(row) == BASE_TOP_KEYS[runner]
        assert set(row["findings"][0]) == BASE_FINDING_KEYS
        assert row["verdicts"] == ["vulnerable"] and row["outcome"] == "TP"
        assert row["run_records"] == []


class TestEarlierResultsStillLoad:
    @staticmethod
    def _old(cid, outcome):
        return {
            "id": cid, "category": "authz", "split": "real_world", "expected": "vulnerable",
            "predicted": "vulnerable", "outcome": outcome, "correct": outcome == "TP",
            "predicted_grounded": "vulnerable", "outcome_grounded": outcome, "n_findings": 0,
            "verdicts": [], "grounded": 0, "grounding_rate": None, "latency_seconds": 1.0,
            "est_tokens": 0, "findings": [], "run_records": [], "pin": {}, "mode": "lgtm",
        }

    @pytest.mark.parametrize("with_trace", [False, True], ids=["old-without-trace", "new-with-trace"])
    def test_result_files_load_in_both_readers_and_summarise_alike(self, tmp_path, with_trace):
        out = tmp_path / "lgtm"
        out.mkdir()
        row = self._old("a", "TP")
        if with_trace:
            row["trace"] = {"runs": [], "kev": []}
        (out / "a.json").write_text(json.dumps(row), encoding="utf-8")

        assert evaluate.load_result(out / "a.json")["id"] == "a"
        assert evaluate.is_done(out / "a.json") is True
        summary = er.write_dir_summary(out, "lgtm", {"a"}, "m")
        assert summary["complete"] is True
        assert summary["summary"]["overall"]["tp"] == 1
