"""Per-case result JSON of the synthetic and real-world runners: the `trace` key, its content, and unchanged keys."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import lgtm.validation.judge as judge_module
from lgtm.agents.base import AgentFinding, EvidenceItem, RunRecord, fill_record, run_tool_loop
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.reporting.report_builder import ReviewMetadata
from lgtm.validation.judge import build_judge_request, judge_candidates

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
KEV_TEXT = "TRACE_KEV_REASONING_SENTINEL the sink gets a formatted string"
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
    out = run_tool_loop(llm, toolbox.build_tools(), "sys", "user", toolbox.config)
    record = RunRecord(section="authz:s1")
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
    for answer in answers.values():
        answer["reasoning"] = KEV_TEXT
    reply = {"model": "kev-test", "answers": answers, "usage": {"input_tokens": 1, "output_tokens": 0},
             "reasoning": KEV_TEXT}
    judge_candidates([finding], lambda item: "CODE", LGTMConfig(), lambda req: judge_module.parse_kev_reply(reply))
    return finding


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
BASE_TOP_KEYS = {
    _run_synthetic: {
        "alarms_outside_target", "base_sha", "case_label", "case_label_grounded", "category", "correct",
        "coverage_gap", "est_tokens", "expected", "findings", "graph_index_seconds", "graph_state", "grounded",
        "grounding_rate", "id", "infra_failure_ids", "infra_failures", "latency_seconds", "mode", "n_findings",
        "off_category", "outcome", "outcome_grounded", "pin", "pr_sha", "predicted", "predicted_grounded",
        "run_records", "sast_error", "scope", "semgrep_findings_total", "split", "target_sections",
        "triage_errors", "verdicts",
    },
    _run_real_world: {
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


def _kev_reasoning_keys(row):
    return [k for f in row["findings"] for k in f if "reasoning" in k]


RUNNERS = pytest.mark.parametrize("runner", [_run_synthetic, _run_real_world], ids=["synthetic", "real-world"])


def _review(findings, records):
    return SimpleNamespace(findings=findings, meta=ReviewMetadata(), run_records=records)


@RUNNERS
class TestTraceInLgtmResults:
    def test_trace_holds_the_turns_tool_results_and_kev_reasoning(self, runner, monkeypatch, tmp_path, git_repo):
        record, tool_result = _real_record(git_repo)

        row = runner(monkeypatch, tmp_path, "lgtm", _review([_kev_finding()], [record]))

        trace = json.dumps(row["trace"])
        assert TURN_TEXT in trace
        assert json.dumps(tool_result)[1:-1] in trace
        assert KEV_TEXT in trace
        assert _kev_reasoning_keys(row) == []
        assert KEV_TEXT not in json.dumps(row["findings"])

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

        def boom(*args, **kwargs):
            raise RuntimeError("scoring blew up")

        monkeypatch.setattr(evaluate, "finding_verdict", boom)
        monkeypatch.setattr(er.evaluate, "finding_verdict", boom)

        row = runner(monkeypatch, tmp_path, "lgtm", _review([_kev_finding()], [record]))

        assert row["outcome"] == "ERROR"
        assert "scoring blew up" in row["error"]
        trace = json.dumps(row["trace"])
        assert TURN_TEXT in trace and KEV_TEXT in trace
        assert _kev_reasoning_keys(row) == []
        assert [f["finding_id"] for f in row["findings"]] == ["authz:1"]


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
