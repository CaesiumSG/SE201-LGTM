"""Tests for the plain LLM-only baseline and the benchmark scoring rules."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from lgtm.agents import registry
from lgtm.agents.plain_reviewer import PlainLLMReviewer
from lgtm.agents.plain_reviewer import DEFAULT_CWE, VERDICTS
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import parse_unified_diff
from lgtm.pipeline import ReviewPipeline
from lgtm.reporting.report_builder import ReviewMetadata
from lgtm.review.provenance import run_pin as real_run_pin

_spec = importlib.util.spec_from_file_location(
    "bench_evaluate",
    Path(__file__).resolve().parent.parent / "benchmark" / "evaluate.py",
)
evaluate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluate)


class _NoToolsLLM:
    """Records calls and fails loudly if anyone tries to bind tools."""

    def __init__(self, content: str):
        self.content = content
        self.calls = 0

    def bind_tools(self, tools):  # pragma: no cover - must never be called
        raise AssertionError("llm-only baseline must not use tools")

    def invoke(self, messages):
        self.calls += 1
        self.messages = messages
        msg = MagicMock()
        msg.content = self.content
        msg.tool_calls = []
        return msg


ASSESSMENTS = json.dumps({
    "assessments": [
        {
            "category": "sqli", "verdict": "vulnerable", "confidence": 0.9,
            "cwe_id": "CWE-89", "file": "app.py", "line": 6,
            "explanation": "f-string into execute",
            "evidence": [{"type": "code", "file": "app.py", "lines": [6, 6],
                          "content": "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"}],
        },
        {"category": "authz", "verdict": "safe", "confidence": 0.6, "cwe_id": "CWE-862"},
    ]
})


class TestPlainReviewer:
    def test_parses_one_finding_per_category(self):
        findings = PlainLLMReviewer._parse(ASSESSMENTS)
        assert [f.category for f in findings] == ["sqli", "authz"]
        assert [f.verdict for f in findings] == ["vulnerable", "safe"]
        assert findings[0].line == 6 and findings[0].agent == "plain_llm"

    def test_category_inferred_from_cwe(self):
        raw = json.dumps({"assessments": [{"verdict": "vulnerable", "cwe_id": "CWE-89"}]})
        assert PlainLLMReviewer._parse(raw)[0].category == "sqli"
        assert PlainLLMReviewer._parse(raw)[0].verdict == "vulnerable"

    def test_prompt_asks_for_the_verdict_the_parser_reads(self):
        prompt = registry.entry("plain_reviewer.system_prompt")
        assert '"verdict"' in prompt
        for verdict in VERDICTS:
            assert verdict in prompt

    def test_unparsable_output_degrades(self):
        findings = PlainLLMReviewer._parse("I think it is fine.")
        assert len(findings) == 1
        assert findings[0].verdict == "insufficient_evidence"

    def test_llm_only_pipeline_uses_no_sast_rag_or_tools(self, git_repo):
        llm = _NoToolsLLM(ASSESSMENTS)
        config = LGTMConfig(mode="llm-only")
        result = ReviewPipeline(git_repo, config, llm=llm).run("main", "pr")
        assert llm.calls == 1
        assert result.meta.semgrep_findings_in_diff == 0
        prompt = llm.messages[1].content
        assert "find_user" in prompt  # the diff is the only context
        sqli = [f for f in result.findings if f.category == "sqli"][0]
        assert sqli.verdict == "vulnerable"
        assert sqli.judged is False


def _f(category, verdict, valid=None):
    """Baseline-form finding; `_case_row` turns it into a judged-form one for judged modes.

    `valid` sets `supported`, the flag grounded scoring reads on baseline-form findings.
    """
    finding = {"category": category, "verdict": verdict}
    if valid is not None:
        finding["supported"] = valid
    return finding


def _s(category, supported):
    return {"category": category, "supported": supported, "judged": True,
            "provenance_confidence": 0.9,
            "kev_verdict": "real" if supported else "not_real", "kev_severity": "medium"}


class TestCaseScoring:
    def test_other_category_findings_do_not_leak(self):
        # Regression: an authz case whose only finding is a SQLi "vulnerable"
        # used to fall back to all findings and be scored as flagged.
        assert evaluate.predict_case_verdict([_f("sqli", "vulnerable")], "authz") == "safe"

    def test_uncategorized_findings_count_for_any_category(self):
        assert evaluate.predict_case_verdict([_f("sast", "vulnerable")], "sqli") == "vulnerable"

    def test_grounded_scoring_discounts_unvalidated_detections(self):
        findings = [_f("authz", "vulnerable", valid=False)]
        assert evaluate.predict_case_verdict(findings, "authz") == "vulnerable"
        assert (
            evaluate.predict_case_verdict(findings, "authz", require_grounded=True)
            == "possible"
        )

    def test_score_case_and_summary_splits(self):
        rows = [
            evaluate.score_case({"id": "a", "category": "authz", "split": "dev",
                                 "expected": "vulnerable",
                                 "findings": [_f("authz", "vulnerable")],
                                 "coverage": _coverage([_target_section()]),
                                 "latency_seconds": 1.0, "est_tokens": 10}),
            evaluate.score_case({"id": "b", "category": "authz", "split": "eval",
                                 "expected": "safe", "findings": [_f("authz", "safe")],
                                 "coverage": _coverage([_target_section()]),
                                 "latency_seconds": 1.0, "est_tokens": 10}),
        ]
        assert rows[0]["outcome"] == "TP"
        summary = evaluate.summarize(rows)
        assert set(summary["per_split"]) == {"dev", "eval"}
        assert summary["overall"]["recall"] == 1.0
        assert summary["grounded_only"]["overall"]["recall"] == 0.0


@pytest.mark.parametrize("experiments", [False, True])
def test_benchmark_cli_keeps_remote_url_and_experiment_flags(tmp_path, monkeypatch, experiments):
    (tmp_path / "labels.json").write_text('{"cases": []}', encoding="utf-8")
    config = LGTMConfig()
    summary = MagicMock()
    monkeypatch.setattr(evaluate, "BENCH", tmp_path)
    monkeypatch.setattr(evaluate, "LGTMConfig", lambda: config)
    monkeypatch.setattr(evaluate, "write_summary", summary)
    argv = [
        "evaluate.py", "--ollama-url", "http://127.0.0.1:11435",
        "--model", "qwen2.5:7b", "--mode", "llm-only",
    ]
    if experiments:
        argv.extend(["--require-tool-use", "--static-facts", "--authz-role-guidance"])
    monkeypatch.setattr("sys.argv", argv)

    evaluate.main()

    assert config.ollama_base_url == "http://127.0.0.1:11435"
    assert config.ollama_model == "qwen2.5:7b"
    assert config.mode == "llm-only"
    assert config.require_tool_use is experiments
    assert config.static_facts is experiments
    assert config.authz_role_guidance is experiments
    assert summary.call_args.args[4]["experiments"] == {
        "require_tool_use": experiments,
        "static_facts": experiments,
        "authz_role_guidance": experiments,
    }
    # Mitigations are on by default and recorded in the run summary
    assert config.strip_comments is True
    assert config.detect_prompt_injection is True
    assert summary.call_args.args[4]["mitigations"] == {
        "strip_comments": True,
        "detect_prompt_injection": True,
    }


def test_benchmark_cli_can_switch_mitigations_off(tmp_path, monkeypatch):
    (tmp_path / "labels.json").write_text('{"cases": []}', encoding="utf-8")
    config = LGTMConfig()
    summary = MagicMock()
    monkeypatch.setattr(evaluate, "BENCH", tmp_path)
    monkeypatch.setattr(evaluate, "LGTMConfig", lambda: config)
    monkeypatch.setattr(evaluate, "write_summary", summary)
    monkeypatch.setattr("sys.argv", [
        "evaluate.py", "--no-strip-comments", "--no-detect-prompt-injection",
    ])

    evaluate.main()

    assert config.strip_comments is False
    assert config.detect_prompt_injection is False
    assert summary.call_args.args[4]["mitigations"] == {
        "strip_comments": False,
        "detect_prompt_injection": False,
    }


@pytest.mark.parametrize("options,model,url", [
    ([], "qwen3.8:27b", "http://localhost:11434"),
    (["--gpu-cluster"], "qwen3.8:27b", "http://127.0.0.1:11435"),
    (["--gpu-cluster", "--model", "custom:7b"], "custom:7b", "http://127.0.0.1:11435"),
    (["--gpu-cluster", "--ollama-url", "http://127.0.0.1:12000"],
     "qwen3.8:27b", "http://127.0.0.1:12000"),
])
def test_benchmark_model_connection(tmp_path, monkeypatch, options, model, url):
    (tmp_path / "labels.json").write_text('{"cases": []}', encoding="utf-8")
    summary = MagicMock()
    monkeypatch.setattr(evaluate, "BENCH", tmp_path)
    monkeypatch.setattr(evaluate, "write_summary", summary)
    monkeypatch.setattr("sys.argv", ["evaluate.py", *options])
    config = LGTMConfig()
    monkeypatch.setattr(evaluate, "LGTMConfig", lambda: config)

    evaluate.main()

    assert config.ollama_model == model
    assert config.ollama_base_url == url
    assert summary.call_args.args[3] == model


class TestRescore:
    def _run_dir(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        cases = [
            {"id": "a", "category": "authz", "split": "dev", "expected_verdict": "vulnerable"},
            {"id": "b", "category": "authz", "split": "eval", "expected_verdict": "safe"},
        ]
        (out / "a.json").write_text(json.dumps({
            "id": "a", "category": "authz", "expected": "vulnerable",
            "findings": [_f("authz", "vulnerable")], "latency_seconds": 1, "est_tokens": 1,
        }), encoding="utf-8")
        # An error result in the pre-grounding format (no outcome_grounded)
        (out / "b.json").write_text(json.dumps({
            "id": "b", "category": "authz", "expected": "safe", "predicted": "error",
            "outcome": "TN", "correct": True, "findings": [], "latency_seconds": 0,
            "est_tokens": 0,
        }))
        (out / "summary.json").write_text(json.dumps({
            "mode": "lgtm", "model": "m", "generated_at": "then", "git_commit": "abc",
            "split": "all", "experiments": {"static_facts": True},
            "outcomes": {"a": "TP", "b": "TN"}, "summary": {},
        }))
        return out, cases

    def test_keeps_provenance_and_handles_old_errors(self, tmp_path):
        out, cases = self._run_dir(tmp_path)
        evaluate.rescore(out, cases, "lgtm")
        saved = json.loads((out / "summary.json").read_text())
        assert saved["generated_at"] == "then" and saved["git_commit"] == "abc"
        assert saved["experiments"] == {"static_facts": True}
        assert "rescored_at_commit" in saved
        assert saved["outcomes"] == {"a": "UNKNOWN", "b": "ERROR"}
        unknown = json.loads((out / "a.json").read_text(encoding="utf-8"))
        assert (unknown["predicted"], unknown["outcome"], unknown["correct"]) == (
            "unknown", "UNKNOWN", None)
        assert unknown.get("coverage") is None

    def test_refuses_partial_rescore(self, tmp_path):
        import pytest

        out, cases = self._run_dir(tmp_path)
        with pytest.raises(SystemExit):
            evaluate.rescore(out, cases[:1], "lgtm")

    def test_rescore_normalizes_old_error_rows(self, tmp_path):
        out, cases = self._run_dir(tmp_path)
        evaluate.rescore(out, cases, "lgtm")
        row = json.loads((out / "b.json").read_text())
        assert row["outcome"] == "ERROR"
        assert row["outcome_grounded"] == "ERROR"
        assert row["predicted"] == "error"
        assert row["correct"] is None
        saved = json.loads((out / "summary.json").read_text())
        assert saved["summary"]["errors"] == 1
        assert saved["summary"]["overall"]["scored"] == 1


class TestRescoreNewFormat:
    LABEL_LOCATION = {"file": "app/orders.py", "old_range": None, "new_range": [10, 14]}
    LABEL_SHAPE = {"kind": "single_hunk"}
    STORED_PIN = {"code_sha": "stored-sha", "model": "stored-model"}

    @pytest.fixture(autouse=True)
    def no_run_pin(self, monkeypatch):
        def refuse(config, repo_root, refs, exclude=None):
            raise AssertionError("rescore must not compute a run pin")

        monkeypatch.setattr(evaluate, "run_pin", refuse)

    def _setup(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        cases = [
            {"id": "a", "category": "authz", "split": "dev",
             "expected_verdict": "vulnerable", "file": "app/orders.py",
             "vulnerable_locations": [self.LABEL_LOCATION],
             "diff_shape": self.LABEL_SHAPE},
            {"id": "b", "category": "authz", "split": "eval",
             "expected_verdict": "safe", "file": "app/orders.py",
             "vulnerable_locations": [self.LABEL_LOCATION],
             "diff_shape": self.LABEL_SHAPE},
        ]
        stale_location = {"file": "app/old.py", "old_range": None, "new_range": [900, 905]}
        new_row = _case_row(
            "a", "vulnerable", findings=[_f("authz", "vulnerable")],
            coverage=_coverage([_target_section()]), file="app/old.py",
            locations=[stale_location], diff_shape={"kind": "stale"},
            pin=copy.deepcopy(self.STORED_PIN))
        (out / "a.json").write_text(json.dumps(new_row), encoding="utf-8")
        (out / "b.json").write_text(json.dumps({
            "id": "b", "category": "authz", "expected": "safe",
            "findings": [_f("authz", "safe")], "latency_seconds": 1, "est_tokens": 1,
        }), encoding="utf-8")
        (out / "summary.json").write_text(json.dumps({
            "mode": "lgtm", "model": "m", "generated_at": "then", "git_commit": "abc",
            "split": "all", "outcomes": {"a": "TP", "b": "TN"}, "summary": {},
        }), encoding="utf-8")
        return out, cases

    def test_new_rows_are_rederived_from_current_labels(self, tmp_path):
        out, cases = self._setup(tmp_path)

        evaluate.rescore(out, cases, "lgtm")

        row = json.loads((out / "a.json").read_text())
        assert row["file"] == "app/orders.py"
        assert row["vulnerable_locations"] == [self.LABEL_LOCATION]
        assert row["diff_shape"] == self.LABEL_SHAPE
        assert row["case_label"] == "detected_vulnerability"
        assert row["outcome"] == "TP"
        assert "legacy" not in row

    def test_new_rows_keep_their_stored_pin_and_coverage(self, tmp_path):
        out, cases = self._setup(tmp_path)

        evaluate.rescore(out, cases, "lgtm")

        row = json.loads((out / "a.json").read_text())
        assert row["pin"] == self.STORED_PIN
        assert row["coverage"] == _coverage([_target_section()])

    def test_legacy_rows_are_rescored_without_gaining_graph_fields(self, tmp_path):
        out, cases = self._setup(tmp_path)

        evaluate.rescore(out, cases, "lgtm")

        row = json.loads((out / "b.json").read_text())
        assert row["legacy"] is True
        assert row["case_label"] is None
        assert row["outcome"] == "UNKNOWN"
        assert row["predicted"] == "unknown"
        assert row["correct"] is None
        for key in ("pin", "file", "vulnerable_locations", "diff_shape", "coverage",
                    "target_sections", "coverage_gap", "mode"):
            assert key not in row

    def test_partial_rescore_of_new_format_run_is_still_refused(self, tmp_path):
        out, cases = self._setup(tmp_path)
        before = (out / "a.json").read_bytes()

        with pytest.raises(SystemExit):
            evaluate.rescore(out, cases[:1], "lgtm")

        assert (out / "a.json").read_bytes() == before


def _run_benchmark(tmp_path, monkeypatch, argv):
    (tmp_path / "labels.json").write_text('{"cases": []}', encoding="utf-8")
    summary = MagicMock()
    monkeypatch.setattr(evaluate, "BENCH", tmp_path)
    monkeypatch.setattr(evaluate, "write_summary", summary)
    monkeypatch.setattr("sys.argv", ["evaluate.py", *argv])
    config = LGTMConfig()
    monkeypatch.setattr(evaluate, "LGTMConfig", lambda: config)
    evaluate.main()
    return config, summary


@pytest.mark.parametrize("extra,url", [
    ([], "http://127.0.0.1:11435"),
    (["--ollama-url", "http://127.0.0.1:12000"], "http://127.0.0.1:12000"),
])
def test_benchmark_gpu_model_connection(tmp_path, monkeypatch, extra, url):
    config, summary = _run_benchmark(
        tmp_path, monkeypatch, ["--gpu-model", "qwen3.8-27b", *extra])

    assert config.ollama_model == "qwen3.8:27b"
    assert config.ollama_base_url == url
    assert summary.call_args.args[3] == "qwen3.8:27b"
    assert summary.call_args.args[4]["reasoning"] is False


def test_benchmark_default_records_reasoning_off(tmp_path, monkeypatch):
    _, summary = _run_benchmark(tmp_path, monkeypatch, [])

    assert summary.call_args.args[4]["reasoning"] is False
    assert summary.call_args.args[4]["cases_expected"] == 0


@pytest.mark.parametrize("conflict", [["--gpu-cluster"], ["--model", "x:1"]])
def test_benchmark_gpu_model_conflicts(tmp_path, monkeypatch, conflict):
    with pytest.raises(SystemExit) as exc:
        _run_benchmark(tmp_path, monkeypatch, ["--gpu-model", "qwen3.8-27b", *conflict])

    assert exc.value.code == 2


def _infra_finding(finding_id="authz:1", explanation="Agent execution failed: boom"):
    return {
        "finding_id": finding_id, "category": "authz",
        "verdict": "insufficient_evidence",
        "explanation": explanation,
    }


class TestErrorAccounting:
    @staticmethod
    def _row(cid="a", expected="vulnerable", category="authz", findings=None,
             latency=1.0, tokens=10, **extra):
        if findings is None:
            findings = [_f(category, "vulnerable" if expected == "vulnerable" else "safe")]
        if not evaluate.infra_failure_ids(findings):
            extra.setdefault("coverage", _coverage([_target_section()]))
        return {"id": cid, "category": category, "split": "dev", "expected": expected,
                "findings": findings, "latency_seconds": latency, "est_tokens": tokens,
                **extra}

    def _tp(self, cid="a", **kw):
        return evaluate.score_case(self._row(cid, "vulnerable", **kw))

    def _tn(self, cid="b", **kw):
        return evaluate.score_case(self._row(cid, "safe", **kw))

    def test_mark_error_sets_error_representation(self):
        row = self._row(findings=[_f("authz", "vulnerable")])
        marked = evaluate.mark_error(row, "boom")
        assert marked["predicted"] == "error"
        assert marked["predicted_grounded"] == "error"
        assert marked["outcome"] == "ERROR"
        assert marked["outcome_grounded"] == "ERROR"
        assert marked["correct"] is None
        assert marked["error"] == "boom"
        assert marked["findings"] == [_f("authz", "vulnerable")]

    def test_score_case_flags_agent_failure_as_error(self):
        row = evaluate.score_case(self._row(
            findings=[_infra_finding("authz:1"), _f("authz", "safe")]))
        assert row["outcome"] == "ERROR"
        assert row["infra_failures"] == 1
        assert row["infra_failure_ids"] == ["authz:1"]

    @pytest.mark.parametrize("finding_id,explanation", [
        ("sqli:1", "LLM call failed: x"),
        ("plain:2", "Agent did not produce parsable structured output."),
        ("plain:unparsable", "no usable assessment"),
    ])
    def test_score_case_flags_llm_call_failed_and_plain_unparsable(
            self, finding_id, explanation):
        row = evaluate.score_case(self._row(
            findings=[_infra_finding(finding_id, explanation)]))
        assert row["outcome"] == "ERROR"
        assert row["outcome_grounded"] == "ERROR"
        assert row["infra_failures"] == 1
        assert row["infra_failure_ids"] == [finding_id]

    def test_total_review_outage_is_an_error_not_a_true_negative(self):
        outage = _coverage(
            [_section("fallback:a", [_hunk(ROW_FILE, 10, 5)], "failed"),
             _section("fallback:b", [_hunk(ROW_FILE, 200, 4)], "failed")],
            investigator_status="failed", investigator_error="[WinError 10061] refused",
            planner="fallback")
        row = evaluate.score_case(_case_row("a", "safe", findings=[], coverage=outage))
        assert row["case_label"] == "scan_failure"
        assert row["outcome"] == "ERROR"
        assert row["outcome_grounded"] == "ERROR"
        assert row["correct"] is None
        assert evaluate.result_is_error(row)

    def test_partial_review_outage_with_no_findings_stays_a_true_negative(self):
        partial = _coverage(
            [_section("done", [_hunk(ROW_FILE, 10, 5)]),
             _section("fallback:b", [_hunk(ROW_FILE, 200, 4)], "failed")])
        row = evaluate.score_case(_case_row("a", "safe", findings=[], coverage=partial))
        assert row["outcome"] == "TN"
        assert not evaluate.result_is_error(row)

    def test_score_case_is_idempotent_on_errors(self):
        infra = evaluate.score_case(self._row(findings=[_infra_finding()]))
        snapshot = copy.deepcopy(infra)
        assert evaluate.score_case(infra) == snapshot

        crashed = evaluate.mark_error(self._row(findings=[]), "boom")
        again = evaluate.score_case(copy.deepcopy(crashed))
        assert again["outcome"] == "ERROR"
        assert again["error"] == "boom"
        assert again["infra_failures"] == 0
        assert again["infra_failure_ids"] == []
        assert evaluate.score_case(copy.deepcopy(again)) == again

    def test_score_case_leaves_clean_rows_unchanged(self):
        row = self._tp()
        assert row["infra_failures"] == 0
        assert row["infra_failure_ids"] == []
        assert row["outcome"] == "TP"
        assert row["predicted"] == "vulnerable"
        assert row["correct"] is True
        assert not row.get("error")

    def test_summarize_excludes_errors_from_counts(self):
        rows = [
            self._tp("a", latency=10.0, tokens=100),
            self._tn("b", latency=20.0, tokens=300),
            evaluate.mark_error(self._row("c", "vulnerable", findings=[],
                                          latency=0.0, tokens=0), "boom"),
        ]
        summary = evaluate.summarize(rows)
        overall = summary["overall"]
        assert (overall["tp"], overall["fp"], overall["fn"], overall["tn"]) == (1, 0, 0, 1)
        assert overall["cases"] == 3
        assert overall["scored"] == 2
        assert overall["errors"] == 1
        assert overall["error_rate"] == pytest.approx(1 / 3, abs=0.001)
        assert overall["recall"] == 1.0
        assert overall["accuracy"] == 1.0
        assert summary["scored"] == 2
        assert summary["errors"] == 1
        assert summary["error_rate"] == pytest.approx(1 / 3, abs=0.001)
        assert summary["error_cases"] == [{"id": "c", "error": "boom"}]
        assert summary["median_latency_seconds"] == 15.0
        assert summary["median_est_tokens_per_pr"] == 200

    def test_summarize_all_errors_gives_null_metrics(self):
        rows = [
            evaluate.mark_error(self._row("a", "vulnerable", findings=[]), "boom"),
            evaluate.score_case(self._row(
                "b", "safe", category="sqli", findings=[_infra_finding("sqli:1")])),
        ]
        summary = evaluate.summarize(rows)
        overall = summary["overall"]
        for key in ("precision", "recall", "f1", "false_positive_rate_on_safe", "accuracy"):
            assert overall[key] is None, key
        assert overall["scored"] == 0
        assert overall["errors"] == 2
        assert overall["error_rate"] == 1.0
        for key in ("off_category_alarm_rate", "evidence_grounding_rate", "possible_rate",
                    "insufficient_evidence_rate", "median_latency_seconds",
                    "median_est_tokens_per_pr"):
            assert summary[key] is None, key
        assert summary["off_category_alarms"] == []
        assert summary["error_rate"] == 1.0
        assert summary["per_category"]["authz"]["errors"] == 1
        assert summary["per_category"]["authz"]["scored"] == 0
        assert summary["per_category"]["authz"]["recall"] is None
        assert summary["per_category"]["sqli"]["errors"] == 1
        assert summary["grounded_only"]["overall"]["accuracy"] is None

        empty = evaluate.summarize([])
        assert empty["overall"]["error_rate"] is None
        assert empty["error_rate"] is None
        assert empty["errors"] == 0
        assert empty["error_cases"] == []

    def test_legacy_row_with_infra_marker_and_no_infra_key_is_error(self):
        legacy = {
            "id": "b", "category": "authz", "split": "dev", "expected": "safe",
            "findings": [_f("authz", "safe"), _infra_finding("authz:9")],
            "latency_seconds": 1.0, "est_tokens": 10,
            "outcome": "TN", "correct": True,
        }
        assert legacy["outcome"] == "TN"
        summary = evaluate.summarize([self._tp("a"), legacy])
        assert summary["overall"]["tn"] == 0
        assert summary["overall"]["scored"] == 1
        assert summary["overall"]["errors"] == 1
        assert summary["error_cases"][0]["id"] == "b"

    def test_legacy_error_row_with_tn_outcome_is_excluded(self):
        legacy = {"id": "b", "category": "authz", "split": "dev", "expected": "safe",
                  "findings": [], "latency_seconds": 1.0, "est_tokens": 10,
                  "predicted": "error", "outcome": "TN", "correct": True}
        assert legacy["outcome"] == "TN"
        summary = evaluate.summarize([self._tp("a"), legacy])
        assert summary["overall"]["tn"] == 0
        assert summary["overall"]["accuracy"] == 1.0
        assert summary["overall"]["errors"] == 1

    def test_grounded_only_excludes_errors(self):
        legacy = {"id": "b", "category": "authz", "split": "dev", "expected": "vulnerable",
                  "findings": [], "latency_seconds": 1.0, "est_tokens": 10,
                  "predicted": "error", "outcome": "FN", "outcome_grounded": "FN",
                  "correct": False}
        assert legacy["outcome_grounded"] == "FN"
        flagged = [dict(_f("authz", "vulnerable"), supported=True)]
        summary = evaluate.summarize([self._tp("a", findings=flagged), legacy])
        grounded = summary["grounded_only"]
        assert grounded["overall"]["fn"] == 0
        assert grounded["overall"]["scored"] == 1
        assert grounded["overall"]["errors"] == 1
        assert grounded["per_category"]["authz"]["fn"] == 0
        assert grounded["per_split"]["dev"]["errors"] == 1

    def test_summary_outcomes_marks_errors(self, tmp_path):
        legacy = {"id": "c", "category": "authz", "split": "dev", "expected": "vulnerable",
                  "findings": [], "latency_seconds": 1.0, "est_tokens": 10,
                  "predicted": "error", "outcome": "FN", "correct": False}
        evaluate.write_summary(tmp_path, [self._tp("a"), legacy], "lgtm", "m")
        saved = json.loads((tmp_path / "summary.json").read_text())
        assert saved["outcomes"] == {"a": "TP", "c": "ERROR"}

    def test_error_text_is_truncated_in_error_cases(self):
        row = evaluate.mark_error(self._row("a", findings=[]), "x" * 500)
        summary = evaluate.summarize([row])
        assert summary["error_cases"] == [{"id": "a", "error": "x" * 300}]


def _pin_for(model, mode, static_facts, base="", pr=""):
    return {
        "model": model, "code_sha": "c" * 40, "code_dirty": False,
        "base_sha": base, "pr_sha": pr,
        "sampling": {"llm_temperature": 0.0, "reasoning": False},
        "budgets": {"max_tool_calls": 8},
        "flags": {"mode": mode, "static_facts": static_facts},
    }


@pytest.fixture(autouse=True)
def pin(monkeypatch):
    """Deterministic run_pin derived from the config it receives; no git runs.

    Returns the list of (config, repo_root, refs) calls.
    """
    calls = []

    def fake_run_pin(config, repo_root, refs, exclude=None):
        calls.append((config, Path(repo_root), dict(refs)))
        return _pin_for(config.ollama_model, config.mode, config.static_facts,
                        refs.get("base", ""), refs.get("pr", ""))

    monkeypatch.setattr(evaluate, "run_pin", fake_run_pin)
    return calls


_DROP = object()


class TestResume:
    EXPECTED = {"a": "vulnerable", "b": "safe", "c": "vulnerable"}

    @staticmethod
    def _row(cid, expected, findings=None):
        verdict = "vulnerable" if expected == "vulnerable" else "safe"
        return _case_row(
            cid, expected, coverage=_coverage([_target_section()]),
            findings=[_f("authz", verdict)] if findings is None else findings)

    def _setup(self, tmp_path, monkeypatch, raises=()):
        bench = tmp_path / "bench"
        bench.mkdir()
        (bench / "labels.json").write_text(json.dumps({"cases": [
            {"id": cid, "category": "authz", "expected_verdict": expected,
             "split": "dev", "patch_file": f"patches/{cid}.patch",
             **({"file": "app/orders.py", "vulnerable_locations": [LOCATION],
                 "diff_shape": "single_hunk"} if cid in raises else {})}
            for cid, expected in self.EXPECTED.items()
        ]}), encoding="utf-8")
        out = tmp_path / "out"
        out.mkdir()
        ran: list[str] = []

        def fake_evaluate_case(case, config):
            ran.append(case["id"])
            if case["id"] in raises:
                raise RuntimeError("boom")
            return evaluate.score_case(self._row(case["id"], case["expected_verdict"]))

        monkeypatch.setattr(evaluate, "BENCH", bench)
        monkeypatch.setattr(evaluate, "evaluate_case", fake_evaluate_case)
        return out, ran

    def _main(self, monkeypatch, out, *args):
        monkeypatch.setattr("sys.argv", ["evaluate.py", "--output", str(out), *args])
        evaluate.main()

    def _write(self, out, row):
        path = out / f"{row['id']}.json"
        path.write_text(json.dumps(row, indent=2), encoding="utf-8")
        return path

    def _done(self, cid):
        return evaluate.score_case(self._row(cid, self.EXPECTED[cid]))

    def _summary(self, out):
        return json.loads((out / "summary.json").read_text(encoding="utf-8"))

    def test_resume_skips_completed_and_reruns_errors(self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch)
        done = self._write(out, self._done("a"))
        self._write(out, evaluate.mark_error(self._row("b", "safe"), "boom"))
        before = done.read_bytes()

        self._main(monkeypatch, out, "--resume")

        assert sorted(ran) == ["b", "c"]
        assert done.read_bytes() == before
        assert json.loads((out / "b.json").read_text())["outcome"] == "TN"
        assert self._summary(out)["outcomes"] == {"a": "TP", "b": "TN", "c": "TP"}

    def test_without_resume_runs_every_case(self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch)
        stale = self._done("a")
        stale["latency_seconds"] = 99.0
        self._write(out, stale)
        self._write(out, self._done("b"))

        self._main(monkeypatch, out)

        assert sorted(ran) == ["a", "b", "c"]
        assert json.loads((out / "a.json").read_text())["latency_seconds"] == 1.0

    def test_resume_rebuilds_summary_from_all_case_jsons(self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch)
        self._write(out, self._done("a"))
        self._write(out, self._done("b"))

        self._main(monkeypatch, out, "--resume")

        assert ran == ["c"]
        summary = self._summary(out)
        assert summary["outcomes"] == {"a": "TP", "b": "TN", "c": "TP"}
        assert summary["summary"]["overall"]["cases"] == 3
        assert summary["summary"]["overall"]["tp"] == 2
        assert summary["summary"]["overall"]["tn"] == 1

    def test_exception_in_a_case_is_recorded_as_error(self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch, raises={"a"})

        self._main(monkeypatch, out)

        row = json.loads((out / "a.json").read_text())
        assert row["outcome"] == "ERROR"
        assert row["predicted"] == "error"
        assert "boom" in row["error"]
        summary = self._summary(out)
        assert summary["outcomes"]["a"] == "ERROR"
        assert summary["summary"]["errors"] == 1
        assert summary["summary"]["overall"]["fn"] == 0

    def test_resume_conflicts_with_rescore(self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch)
        with pytest.raises(SystemExit) as exc:
            self._main(monkeypatch, out, "--resume", "--rescore")
        assert exc.value.code == 2
        assert ran == []

    def test_resume_reruns_legacy_row_with_infra_marker(self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch)
        legacy = self._done("a")
        legacy["findings"].append(_infra_finding("authz:9"))
        legacy.pop("infra_failures", None)
        legacy.pop("infra_failure_ids", None)
        legacy.pop("coverage")
        legacy["outcome"] = "TN"
        self._write(out, legacy)
        self._write(out, self._done("b"))
        self._write(out, self._done("c"))

        self._main(monkeypatch, out, "--resume")

        assert ran == ["a"]

    @pytest.mark.parametrize("stored", [
        {"model": "other:1b", "reasoning": None},
        {"model": "m:1", "reasoning": True},
    ])
    def test_resume_refuses_different_model(self, tmp_path, monkeypatch, capsys, stored):
        out, ran = self._setup(tmp_path, monkeypatch)
        manifest = out / "run.json"
        manifest.write_text(json.dumps({
            "ollama_base_url": "http://localhost:11434", "mode": "lgtm", **stored}),
            encoding="utf-8")
        a = self._write(out, self._done("a"))
        b = self._write(out, evaluate.mark_error(self._row("b", "safe"), "boom"))
        before = (a.read_bytes(), b.read_bytes(), manifest.read_bytes())

        with pytest.raises(SystemExit) as exc:
            self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert exc.value.code == 2
        assert "different model or reasoning setting" in capsys.readouterr().err
        assert ran == []
        assert (a.read_bytes(), b.read_bytes(), manifest.read_bytes()) == before
        assert not (out / "c.json").exists()

    def test_run_json_written_with_model_and_reasoning(self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch)

        self._main(monkeypatch, out, "--model", "m:1",
                   "--ollama-url", "http://127.0.0.1:11435")

        manifest = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert set(manifest) == {"model", "ollama_base_url", "reasoning", "mode", "pin"}
        assert manifest["model"] == "m:1"
        assert manifest["ollama_base_url"] == "http://127.0.0.1:11435"
        assert manifest["reasoning"] is False
        assert manifest["mode"] == "lgtm"

    PIN = _pin_for("m:1", "lgtm", False)

    def _manifest(self, out, **over):
        manifest = {
            "model": "m:1", "ollama_base_url": "http://localhost:11434",
            "reasoning": False, "mode": "lgtm", "pin": copy.deepcopy(self.PIN),
        }
        manifest.update(over)
        manifest = {k: v for k, v in manifest.items() if v is not _DROP}
        path = out / "run.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def _new_row(self, cid, **over):
        verdict = "vulnerable" if self.EXPECTED[cid] == "vulnerable" else "safe"
        return evaluate.score_case(_case_row(
            cid, self.EXPECTED[cid], coverage=_coverage([_target_section()]),
            findings=[_f("authz", verdict)], **over))

    def test_run_json_pin_is_computed_from_the_cli_adjusted_config(
            self, tmp_path, monkeypatch, pin):
        out, ran = self._setup(tmp_path, monkeypatch)

        self._main(monkeypatch, out, "--model", "m:1", "--static-facts",
                   "--mode", "llm-only")

        manifest = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert manifest["pin"] == _pin_for("m:1", "llm-only", True)
        assert pin and all(
            root == evaluate.REPO_ROOT and not refs.get("base") and not refs.get("pr")
            for _, root, refs in pin)

    def test_resume_refuses_when_only_an_experiment_flag_differs(
            self, tmp_path, monkeypatch, capsys):
        out, ran = self._setup(tmp_path, monkeypatch)
        self._manifest(out)

        with pytest.raises(SystemExit) as exc:
            self._main(monkeypatch, out, "--resume", "--model", "m:1", "--static-facts")

        assert exc.value.code == 2
        assert "(differs in: flags)" in capsys.readouterr().err
        assert ran == []

    def test_resume_pin_difference_ignores_base_and_pr_sha_in_the_message(
            self, tmp_path, monkeypatch, capsys):
        out, ran = self._setup(tmp_path, monkeypatch)
        self._manifest(out, pin={**self.PIN, "code_sha": "d" * 40,
                                 "base_sha": "a" * 40, "pr_sha": "b" * 40})

        with pytest.raises(SystemExit):
            self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert "(differs in: code_sha)" in capsys.readouterr().err

    def test_new_run_overwrites_a_pinless_manifest_with_a_pinned_one(
            self, tmp_path, monkeypatch):
        out, ran = self._setup(tmp_path, monkeypatch)
        self._manifest(out, pin=_DROP)

        self._main(monkeypatch, out, "--model", "m:1")

        manifest = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert manifest["pin"] == self.PIN

    def test_resume_refuses_manifest_without_pin(
            self, tmp_path, monkeypatch, capsys, pin):
        out, ran = self._setup(tmp_path, monkeypatch)
        manifest = self._manifest(out, pin=_DROP)
        a = self._write(out, self._new_row("a"))
        before = (a.read_bytes(), manifest.read_bytes())

        with pytest.raises(SystemExit) as exc:
            self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert exc.value.code == 2
        assert (f"--resume: {out} has no run pin; start a new output directory"
                in capsys.readouterr().err)
        assert ran == []
        assert (a.read_bytes(), manifest.read_bytes()) == before
        assert not (out / "b.json").exists() and not (out / "summary.json").exists()

    @pytest.mark.parametrize("changes,differs", [
        ({"code_sha": "d" * 40}, "code_sha"),
        ({"code_dirty": True}, "code_dirty"),
        ({"flags": {"mode": "lgtm", "static_facts": True}}, "flags"),
        ({"budgets": {"max_tool_calls": 9}}, "budgets"),
        ({"sampling": {"llm_temperature": 0.7, "reasoning": False}}, "sampling"),
        ({"code_sha": "d" * 40, "budgets": {}, "flags": {}}, "budgets, code_sha, flags"),
    ])
    def test_resume_refuses_different_pin(
            self, tmp_path, monkeypatch, capsys, pin, changes, differs):
        out, ran = self._setup(tmp_path, monkeypatch)
        stored = {**copy.deepcopy(self.PIN), **changes}
        manifest = self._manifest(out, pin=stored)
        a = self._write(out, self._new_row("a"))
        before = (a.read_bytes(), manifest.read_bytes())

        with pytest.raises(SystemExit) as exc:
            self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert exc.value.code == 2
        assert (f"--resume: {out} was produced with a different run pin "
                f"(differs in: {differs})" in capsys.readouterr().err)
        assert ran == []
        assert (a.read_bytes(), manifest.read_bytes()) == before
        assert not (out / "b.json").exists()

    def test_resume_checks_model_before_the_pin(
            self, tmp_path, monkeypatch, capsys, pin):
        out, ran = self._setup(tmp_path, monkeypatch)
        self._manifest(out, model="other:1b", pin={**self.PIN, "code_sha": "d" * 40})

        with pytest.raises(SystemExit) as exc:
            self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "different model or reasoning setting" in err
        assert "run pin" not in err

    def test_resume_accepts_pin_differing_only_in_base_and_pr_sha(
            self, tmp_path, monkeypatch, pin):
        out, ran = self._setup(tmp_path, monkeypatch)
        stored = {**copy.deepcopy(self.PIN), "base_sha": "a" * 40, "pr_sha": "b" * 40}
        self._manifest(out, pin=stored)
        self._write(out, self._new_row("a"))

        self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert sorted(ran) == ["b", "c"]

    @pytest.fixture
    def real_pin_repo(self, tmp_path, monkeypatch):
        repo = tmp_path / "repo"
        repo.mkdir()
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath="]
        (repo / "tracked.txt").write_text("one\n", encoding="utf-8")
        for args in (["init", "-q"], ["add", "tracked.txt"],
                     ["commit", "-q", "-m", "init"]):
            subprocess.run([*git, *args], cwd=repo, check=True, capture_output=True)
        monkeypatch.setattr(evaluate, "run_pin", real_run_pin)
        monkeypatch.setattr(evaluate, "REPO_ROOT", repo)
        return repo

    def test_resume_accepts_a_run_written_into_an_untracked_repo_directory(
            self, tmp_path, monkeypatch, real_pin_repo):
        _, ran = self._setup(tmp_path, monkeypatch)
        out = real_pin_repo / "runs" / "dev-run"

        self._main(monkeypatch, out)
        assert sorted(ran) == ["a", "b", "c"]
        stored = json.loads((out / "run.json").read_text(encoding="utf-8"))["pin"]
        (out / "c.json").unlink()
        ran.clear()

        self._main(monkeypatch, out, "--resume")

        assert ran == ["c"]
        assert stored["code_dirty"] is False

    def test_resume_still_refuses_a_tracked_file_edit_between_invocations(
            self, tmp_path, monkeypatch, capsys, real_pin_repo):
        _, ran = self._setup(tmp_path, monkeypatch)
        out = real_pin_repo / "runs" / "dev-run"
        self._main(monkeypatch, out)
        (out / "c.json").unlink()
        ran.clear()
        (real_pin_repo / "tracked.txt").write_text("two\n", encoding="utf-8")

        with pytest.raises(SystemExit) as exc:
            self._main(monkeypatch, out, "--resume")

        assert exc.value.code == 2
        assert "(differs in: code_dirty)" in capsys.readouterr().err
        assert ran == []
        assert not (out / "c.json").exists()

    def test_resume_reruns_scan_failure_rows_and_keeps_scored_new_rows(
            self, tmp_path, monkeypatch, pin):
        out, ran = self._setup(tmp_path, monkeypatch)
        self._manifest(out)
        done = self._write(out, self._new_row("a"))
        failed = evaluate.score_case(_case_row(
            "b", "safe", findings=[_f("authz", "safe")], coverage=None))
        assert failed["case_label"] == "scan_failure"
        self._write(out, failed)
        before = done.read_bytes()

        self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert sorted(ran) == ["b", "c"]
        assert done.read_bytes() == before

    @pytest.mark.parametrize("failure", [
        "target_section_failed", "other_section_failed", "investigator_failed"])
    def test_resume_reruns_a_scored_row_whose_coverage_shows_a_failure(
            self, tmp_path, monkeypatch, pin, failure):
        coverage = {
            "target_section_failed": _failed_target_coverage,
            "other_section_failed": lambda: _coverage([
                _target_section(),
                _section("other", [_hunk(ROW_FILE, 200, 4)], "failed")]),
            "investigator_failed": lambda: _coverage(
                [_target_section()], investigator_status="failed",
                investigator_error="connection reset"),
        }[failure]()
        out, ran = self._setup(tmp_path, monkeypatch)
        self._manifest(out)
        failed = evaluate.score_case(_case_row(
            "a", "vulnerable", findings=[_f("authz", "vulnerable")],
            coverage=coverage))
        assert failed["case_label"] != "scan_failure"
        assert not evaluate.result_is_error(failed)
        self._write(out, failed)
        kept = self._write(out, self._new_row("b"))
        before = kept.read_bytes()

        self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert sorted(ran) == ["a", "c"]
        assert kept.read_bytes() == before

    def test_resume_keeps_a_row_whose_coverage_has_no_failure(
            self, tmp_path, monkeypatch, pin):
        out, ran = self._setup(tmp_path, monkeypatch)
        self._manifest(out)
        for cid in ("a", "b", "c"):
            self._write(out, self._new_row(cid))

        self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert ran == []

    def test_fresh_harness_exception_is_a_new_format_scan_failure_that_resume_reruns(
            self, tmp_path, monkeypatch, pin):
        out, ran = self._setup(tmp_path, monkeypatch, raises={"a"})

        self._main(monkeypatch, out, "--model", "m:1")

        row = json.loads((out / "a.json").read_text(encoding="utf-8"))
        assert row["outcome"] == "ERROR" and "boom" in row["error"]
        manifest = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert row["pin"] == manifest["pin"] == self.PIN
        assert "legacy" not in row
        assert row["case_label"] == "scan_failure"
        assert row["mode"] == "lgtm"
        assert row["file"] == "app/orders.py"
        assert row["vulnerable_locations"] == [LOCATION]
        assert row["diff_shape"] == "single_hunk"
        assert "coverage" in row
        ran.clear()

        self._main(monkeypatch, out, "--resume", "--model", "m:1")

        assert ran == ["a"]

    @pytest.mark.parametrize("label,expected", [
        ("detected_vulnerability", "vulnerable"),
        ("explicit_safe", "safe"),
    ])
    def test_console_line_prints_the_case_label(
            self, tmp_path, monkeypatch, capsys, pin, label, expected):
        out, ran = self._setup(tmp_path, monkeypatch)
        row = evaluate.score_case(_case_row("a", expected, **_scenario(label)))
        assert row["case_label"] == label
        monkeypatch.setattr(evaluate, "evaluate_case", lambda case, config: row)
        (tmp_path / "bench" / "labels.json").write_text(json.dumps({"cases": [
            {"id": "a", "category": "authz", "expected_verdict": expected,
             "split": "dev", "patch_file": "patches/a.patch"}]}), encoding="utf-8")

        self._main(monkeypatch, out)

        lines = capsys.readouterr().out.splitlines()
        [progress] = [line for line in lines if line.startswith("[1/1] a")]
        assert label in progress

    def test_is_done_treats_unreadable_json_as_pending(self, tmp_path):
        corrupt = tmp_path / "corrupt.json"
        corrupt.write_text("{not json", encoding="utf-8")
        empty = tmp_path / "empty_object.json"
        empty.write_text("{}", encoding="utf-8")
        assert evaluate.is_done(corrupt) is False
        assert evaluate.is_done(empty) is False
        assert evaluate.is_done(tmp_path / "missing.json") is False


class _ScriptedPlainLLM:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def bind_tools(self, tools):
        raise AssertionError("llm-only baseline must not use tools")

    def invoke(self, messages):
        self.calls += 1
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        msg = MagicMock()
        msg.content = item
        msg.tool_calls = []
        return msg


_DIFF = """diff --git a/app/routes/orders.py b/app/routes/orders.py
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


class TestPlainReviewerResilience:
    def _review(self, llm):
        reviewer = PlainLLMReviewer(LGTMConfig(), llm=llm)
        return reviewer.review(parse_unified_diff(_DIFF))

    def test_retries_llm_call_with_backoff(self, sleeps):
        llm = _ScriptedPlainLLM([RuntimeError("down"), ASSESSMENTS])
        findings = self._review(llm)
        assert sleeps == [2.0]
        assert len(findings) == 2
        assert llm.calls == 2
        assert [f.category for f in findings] == ["sqli", "authz"]
        assert [f.verdict for f in findings] == ["vulnerable", "safe"]

    def test_failure_after_retries_reports_llm_call_failed(self, sleeps):
        llm = _ScriptedPlainLLM([RuntimeError("down")] * 4)
        findings = self._review(llm)
        assert sorted(f.category for f in findings) == sorted(DEFAULT_CWE)
        assert all(f.explanation.startswith("LLM call failed") for f in findings)
        assert llm.calls == 4
        assert sleeps == [2.0, 4.0, 8.0]
        assert all(f.verdict == "insufficient_evidence" for f in findings)
        assert {f.category: f.cwe_id for f in findings} == DEFAULT_CWE

    def test_unparsable_answer_is_reasked(self):
        llm = _ScriptedPlainLLM(["I think it is fine.", ASSESSMENTS])
        findings = self._review(llm)
        assert llm.calls == 2
        assert [f.category for f in findings] == ["sqli", "authz"]
        assert [f.verdict for f in findings] == ["vulnerable", "safe"]
        assert all(f.finding_id != "plain:unparsable" for f in findings)

    def test_gives_up_after_three_reasks(self):
        llm = _ScriptedPlainLLM(["I think it is fine."] * 4)
        findings = self._review(llm)
        assert llm.calls == 4
        assert [f.finding_id for f in findings] == ["plain:unparsable"]
        assert findings[0].verdict == "insufficient_evidence"


def test_llm_only_baseline_leaves_graph_fields_empty(git_repo):
    llm = _NoToolsLLM(ASSESSMENTS)
    result = ReviewPipeline(git_repo, LGTMConfig(mode="llm-only"), llm=llm).run("main", "pr")
    assert result.findings
    assert all(f.pr_graph_ok is None for f in result.findings)
    assert result.meta.graph_state is None
    assert result.meta.graph_index_seconds is None
    assert result.meta.base_sha == ""
    assert result.meta.pr_sha == ""


def _hunk(file, new_start=10, new_count=5, hunk_id=None, old_start=None):
    old_start = new_start if old_start is None else old_start
    return {
        "hunk_id": hunk_id or f"{file}:{new_start}", "file": file,
        "old_start": old_start, "old_count": new_count,
        "new_start": new_start, "new_count": new_count, "change": "modified",
    }


def _section(section_id, hunks, status="completed"):
    return {
        "section_id": section_id, "origin": "planner", "title": section_id,
        "files": sorted({h["file"] for h in hunks}), "split": False,
        "partial_hunk": False, "hunks": hunks, "status": status,
        "supported": [], "finding_ids": [], "error": None,
    }


def _coverage(sections, **over):
    completed = sum(1 for s in sections if s["status"] == "completed")
    failed = sum(1 for s in sections if s["status"] not in ("completed", None))
    hunks = sum(len(s["hunks"]) for s in sections)
    base = {
        "planner": "deterministic", "investigator_status": "ok",
        "investigator_error": None, "investigator_input": "diff",
        "investigator_tool_calls": 0, "files_total": 1, "files_in_scope": 1,
        "hunks_total": hunks, "hunks_assigned": hunks, "hunks_leftover": 0,
        "hunks_reviewed": sum(
            len(s["hunks"]) for s in sections if s["status"] == "completed"),
        "sections_scheduled": len(sections), "sections_completed": completed,
        "sections_failed": failed, "sections_coalesced": 0,
        "complete": failed == 0 and completed == len(sections),
        "exclusions": [], "invalid_refs": [], "sections": sections,
    }
    base.update(over)
    return base


ROW_FILE = "app/orders.py"
LOCATION = {"file": ROW_FILE, "old_range": None, "new_range": [10, 14]}


JUDGED_MODES = ("lgtm",)


def _as_judged(finding):
    """Judged modes carry `supported`, never the verdict; only "vulnerable" stands for supported."""
    if "verdict" not in finding:
        return finding
    judged = {k: v for k, v in finding.items() if k != "verdict"}
    supported = finding["verdict"] == "vulnerable"
    return {**judged, "supported": supported, "judged": True, "provenance_confidence": 0.9,
            "kev_verdict": "real" if supported else "not_real", "kev_severity": "medium"}


def _case_row(cid="c", expected="vulnerable", findings=(), coverage="absent",
              mode="lgtm", locations="default", file=ROW_FILE, split="dev",
              raw=False, **extra):
    """`locations=None` omits the vulnerable_locations key; `raw` keeps verdict-form findings in any mode."""
    findings = copy.deepcopy(list(findings))
    if mode in JUDGED_MODES and not raw:
        findings = [_as_judged(f) for f in findings]
    row = {
        "id": cid, "category": "authz", "split": split, "expected": expected,
        "findings": findings, "latency_seconds": 1.0,
        "est_tokens": 10, "mode": mode, "file": file,
        "pin": {"code_sha": "abc"}, **extra,
    }
    if locations == "default":
        locations = [LOCATION]
    if locations is not None:
        row["vulnerable_locations"] = copy.deepcopy(list(locations))
    if coverage != "absent":
        row["coverage"] = copy.deepcopy(coverage)
    return row


def _target_section(status="completed"):
    return _section("s-target", [_hunk(ROW_FILE, 10, 5)], status)


def _failed_target_coverage():
    return _coverage([
        _target_section("failed"),
        _section("done", [_hunk(ROW_FILE, 200, 4)]),
    ])


def _scenario(label):
    """Coverage-mode row inputs whose derived label is `label`."""
    complete = _coverage([_target_section()])
    return {
        "detected_vulnerability": dict(
            findings=[_f("authz", "vulnerable")], coverage=complete),
        "possible_vulnerability": dict(
            findings=[_f("authz", "possible")], mode="llm-only"),
        "insufficient_evidence": dict(
            findings=[_f("authz", "insufficient_evidence")], mode="llm-only"),
        "explicit_safe": dict(findings=[_f("authz", "safe")], coverage=complete),
        "missing_review": dict(
            findings=[_f("authz", "safe")],
            coverage=_failed_target_coverage()),
        "no_candidate": dict(
            findings=[_f("authz", "safe")],
            coverage=_coverage([_section("other", [_hunk("app/other.py")])])),
        "scan_failure": dict(findings=[_f("authz", "vulnerable")], coverage=None),
    }[label]


def _label(**kw):
    return evaluate.score_case(_case_row(**kw))["case_label"]


COVERAGE_MODES = ["lgtm"]
BASELINE_ONLY_LABELS = ["possible_vulnerability", "insufficient_evidence"]
ALL_LABELS = [
    "detected_vulnerability", "explicit_safe", "missing_review", "no_candidate",
    "scan_failure",
]


class TestCaseLabels:
    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    @pytest.mark.parametrize("label", ALL_LABELS)
    def test_each_label_is_derived_from_coverage_and_findings(self, label, mode):
        row = evaluate.score_case(_case_row(mode=mode, **_scenario(label)))
        assert row["case_label"] == label
        assert row["case_label_grounded"] == label

    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    @pytest.mark.parametrize("label,predicted", [
        ("detected_vulnerability", "vulnerable"),
        ("explicit_safe", "safe"),
        # predicted comes from the findings (round-2 rule); the label is a
        # diagnostic next to it, so a failed or missing review with a safe
        # finding predicts "safe" and a scan failure with a vulnerable one
        # still predicts "vulnerable".
        ("missing_review", "safe"),
        ("no_candidate", "safe"),
        ("scan_failure", "vulnerable"),
    ])
    def test_predicted_follows_the_label(self, label, predicted, mode):
        row = evaluate.score_case(_case_row(mode=mode, **_scenario(label)))
        assert row["predicted"] == predicted

    def test_new_format_rows_are_not_legacy(self):
        row = evaluate.score_case(_case_row(**_scenario("explicit_safe")))
        assert not row.get("legacy")

    def test_scan_failure_when_sections_scheduled_but_none_completed(self):
        cov = _coverage([_target_section("failed")], sections_completed=0)
        assert _label(findings=[_f("authz", "vulnerable")], coverage=cov) == "scan_failure"

    def test_confirmed_zero_scheduled_sections_is_error_not_a_clean_negative(self):
        cov = _coverage([], sections_scheduled=0, sections_completed=0)
        row = evaluate.score_case(_case_row(expected="safe", findings=[], coverage=cov))

        assert row["outcome"] == "ERROR"
        assert row["error"] == "review failed: no section completed"


    def test_scan_failure_outranks_no_candidate_when_no_section_touches_the_target(self):
        cov = _coverage([_section("other", [_hunk("app/other.py")], "failed")])
        assert _label(findings=[_f("authz", "safe")], coverage=cov) == "scan_failure"

    def test_scan_failure_when_investigator_errored_with_nothing_scheduled(self):
        cov = _coverage([], investigator_error="boom", investigator_status="failed")
        assert _label(findings=[], coverage=cov) == "scan_failure"

    def test_investigator_error_with_completed_sections_is_not_scan_failure(self):
        cov = _coverage([_target_section()], investigator_error="boom")
        assert _label(findings=[_f("authz", "safe")], coverage=cov) == "explicit_safe"

    def test_verdict_in_a_file_outside_the_target_is_not_a_detection(self):
        elsewhere = dict(_f("authz", "vulnerable"), file="app/other.py")
        cov = _coverage([_target_section()])
        assert _label(findings=[elsewhere], coverage=cov) == "explicit_safe"

    def test_verdict_in_the_target_file_is_a_detection(self):
        here = dict(_f("authz", "vulnerable"), file=ROW_FILE)
        cov = _coverage([_target_section()])
        assert _label(findings=[here], coverage=cov) == "detected_vulnerability"

    def test_sast_triage_crash_is_an_error_even_with_authz_coverage(self):
        crash = dict(
            _f("sast", "insufficient_evidence"),
            finding_id="sast:1", explanation="Agent execution failed: timeout",
        )
        row = evaluate.score_case(_case_row(
            findings=[crash], coverage=_coverage([_target_section()])))
        assert evaluate.result_is_error(row)
        assert row["infra_failure_ids"] == ["sast:1"]

    def test_nothing_scheduled_and_no_error_is_no_candidate(self):
        completed_elsewhere = _coverage([
            _section("other", [_hunk("app/other.py")])])
        assert _label(findings=[_f("authz", "safe")], coverage=completed_elsewhere) == "no_candidate"

    def test_no_candidate_outranks_a_vulnerable_finding(self):
        cov = _coverage([_section("other", [_hunk("app/other.py")])])
        assert _label(findings=[_f("authz", "vulnerable")], coverage=cov) == "no_candidate"

    def test_row_file_counts_as_a_target_file(self):
        elsewhere = {"file": "app/models.py", "old_range": None, "new_range": [1, 3]}
        cov = _coverage([_target_section()])
        assert _label(findings=[_f("authz", "safe")], coverage=cov,
                      locations=[elsewhere]) == "explicit_safe"

    def test_detected_with_failed_target_section_reports_gap(self):
        cov = _coverage([
            _target_section("failed"),
            _section("ok", [_hunk(ROW_FILE, 40, 3)]),
        ])
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "vulnerable")], coverage=cov))
        assert row["case_label"] == "detected_vulnerability"
        assert row["coverage_gap"] is True

    def test_detected_on_complete_coverage_has_no_gap(self):
        row = evaluate.score_case(_case_row(**_scenario("detected_vulnerability")))
        assert row["coverage_gap"] is False

    @pytest.mark.parametrize("over", [
        {"complete": False}, {"hunks_leftover": 1}, {"hunks_leftover": 2},
        {"sections_failed": 1},
    ])
    def test_detected_gap_triggers(self, over):
        cov = _coverage([_target_section()], **over)
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "vulnerable")], coverage=cov))
        assert row["case_label"] == "detected_vulnerability"
        assert row["coverage_gap"] is True

    @pytest.mark.parametrize("status", ["failed", "skipped", "pending", None])
    def test_any_non_completed_target_section_is_missing_review(self, status):
        cov = _coverage([
            _target_section(status),
            _section("done", [_hunk(ROW_FILE, 200, 4)]),
        ])
        assert _label(findings=[_f("authz", "safe")], coverage=cov) == "missing_review"

    @pytest.mark.parametrize("findings,label", [
        ([_s("authz", False), _s("authz", False)], "explicit_safe"),
        ([_s("authz", False), _s("authz", True)], "detected_vulnerability"),
    ])
    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_supported_candidate_decides_the_label_in_judged_modes(
            self, mode, findings, label):
        cov = _coverage([_target_section()])
        assert _label(mode=mode, findings=findings, coverage=cov) == label

    def test_failed_non_target_section_reports_gap_on_a_detected_row(self):
        cov = _coverage(
            [_target_section(), _section("far", [_hunk(ROW_FILE, 200, 4)], "failed")],
            complete=True, hunks_leftover=0)
        assert cov["sections_failed"] == 1
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "vulnerable")], coverage=cov))
        assert row["case_label"] == "detected_vulnerability"
        assert row["coverage_gap"] is True

    @pytest.mark.parametrize("mode", COVERAGE_MODES + ["llm-only"])
    @pytest.mark.parametrize("verdict", ["possible", "insufficient_evidence", "safe"])
    def test_coverage_gap_is_false_for_non_detected_labels(self, mode, verdict):
        cov = _coverage([_target_section()], hunks_leftover=3, complete=False)
        kwargs = {} if mode == "llm-only" else {"coverage": cov}
        row = evaluate.score_case(_case_row(
            mode=mode, findings=[_f("authz", verdict)], **kwargs))
        assert row["coverage_gap"] is False

    @pytest.mark.parametrize("label", [
        "missing_review", "no_candidate", "scan_failure"])
    def test_coverage_gap_is_false_for_unreviewed_labels(self, label):
        row = evaluate.score_case(_case_row(**_scenario(label)))
        assert row["coverage_gap"] is False

    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_coverage_gap_is_false_for_findings_only_detections(self, mode):
        row = evaluate.score_case(_case_row(
            mode=mode, findings=[_f("authz", "vulnerable")]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["coverage_gap"] is False

    @pytest.mark.parametrize("locations", [None, []])
    def test_safe_rows_without_vulnerable_locations_target_the_row_file(self, locations):
        cov = _coverage([
            _target_section(),
            _section("far", [_hunk(ROW_FILE, 200, 4)], "failed"),
            _section("unrelated", [_hunk("app/other.py")], "failed"),
        ])
        row = evaluate.score_case(_case_row(
            expected="safe", findings=[_f("authz", "safe")], coverage=cov,
            locations=locations))
        assert sorted(row["target_sections"]) == ["far", "s-target"]
        assert row["case_label"] == "missing_review"
        assert row["outcome"] == "TN"  # no vulnerable finding on a safe PR

    @pytest.mark.parametrize("locations", [None, []])
    def test_safe_rows_without_locations_are_explicit_safe_when_row_file_reviewed(
            self, locations):
        cov = _coverage([
            _target_section(),
            _section("unrelated", [_hunk("app/other.py")], "failed"),
        ])
        row = evaluate.score_case(_case_row(
            expected="safe", findings=[_f("authz", "safe")], coverage=cov,
            locations=locations))
        assert row["case_label"] == "explicit_safe"
        assert row["outcome"] == "TN"

    @pytest.mark.parametrize("locations", [None, []])
    def test_safe_rows_without_locations_are_no_candidate_when_row_file_untouched(
            self, locations):
        cov = _coverage([_section("other", [_hunk("app/other.py")])])
        assert _label(expected="safe", findings=[_f("authz", "safe")],
                      coverage=cov, locations=locations) == "no_candidate"

    @pytest.mark.parametrize("verdict", ["possible", "insufficient_evidence", "safe"])
    def test_failed_target_section_outranks_non_vulnerable_findings(self, verdict):
        cov = _failed_target_coverage()
        assert _label(findings=[_f("authz", verdict)], coverage=cov) == "missing_review"

    def test_failed_section_outside_the_target_is_not_missing_review(self):
        cov = _coverage([
            _target_section(),
            _section("far", [_hunk(ROW_FILE, 200, 4)], "failed"),
        ])
        row = evaluate.score_case(_case_row(findings=[_f("authz", "safe")], coverage=cov))
        assert row["case_label"] == "explicit_safe"
        assert row["target_sections"] == ["s-target"]

    def test_failed_section_in_an_unrelated_file_is_not_missing_review(self):
        cov = _coverage([
            _target_section(),
            _section("unrelated", [_hunk("app/other.py")], "failed"),
        ])
        assert _label(findings=[_f("authz", "safe")], coverage=cov) == "explicit_safe"

    def test_other_category_findings_are_not_relevant(self):
        cov = _coverage([_target_section()])
        assert _label(findings=[_f("sqli", "vulnerable")], coverage=cov) == "explicit_safe"

    def test_target_sections_are_those_overlapping_a_location(self):
        near = _section("near", [_hunk(ROW_FILE, 12, 2)])
        far = _section("far", [_hunk(ROW_FILE, 300, 2)])
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "safe")], coverage=_coverage([near, far])))
        assert row["target_sections"] == ["near"]

    def test_file_level_fallback_when_no_section_overlaps_any_location(self):
        a = _section("a", [_hunk(ROW_FILE, 100, 2)])
        b = _section("b", [_hunk(ROW_FILE, 300, 2)], "failed")
        c = _section("c", [_hunk("app/other.py", 12, 2)])
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "safe")], coverage=_coverage([a, b, c])))
        assert sorted(row["target_sections"]) == ["a", "b"]
        assert row["case_label"] == "missing_review"

    def test_fallback_covers_location_files_other_than_the_row_file(self):
        loc = {"file": "app/models.py", "old_range": None, "new_range": [1, 3]}
        a = _section("a", [_hunk("app/models.py", 50, 2)])
        b = _section("b", [_hunk(ROW_FILE, 50, 2)])
        c = _section("c", [_hunk("app/other.py", 50, 2)])
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "safe")], locations=[loc],
            coverage=_coverage([a, b, c])))
        assert sorted(row["target_sections"]) == ["a", "b"]

    def test_every_location_is_checked_for_overlap(self):
        second = {"file": ROW_FILE, "old_range": None, "new_range": [300, 305]}
        p = _section("p", [_hunk(ROW_FILE, 100, 2)])
        q = _section("q", [_hunk(ROW_FILE, 301, 2)], "failed")
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "safe")], locations=[LOCATION, second],
            coverage=_coverage([p, q])))
        assert row["target_sections"] == ["q"]
        assert row["case_label"] == "missing_review"

    def test_no_file_fallback_when_any_location_overlaps_a_section(self):
        elsewhere = {"file": "app/models.py", "old_range": None, "new_range": [1, 3]}
        m = _section("m", [_hunk("app/models.py", 50, 2)], "failed")
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "safe")], locations=[LOCATION, elsewhere],
            coverage=_coverage([_target_section(), m])))
        assert row["target_sections"] == ["s-target"]
        assert row["case_label"] == "explicit_safe"

    def test_location_file_other_than_the_row_file_can_make_a_candidate(self):
        loc = {"file": "app/models.py", "old_range": None, "new_range": [1, 3]}
        only = _section("only", [_hunk("app/models.py", 50, 2)])
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "safe")], locations=[loc],
            coverage=_coverage([only])))
        assert row["case_label"] == "explicit_safe"
        assert row["target_sections"] == ["only"]

    def test_old_side_range_alone_selects_the_overlapping_section(self):
        loc = {"file": ROW_FILE, "old_range": [100, 104], "new_range": None}
        by_old = _section("by-old", [_hunk(ROW_FILE, 500, 5, old_start=100)])
        far = _section("far", [_hunk(ROW_FILE, 300, 5)])
        row = evaluate.score_case(_case_row(
            findings=[_f("authz", "safe")], locations=[loc],
            coverage=_coverage([by_old, far])))
        assert row["target_sections"] == ["by-old"]


class TestFindingsOnlyLabels:
    @pytest.mark.parametrize("mode", ["llm-only"])
    @pytest.mark.parametrize("findings,label", [
        ([], "no_candidate"),
        ([_f("sqli", "vulnerable")], "no_candidate"),
        ([_f("authz", "vulnerable")], "detected_vulnerability"),
        ([_f("authz", "possible"), _f("authz", "safe")], "possible_vulnerability"),
        ([_f("authz", "insufficient_evidence")], "insufficient_evidence"),
        ([_f("authz", "safe")], "explicit_safe"),
    ])
    def test_label_mapping(self, mode, findings, label):
        row = evaluate.score_case(_case_row(findings=findings, mode=mode))
        assert row["case_label"] == label
        assert "coverage" not in row

    def test_no_relevant_finding_on_safe_case_is_a_true_negative(self):
        # The round-2 rule: a safe PR the tool did not flag is a TN, in every mode.
        row = evaluate.score_case(_case_row(expected="safe", findings=[], mode="llm-only"))
        assert row["outcome"] == "TN"
        assert row["case_label"] == "no_candidate"

    def test_no_relevant_finding_on_vulnerable_case_is_a_miss(self):
        row = evaluate.score_case(_case_row(expected="vulnerable", findings=[], mode="llm-only"))
        assert row["outcome"] == "FN"


    @pytest.mark.parametrize("mode", ["llm-only"])
    @pytest.mark.parametrize("findings,label", [
        ([_f("authz", "possible"), _f("authz", "insufficient_evidence"),
          _f("authz", "safe")], "possible_vulnerability"),
        ([_f("authz", "insufficient_evidence"), _f("authz", "safe")], "explicit_safe"),
        ([_f("authz", "insufficient_evidence"), _f("authz", "insufficient_evidence")],
         "insufficient_evidence"),
    ])
    def test_non_vulnerable_verdict_precedence(self, mode, findings, label):
        assert _label(mode=mode, findings=findings) == label

    @pytest.mark.parametrize("expected,plain,grounded", [
        ("vulnerable", "TP", "FN"), ("safe", "FP", "TN"),
    ])
    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_ungrounded_vulnerable_is_downgraded_to_possible_in_grounded_label(
            self, mode, expected, plain, grounded):
        row = evaluate.score_case(_case_row(
            expected=expected, mode=mode,
            findings=[_f("authz", "vulnerable", valid=False)]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "possible_vulnerability"
        assert row["outcome"] == plain
        assert row["outcome_grounded"] == grounded

    def test_grounded_label_stays_detected_with_one_valid_vulnerable_finding(self):
        row = evaluate.score_case(_case_row(
            mode="llm-only",
            findings=[_f("authz", "vulnerable", valid=True),
                      _f("authz", "vulnerable", valid=False)]))
        assert row["case_label_grounded"] == "detected_vulnerability"
        assert row["outcome_grounded"] == "TP"

    def test_grounded_label_prefers_a_valid_possible_over_an_invalid_vulnerable(self):
        row = evaluate.score_case(_case_row(
            mode="llm-only",
            findings=[_f("authz", "vulnerable", valid=False), _f("authz", "possible")]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "possible_vulnerability"

    def test_sqli_grounded_label_downgrades_an_ungrounded_detection(self):
        row = evaluate.score_case(_case_row(
            category="sqli", mode="llm-only",
            findings=[_f("sqli", "vulnerable", valid=False)]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "possible_vulnerability"

    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_judged_modes_have_no_grounded_downgrade(self, mode):
        row = evaluate.score_case(_case_row(
            mode=mode, coverage=_coverage([_target_section()]),
            findings=[_s("authz", True)]))
        assert row["case_label"] == row["case_label_grounded"] == "detected_vulnerability"


class TestOutcomeTable:
    @pytest.mark.parametrize("label,vulnerable_outcome,safe_outcome", [
        ("detected_vulnerability", "TP", "FP"),
        ("explicit_safe", "FN", "TN"),
        ("no_candidate", "FN", "TN"),
        ("missing_review", "FN", "TN"),
        # scan_failure's scenario carries a vulnerable finding: the finding,
        # not the label, decides the outcome.
        ("scan_failure", "TP", "FP"),
    ])
    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_outcome_by_label_and_expectation(
            self, label, vulnerable_outcome, safe_outcome, mode):
        vuln = evaluate.score_case(_case_row(
            expected="vulnerable", mode=mode, **_scenario(label)))
        safe = evaluate.score_case(_case_row(
            expected="safe", mode=mode, **_scenario(label)))
        assert vuln["outcome"] == vulnerable_outcome
        assert vuln["outcome_grounded"] == vulnerable_outcome
        assert safe["outcome"] == safe_outcome
        assert safe["outcome_grounded"] == safe_outcome

    @pytest.mark.parametrize("label,vulnerable_outcome,safe_outcome", [
        ("possible_vulnerability", "FN", "TN"),
        ("insufficient_evidence", "FN", "TN"),
    ])
    def test_baseline_only_labels_score_as_before(
            self, label, vulnerable_outcome, safe_outcome):
        vuln = evaluate.score_case(_case_row(expected="vulnerable", **_scenario(label)))
        safe = evaluate.score_case(_case_row(expected="safe", **_scenario(label)))
        assert (vuln["outcome"], safe["outcome"]) == (vulnerable_outcome, safe_outcome)

    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    @pytest.mark.parametrize("expected,outcome", [("vulnerable", "TP"), ("safe", "FP")])
    def test_one_supported_candidate_among_unsupported_is_a_detection(
            self, mode, expected, outcome):
        row = evaluate.score_case(_case_row(
            expected=expected, mode=mode, coverage=_coverage([_target_section()]),
            findings=[_s("authz", False), _s("authz", True)]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["outcome"] == outcome
        assert row["outcome_grounded"] == outcome

    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_judged_modes_ignore_a_verdict_and_key_on_supported(self, mode):
        stale = dict(_s("authz", False), verdict="vulnerable")
        row = evaluate.score_case(_case_row(
            mode=mode, coverage=_coverage([_target_section()]), findings=[stale],
            raw=True))
        assert row["case_label"] == "explicit_safe"
        assert row["outcome"] == "FN"

    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_supported_candidate_in_another_category_is_not_a_detection(self, mode):
        row = evaluate.score_case(_case_row(
            mode=mode, coverage=_coverage([_target_section()]),
            findings=[_s("sqli", True)]))
        assert row["case_label"] == "explicit_safe"

    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_baselines_key_on_verdict_not_on_supported(self, mode):
        row = evaluate.score_case(_case_row(
            mode=mode, findings=[dict(_f("authz", "vulnerable"), supported=False)]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["outcome"] == "TP"


@pytest.fixture
def stored(monkeypatch):
    """Serve a row to is_done without touching the filesystem."""
    def put(row):
        monkeypatch.setattr(evaluate, "load_result", lambda path: row)
    return put


class TestCoverageRowErrors:
    def test_infra_marker_findings_are_ignored_for_coverage_rows(self, stored):
        row = evaluate.score_case(_case_row(
            expected="safe", coverage=_coverage([_target_section()]),
            findings=[_infra_finding("authz:1"), _f("authz", "safe")]))
        assert row["outcome"] != "ERROR"
        assert row["case_label"] == "explicit_safe"
        assert row["infra_failures"] == 0
        assert row["infra_failure_ids"] == []
        assert evaluate.summarize([row])["errors"] == 0
        stored(row)
        assert evaluate.is_done(Path("row.json")) is True

    def test_infra_marker_findings_still_error_findings_only_rows(self):
        row = evaluate.score_case(_case_row(
            mode="llm-only", findings=[_infra_finding("authz:1")]))
        assert row["outcome"] == "ERROR"
        assert row["infra_failures"] == 1

    def test_row_error_keeps_the_error_path_for_coverage_rows(self):
        row = evaluate.score_case(_case_row(
            coverage=_coverage([_target_section()]), error="harness exploded"))
        assert row["outcome"] == "ERROR"
        assert row["error"] == "harness exploded"
        assert row["case_label"] == "scan_failure"
        assert row["case_label_grounded"] == "scan_failure"

    def test_mark_error_sets_both_labels_to_scan_failure(self):
        marked = evaluate.mark_error(_case_row(coverage=None), "boom")
        assert marked["case_label"] == "scan_failure"
        assert marked["case_label_grounded"] == "scan_failure"
        assert marked["outcome"] == "ERROR"

    def test_scan_failure_and_missing_review_rows_are_not_errors_in_summary(self):
        rows = [
            evaluate.score_case(_case_row("a", "safe", **_scenario("scan_failure"))),
            evaluate.score_case(_case_row("b", "safe", **_scenario("missing_review"))),
        ]
        summary = evaluate.summarize(rows)
        assert summary["errors"] == 0
        assert summary["error_cases"] == []
        assert summary["overall"]["errors"] == 0

    @pytest.mark.parametrize("reason,done", [("judge-failed", False), ("request-too-large", True)])
    def test_is_done_reruns_rows_whose_judge_call_failed(self, stored, reason, done):
        row = _case_row(findings=[{"category": "authz", "judged": False, "not_judged_reason": reason}], raw=True)
        stored(row)
        assert evaluate.is_done(Path("row.json")) is done

    def test_is_done_is_false_for_scan_failure_rows(self, stored):
        stored(evaluate.score_case(_case_row(**_scenario("scan_failure"))))
        assert evaluate.is_done(Path("row.json")) is False

    @pytest.mark.parametrize("label", [
        "explicit_safe", "no_candidate",
        "possible_vulnerability", "insufficient_evidence",
        "detected_vulnerability"])
    def test_is_done_is_true_for_scored_coverage_rows(self, stored, label):
        stored(evaluate.score_case(_case_row(**_scenario(label))))
        assert evaluate.is_done(Path("row.json")) is True

    def test_is_done_is_false_for_missing_review_rows_with_a_failed_section(self, stored):
        row = evaluate.score_case(_case_row(**_scenario("missing_review")))
        assert row["coverage"]["sections_failed"] > 0
        stored(row)
        assert evaluate.is_done(Path("row.json")) is False


class TestNonAuthzCoverageRows:
    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    @pytest.mark.parametrize("cov", [
        _coverage([_target_section("failed")], sections_completed=0),
        _coverage([], investigator_error="boom", investigator_status="failed"),
    ], ids=["sections-failed", "investigator-error"])
    def test_failed_authz_review_does_not_make_a_sqli_row_a_scan_failure(self, mode, cov):
        row = evaluate.score_case(_case_row(
            mode=mode, category="sqli", findings=[_f("sqli", "vulnerable")], coverage=cov))
        assert row["case_label"] == "detected_vulnerability"
        assert row["outcome"] == "TP"

    def test_failed_target_section_is_not_missing_review_for_sqli(self):
        row = evaluate.score_case(_case_row(
            category="sqli", expected="safe", findings=[_f("sqli", "safe")],
            coverage=_failed_target_coverage()))
        assert row["case_label"] == "explicit_safe"
        assert row["target_sections"] == ["s-target"]
        assert row["coverage_gap"] is False

    def test_sqli_detection_without_a_target_section_is_detected(self):
        cov = _coverage([_section("other", [_hunk("app/other.py")])])
        row = evaluate.score_case(_case_row(
            category="sqli", findings=[dict(_f("sast", "vulnerable"), file=ROW_FILE)],
            coverage=cov))
        assert row["case_label"] == "detected_vulnerability"
        assert row["target_sections"] == []

    def test_sqli_row_without_relevant_findings_is_no_candidate(self):
        row = evaluate.score_case(_case_row(
            category="sqli", findings=[_f("authz", "vulnerable")],
            coverage=_coverage([_target_section()])))
        assert row["case_label"] == "no_candidate"

    def test_sqli_finding_outside_the_target_files_is_not_relevant(self):
        elsewhere = dict(_f("sqli", "vulnerable"), file="app/other.py")
        row = evaluate.score_case(_case_row(
            category="sqli", findings=[elsewhere],
            coverage=_coverage([_target_section()])))
        assert row["case_label"] == "no_candidate"

    def test_sqli_finding_in_a_vulnerable_location_file_is_relevant(self):
        location = {"file": "app/db.py", "old_range": None, "new_range": [1, 3]}
        row = evaluate.score_case(_case_row(
            category="sqli", locations=[location],
            findings=[dict(_s("sqli", True), file="app/db.py")],
            coverage=_coverage([_target_section()])))
        assert row["case_label"] == "detected_vulnerability"

    def test_sqli_row_without_coverage_is_a_scan_failure(self):
        row = evaluate.score_case(_case_row(
            category="sqli", findings=[_f("sqli", "vulnerable")], coverage=None))
        assert row["case_label"] == "scan_failure"


class TestSastErrorRows:
    def test_row_with_a_sast_error_is_an_error(self):
        row = evaluate.score_case(_case_row(
            mode="lgtm", category="sqli", findings=[_f("sqli", "safe")],
            sast_error="semgrep timed out after 60s",
            coverage=_coverage([_target_section()])))
        assert evaluate.result_is_error(row)
        assert row["outcome"] == "ERROR"
        assert row["error"] == "SAST failed: semgrep timed out after 60s"
        assert row["case_label"] == "scan_failure"

    def test_row_with_a_failed_sast_triage_is_an_error_not_a_miss(self):
        row = evaluate.score_case(_case_row(
            mode="lgtm", category="sqli", findings=[],
            coverage=_coverage([_target_section()]), triage_errors=1))
        assert evaluate.result_is_error(row)
        assert row["outcome"] == "ERROR"
        assert row["error"] == "SAST triage failed for 1 hit(s)"

    def test_triage_errors_count_only_sast_triage_agent_errors(self):
        meta = SimpleNamespace(agent_errors=[
            {"source": "r:app.py:3", "message": "x", "stage": "sast_triage"},
            {"source": "s1", "message": "y"},
        ])
        assert evaluate.sast_fields(SimpleNamespace(meta=meta))["triage_errors"] == 1

    def test_sast_error_rows_are_excluded_from_metrics_and_rerun(self, stored):
        failed = evaluate.score_case(_case_row(
            "a", category="sqli", findings=[_f("sqli", "vulnerable")],
            coverage=_coverage([_target_section()]), sast_error="boom"))
        ok = evaluate.score_case(_case_row(
            "b", category="sqli", findings=[_f("sqli", "vulnerable")],
            coverage=_coverage([_target_section()]), sast_error=None))
        summary = evaluate.summarize([failed, ok])
        assert summary["errors"] == 1
        assert summary["error_cases"] == [{"id": "a", "error": "SAST failed: boom"}]
        assert summary["scored"] == 1
        stored(failed)
        assert evaluate.is_done(Path("row.json")) is False

    def test_rows_without_the_field_rescore_as_before(self):
        row = _case_row(category="sqli", findings=[_f("sqli", "vulnerable")],
                        coverage=_coverage([_target_section()]))
        assert "sast_error" not in row
        assert evaluate.score_case(row)["case_label"] == "detected_vulnerability"

    def test_sast_fields_read_the_review_metadata(self):
        review = SimpleNamespace(meta=ReviewMetadata(
            sast_error="semgrep exited 2", semgrep_findings_total=0))
        assert evaluate.sast_fields(review) == {
            "sast_error": "semgrep exited 2", "semgrep_findings_total": 0, "triage_errors": 0}

    @pytest.mark.parametrize("review", [None, SimpleNamespace(meta=SimpleNamespace())])
    def test_sast_fields_default_for_missing_metadata(self, review):
        assert evaluate.sast_fields(review) == {
            "sast_error": None, "semgrep_findings_total": None, "triage_errors": 0}

    def test_error_record_carries_the_sast_fields(self):
        review = SimpleNamespace(meta=ReviewMetadata(
            sast_error="semgrep exited 2", semgrep_findings_total=0))
        case = {"id": "c", "category": "sqli", "expected_verdict": "vulnerable"}
        rec = evaluate.error_record(case, "llm-only", {}, review)
        assert rec["sast_error"] == "semgrep exited 2"
        assert rec["semgrep_findings_total"] == 0


def _legacy_row():
    return evaluate.score_case({
        "id": "old", "category": "authz", "split": "dev", "expected": "safe",
        "findings": [_f("authz", "safe")], "latency_seconds": 1.0, "est_tokens": 10})


class TestSummaryContract:
    @staticmethod
    def _mixed_rows():
        specs = [
            ("v1", "vulnerable", "detected_vulnerability"),
            ("v2", "vulnerable", "explicit_safe"),
            ("v3", "vulnerable", "missing_review"),
            ("v4", "vulnerable", "possible_vulnerability"),
            ("v5", "vulnerable", "insufficient_evidence"),
            ("s1", "safe", "detected_vulnerability"),
            ("s2", "safe", "explicit_safe"),
            ("s3", "safe", "possible_vulnerability"),
            ("s4", "safe", "insufficient_evidence"),
            ("s5", "safe", "no_candidate"),
            ("s6", "safe", "missing_review"),
            ("s7", "safe", "scan_failure"),
        ]
        rows = [evaluate.score_case(_case_row(cid, exp, **_scenario(label)))
                for cid, exp, label in specs]
        rows.append(evaluate.score_case(_case_row(
            "e1", "safe", coverage=_coverage([_target_section()]),
            error="harness exploded")))
        return rows

    def test_grounded_only_uses_the_grounded_outcome(self):
        rows = [
            evaluate.score_case(_case_row(
                "v", "vulnerable", mode="llm-only",
                findings=[_f("authz", "vulnerable", valid=False)])),
            evaluate.score_case(_case_row(
                "s", "safe", mode="llm-only",
                findings=[_f("authz", "vulnerable", valid=False)])),
        ]
        summary = evaluate.summarize(rows)
        assert (summary["overall"]["tp"], summary["overall"]["fp"]) == (1, 1)
        grounded = summary["grounded_only"]["overall"]
        assert (grounded["tp"], grounded["fp"], grounded["fn"]) == (0, 0, 1)

    def test_grounded_only_metrics_use_the_grounded_label(self):
        rows = [
            evaluate.score_case(_case_row(
                "s", "safe", mode="llm-only", coverage=_coverage([_target_section()]),
                findings=[_f("authz", "vulnerable", valid=False)])),
            evaluate.score_case(_case_row(
                "m", "safe", coverage=_failed_target_coverage(),
                findings=[_f("authz", "safe")])),
        ]
        summary = evaluate.summarize(rows)
        plain = summary["overall"]
        grounded = summary["grounded_only"]["overall"]
        assert (plain["abstentions"], plain["possible_on_safe"]) == (0, 0)
        assert (grounded["abstentions"], grounded["possible_on_safe"]) == (1, 1)
        assert plain["excluded_on_safe"] == grounded["excluded_on_safe"] == 0
        assert (plain["safe_scored"], grounded["safe_scored"]) == (2, 2)

    def test_metrics_score_every_non_error_row(self):
        # s7 (scan failure, vulnerable finding) is an FP; s3-s6 are TNs:
        # nothing is excluded or uncredited under the round-2 rule.
        overall = evaluate.summarize(self._mixed_rows())["overall"]
        assert (overall["cases"], overall["scored"], overall["errors"]) == (13, 12, 1)
        assert (overall["tp"], overall["fp"], overall["fn"], overall["tn"]) == (1, 2, 4, 5)
        assert overall["vulnerable_scored"] == 5
        assert overall["safe_scored"] == 7
        assert overall["abstentions"] == 4
        assert overall["possible_on_safe"] == 1
        assert overall["excluded_on_safe"] == 0
        assert overall["false_positive_rate_on_safe"] == 0.286
        assert overall["accuracy"] == 0.5
        assert overall["precision"] == 0.333
        assert overall["recall"] == 0.2

    def test_failed_reviews_are_scored_not_excluded(self):
        rows = [
            evaluate.score_case(_case_row("a", "safe", **_scenario("scan_failure"))),
            evaluate.score_case(_case_row("b", "safe", **_scenario("missing_review"))),
        ]
        overall = evaluate.summarize(rows)["overall"]
        assert [r["outcome"] for r in rows] == ["FP", "TN"]
        assert overall["safe_scored"] == 2
        assert overall["excluded_on_safe"] == 0
        assert overall["accuracy"] == 0.5
        assert overall["false_positive_rate_on_safe"] == 0.5

    @staticmethod
    def _excluded(cid):
        row = evaluate.score_case(_case_row(cid, "safe", **_scenario("explicit_safe")))
        row["outcome"] = row["outcome_grounded"] = "EXCLUDED"
        return row

    def test_metrics_denominators_exclude_excluded_safe_rows(self):
        rows = [
            evaluate.score_case(_case_row("tn", "safe", **_scenario("explicit_safe"))),
            evaluate.score_case(_case_row("fp", "safe", **_scenario("detected_vulnerability"))),
            self._excluded("x1"), self._excluded("x2"),
        ]
        overall = evaluate.summarize(rows)["overall"]
        assert (overall["tn"], overall["fp"]) == (1, 1)
        assert overall["safe_scored"] == 2
        assert overall["excluded_on_safe"] == 2
        assert overall["false_positive_rate_on_safe"] == 0.5
        assert overall["accuracy"] == 0.5

    def test_metrics_are_none_when_every_safe_row_is_excluded(self):
        overall = evaluate.summarize([self._excluded("x1"), self._excluded("x2")])["overall"]
        assert overall["safe_scored"] == 0
        assert overall["excluded_on_safe"] == 2
        assert overall["accuracy"] is None
        assert overall["false_positive_rate_on_safe"] is None

    def test_per_category_and_per_split_use_the_new_metrics(self):
        summary = evaluate.summarize(self._mixed_rows())
        assert summary["per_split"]["dev"]["excluded_on_safe"] == 0
        assert summary["per_split"]["dev"]["abstentions"] == 4
        assert summary["per_category"]["authz"]["safe_scored"] == 7

    def test_case_labels_count_each_label_and_legacy_rows(self):
        rows = [
            evaluate.score_case(_case_row("a", "safe", **_scenario("explicit_safe"))),
            evaluate.score_case(_case_row("b", "safe", **_scenario("explicit_safe"))),
            evaluate.score_case(_case_row("c", "safe", **_scenario("no_candidate"))),
            _legacy_row(),
        ]
        summary = evaluate.summarize(rows)
        assert summary["case_labels"] == {
            "explicit_safe": 2, "no_candidate": 1, "legacy": 1}
        assert summary["legacy_rows"] == 1

    def test_error_rows_count_under_the_label_they_carry(self):
        coverage_error = evaluate.score_case(_case_row(
            "e", "safe", coverage=_coverage([_target_section()]), error="boom"))
        legacy_error = evaluate.score_case({
            "id": "old-e", "category": "authz", "split": "dev", "expected": "safe",
            "findings": [], "error": "boom"})
        summary = evaluate.summarize([coverage_error, legacy_error])
        assert summary["case_labels"] == {"scan_failure": 1, "legacy": 1}
        assert summary["coverage"]["rows"] == 0
        assert summary["coverage"]["sections_scheduled"] == 0

    def test_coverage_rows_include_dict_coverage_with_no_completed_section(self):
        row = evaluate.score_case(_case_row(
            "a", "safe", coverage=_coverage([_target_section("failed")])))
        cov = evaluate.summarize([row])["coverage"]
        assert cov["rows"] == 1
        assert cov["sections_scheduled"] == 1
        assert cov["sections_completed"] == 0

    def test_detected_with_gap_counts_detections_regardless_of_expectation(self):
        gappy = _coverage([_target_section()], hunks_leftover=2)
        rows = [
            evaluate.score_case(_case_row(
                "tp", "vulnerable", coverage=gappy, findings=[_f("authz", "vulnerable")])),
            evaluate.score_case(_case_row(
                "fp", "safe", coverage=gappy, findings=[_f("authz", "vulnerable")])),
            evaluate.score_case(_case_row(
                "tn", "safe", coverage=gappy, findings=[_f("authz", "safe")])),
            evaluate.score_case(_case_row(
                "clean", "safe", **_scenario("detected_vulnerability"))),
        ]
        assert evaluate.summarize(rows)["coverage"]["detected_with_gap"] == 2

    def test_legacy_rows_count_in_outcome_metrics_but_not_label_metrics(self):
        safe = evaluate.score_case({
            "id": "ls", "category": "authz", "split": "dev", "expected": "safe",
            "findings": [_f("authz", "possible")], "latency_seconds": 1.0,
            "est_tokens": 10})
        vuln = evaluate.score_case({
            "id": "lv", "category": "authz", "split": "dev", "expected": "vulnerable",
            "findings": [_f("authz", "vulnerable")], "latency_seconds": 1.0,
            "est_tokens": 10})
        assert (safe["outcome"], safe["predicted"], safe["correct"]) == ("UNKNOWN", "unknown", None)
        assert (vuln["outcome"], vuln["predicted"], vuln["correct"]) == ("UNKNOWN", "unknown", None)
        overall = evaluate.summarize([safe, vuln])["overall"]
        assert (overall["safe_scored"], overall["vulnerable_scored"]) == (0, 0)
        assert overall["unknown_rows"] == 2
        assert overall["excluded_on_safe"] == 0
        assert overall["abstentions"] == 0
        assert overall["possible_on_safe"] == 0

    def test_unknown_row_is_counted_once_beside_scored_rows(self):
        unknown = evaluate.score_case({
            "id": "lu", "category": "authz", "split": "dev", "expected": "vulnerable",
            "findings": [_f("authz", "vulnerable")], "latency_seconds": 1.0,
            "est_tokens": 10})
        tp = evaluate.score_case(_case_row(
            "tp", "vulnerable", coverage=_coverage([_target_section()]),
            findings=[_f("authz", "vulnerable")]))
        tn = evaluate.score_case(_case_row(
            "tn", "safe", coverage=_coverage([_target_section()]),
            findings=[_f("authz", "safe")]))
        assert (tp["outcome"], tn["outcome"]) == ("TP", "TN")
        assert unknown["outcome"] == "UNKNOWN"
        overall = evaluate.summarize([unknown, tp, tn])["overall"]
        assert (overall["vulnerable_scored"], overall["safe_scored"]) == (1, 1)
        assert overall["unknown_rows"] == 1
        assert overall["accuracy"] == 1.0

    def test_row_with_mode_and_coverage_but_no_pin_is_legacy(self):
        raw = _case_row(
            expected="vulnerable", coverage=_coverage([_target_section()]),
            findings=[_f("authz", "vulnerable")], raw=True)
        del raw["pin"]
        row = evaluate.score_case(raw)
        assert row["legacy"] is True
        assert row["case_label"] is None
        assert row["outcome"] == "TP"

    def test_row_with_pin_but_no_mode_is_not_legacy(self):
        raw = _case_row(expected="safe", findings=[_f("authz", "safe")])
        del raw["mode"]
        row = evaluate.score_case(raw)
        assert not row.get("legacy")
        assert row["case_label"] == "explicit_safe"

    @pytest.mark.parametrize("coverage", [None, "absent"])
    def test_unknown_coverage_stays_unknown_through_reload_rescore_and_summary(
        self, tmp_path, coverage
    ):
        raw = _case_row(expected="safe", findings=[_f("authz", "safe")], coverage=coverage)
        del raw["pin"]
        row = evaluate.score_case(raw)
        path = tmp_path / "legacy.json"
        path.write_text(json.dumps(row), encoding="utf-8")

        loaded = evaluate.load_result(path)
        rescored = evaluate.score_case(loaded)
        summary = evaluate.summarize([rescored])

        assert rescored.get("coverage") is None
        assert (rescored["outcome"], rescored["predicted"], rescored["correct"]) == (
            "UNKNOWN", "unknown", None)
        assert not evaluate.result_is_error(rescored)
        assert summary["coverage"]["rows"] == 0
        assert summary["coverage"]["complete_rate"] is None
        assert summary["overall"]["accuracy"] is None
        assert not evaluate.is_done(path)

    def test_existing_summary_keys_are_kept(self):
        summary = evaluate.summarize(self._mixed_rows())
        for key in ("overall", "per_category", "per_split", "graph_states",
                    "grounded_only", "scored", "errors", "error_rate",
                    "error_cases", "off_category_alarm_rate",
                    "off_category_alarms", "evidence_grounding_rate",
                    "possible_rate", "insufficient_evidence_rate",
                    "median_latency_seconds", "median_est_tokens_per_pr",
                    "case_labels", "legacy_rows", "coverage"):
            assert key in summary

    def test_coverage_summary_aggregates_coverage_dicts(self):
        full = _coverage(
            [_target_section(), _section("x", [_hunk(ROW_FILE, 40, 3)])],
            sections_coalesced=1, hunks_total=4, hunks_reviewed=4)
        gappy = _coverage(
            [_target_section("failed"), _section("y", [_hunk(ROW_FILE, 60, 3)])],
            planner="llm", investigator_status="failed", hunks_total=6,
            hunks_reviewed=3, hunks_leftover=2, invalid_refs=["h9", "h8"])
        rows = [
            evaluate.score_case(_case_row(
                "a", "vulnerable", coverage=full, findings=[_f("authz", "vulnerable")])),
            evaluate.score_case(_case_row(
                "b", "vulnerable", coverage=gappy, findings=[_f("authz", "vulnerable")])),
            evaluate.score_case(_case_row(
                "c", "safe", **_scenario("scan_failure"))),
            evaluate.score_case(_case_row(
                "d", "safe", mode="llm-only", findings=[_f("authz", "safe")])),
        ]
        cov = evaluate.summarize(rows)["coverage"]
        assert cov["rows"] == 2
        assert cov["complete"] == 1
        assert cov["complete_rate"] == 0.5
        assert cov["sections_scheduled"] == 4
        assert cov["sections_completed"] == 3
        assert cov["sections_failed"] == 1
        assert cov["sections_coalesced"] == 1
        assert cov["hunks_total"] == 10
        assert cov["hunks_reviewed"] == 7
        assert cov["hunks_leftover"] == 2
        assert cov["invalid_refs"] == 2
        assert cov["planners"] == {"deterministic": 1, "llm": 1}
        assert cov["investigator_status"] == {"ok": 1, "failed": 1}
        assert cov["detected_with_gap"] == 1

    def test_complete_rate_is_rounded_to_three_places(self):
        rows = [
            evaluate.score_case(_case_row(
                cid, "safe", findings=[_f("authz", "safe")],
                coverage=_coverage(
                    [_target_section("completed" if cid == "a" else "failed")])))
            for cid in ("a", "b", "c")
        ]
        cov = evaluate.summarize(rows)["coverage"]
        assert (cov["complete"], cov["rows"]) == (1, 3)
        assert cov["complete_rate"] == 0.333

    def test_detected_with_gap_excludes_error_rows(self):
        gappy = _coverage([_target_section()], hunks_leftover=2)
        detected = evaluate.score_case(_case_row(
            "d", "vulnerable", coverage=gappy, findings=[_f("authz", "vulnerable")]))
        errored = copy.deepcopy(detected)
        errored["id"] = "e"
        errored["error"] = "boom"
        assert detected["coverage_gap"] is True
        assert evaluate.coverage_summary([detected, errored])["detected_with_gap"] == 1

    def test_error_rescore_clears_stale_target_sections_and_gap(self):
        gappy = _coverage([_target_section()], hunks_leftover=2)
        row = evaluate.score_case(_case_row(
            "d", "vulnerable", coverage=gappy, findings=[_f("authz", "vulnerable")]))
        assert row["coverage_gap"] is True
        assert row["target_sections"] != []
        row["error"] = "boom"
        row = evaluate.score_case(row)
        assert row["target_sections"] == []
        assert row["coverage_gap"] is False
        assert row["case_label"] == "scan_failure"

    def test_fresh_error_row_carries_target_sections_and_boolean_gap(self):
        row = evaluate.score_case(_case_row(
            "e", "safe", coverage=_coverage([_target_section()]), error="boom"))
        assert row["target_sections"] == []
        assert row["coverage_gap"] is False


UNRESOLVABLE_ASSESSMENTS = json.dumps({
    "assessments": [{
        "category": "sqli", "verdict": "vulnerable", "cwe_id": "CWE-89", "file": "ghost.py",
        "line": 40, "explanation": "invented sink",
        "evidence": [{"type": "code", "file": "ghost.py", "lines": [40, 41],
                      "content": "ghost.execute(sql)", "snapshot": "pr"}],
    }]
})


class TestReferenceGuardrailExemptions:
    def test_llm_only_keeps_a_finding_whose_references_do_not_resolve_without_a_second_call(
        self, git_repo
    ):
        llm = _NoToolsLLM(UNRESOLVABLE_ASSESSMENTS)
        result = ReviewPipeline(git_repo, LGTMConfig(mode="llm-only"), llm=llm).run("main", "pr")
        sqli = [f for f in result.findings if f.category == "sqli"][0]
        assert llm.calls == 1
        assert sqli.explanation == "invented sink"
        assert [(e.file, list(e.lines), e.content) for e in sqli.evidence] == [
            ("ghost.py", [40, 41], "ghost.execute(sql)")
        ]

    def test_plain_reviewer_parse_leaves_unresolvable_evidence_unchanged(self):
        [finding] = PlainLLMReviewer._parse(UNRESOLVABLE_ASSESSMENTS)[:1]
        assert [(e.file, list(e.lines)) for e in finding.evidence] == [("ghost.py", [40, 41])]

    def test_sast_only_candidate_keeps_its_semgrep_citation_when_the_file_is_absent(self):
        from lgtm.sast.semgrep_runner import SemgrepFinding

        hit = SemgrepFinding(
            rule_id="py.sqli", path="ghost.py", start_line=40, end_line=41,
            message="SQL built from input", severity="ERROR", cwe=["CWE-89"],
            matched_code="ghost.execute(sql)",
        )
        finding = ReviewPipeline._sast_finding_to_agent_finding(hit)
        assert (finding.verdict, finding.judged) == ("vulnerable", False)
        assert [(e.file, list(e.lines), e.content) for e in finding.evidence] == [
            ("ghost.py", [40, 41], "ghost.execute(sql)")
        ]


def _scored(cid, category="authz", mode="lgtm", expected="vulnerable", findings=None, **extra):
    if findings is None:
        findings = [_f(category, "vulnerable" if expected == "vulnerable" else "safe")]
    return evaluate.score_case(
        _case_row(cid, expected, findings=findings, mode=mode, category=category, **extra))


class TestScopeInCaseResults:
    def test_case_flagged_out_of_scope_is_out_of_scope(self):
        assert _scored("a", "sqli", "lgtm", case_scope="out")["scope"] == "out"

    @pytest.mark.parametrize("category,mode", [
        ("sqli", "lgtm"), ("authz", "lgtm"), ("sqli", "llm-only"),
    ])
    def test_other_rows_stay_in_scope(self, category, mode):
        assert _scored("a", category, mode)["scope"] == "in"

    def test_out_of_scope_row_keeps_its_own_outcome(self):
        assert _scored("a", "sqli", "lgtm", case_scope="out")["outcome"] == "TP"

    def test_headline_counts_only_in_scope_rows(self):
        rows = [
            _scored("out_sql", "sqli", "lgtm", case_scope="out"),
            _scored("out_sql_safe", "sqli", "lgtm", expected="safe",
                    findings=[_f("sqli", "vulnerable")], case_scope="out"),
            _scored("in_authz", "authz", "lgtm"),
            _scored("in_sql", "sqli", "lgtm"),
        ]
        summary = evaluate.summarize(rows)
        for overall in (summary["overall"], summary["grounded_only"]["overall"]):
            assert (overall["cases"], overall["tp"], overall["fp"]) == (2, 2, 0)
        assert summary["per_category"]["sqli"]["cases"] == 1
        assert summary["per_category"]["authz"]["cases"] == 1
        assert summary["out_of_scope_cases"] == ["out_sql", "out_sql_safe"]

    def test_only_headline_metrics_exclude_out_of_scope_rows_while_other_counts_keep_them(self):
        in_row = _scored("in_authz", "authz", "lgtm")
        out_noisy = _scored(
            "out_noisy", "sqli", "lgtm", expected="safe",
            findings=[_f("sqli", "vulnerable"), _f("sqli", "safe")],
            latency_seconds=99.0, est_tokens=999, case_scope="out")
        out_noisy["predicted"] = "possible"
        out_failed = evaluate.mark_error(_scored("out_failed", "sqli", "lgtm", case_scope="out"), "boom")
        summary = evaluate.summarize([in_row, out_noisy, out_failed])

        for overall in (summary["overall"], summary["grounded_only"]["overall"]):
            assert overall["cases"] == 1
        assert set(summary["per_category"]) == {"authz"}
        assert (summary["scored"], summary["errors"], summary["error_rate"]) == (2, 1, 0.333)
        assert summary["error_cases"] == [{"id": "out_failed", "error": "boom"}]
        assert summary["evidence_grounding_rate"] == pytest.approx(2 / 3, abs=1e-3)
        assert summary["possible_rate"] == 0.5
        assert summary["insufficient_evidence_rate"] == 0.0
        assert summary["median_latency_seconds"] == 50.0
        assert summary["median_est_tokens_per_pr"] == 504
        assert summary["off_category_alarms"] == []
        assert summary["alarms_outside_target"] == []
        assert summary["kev"]["judged"] == 4
        assert summary["out_of_scope_cases"] == ["out_failed", "out_noisy"]
        assert sum(summary["case_labels"].values()) == 3

    def test_result_without_scope_key_counts_as_in_scope(self):
        old = _legacy_row()
        old.pop("scope", None)
        overall = evaluate.summarize([old])["overall"]
        assert (overall["cases"], overall["tn"]) == (1, 0)
        assert old["outcome"] == "UNKNOWN"
        assert old["correct"] is None


def _find_key(obj, name):
    """First value stored under ``name`` anywhere in a JSON-like object."""
    if isinstance(obj, dict):
        if name in obj:
            return obj[name]
        for value in obj.values():
            if (found := _find_key(value, name)) is not None:
                return found
    elif isinstance(obj, list):
        for value in obj:
            if (found := _find_key(value, name)) is not None:
                return found
    return None


def _off(category, verdict, fid):
    return {**_f(category, verdict), "finding_id": fid}


class TestOffCategoryFindings:
    @pytest.mark.parametrize("mode", ["llm-only", "lgtm"])
    def test_case_result_lists_other_category_findings_by_id(self, mode):
        row = _scored("a", "authz", mode, expected="safe", findings=[
            _off("authz", "safe", "authz:1"), _off("sqli", "vulnerable", "sqli:7")])
        assert row["off_category"] == ["sqli:7"]

    def test_same_category_and_uncategorized_findings_are_not_off_category(self):
        row = _scored("a", "authz", "llm-only", findings=[
            _off("authz", "vulnerable", "authz:1"), _off("sast", "vulnerable", "sast:1")])
        assert row["off_category"] == []

    def test_off_category_finding_does_not_change_the_outcome(self):
        safe = _scored("a", "authz", "llm-only", expected="safe", findings=[
            _off("authz", "safe", "authz:1"), _off("sqli", "vulnerable", "sqli:7")])
        assert (safe["outcome"], safe["predicted"]) == ("TN", "safe")
        vulnerable = _scored("b", "authz", "llm-only",
                             findings=[_off("sqli", "vulnerable", "sqli:7")])
        assert vulnerable["outcome"] == "FN"

    def test_summary_lists_the_off_category_finding(self):
        rows = [
            _scored("a", "authz", "llm-only", expected="safe", findings=[
                _off("authz", "safe", "authz:2"), _off("sqli", "vulnerable", "sqli:7")]),
            _scored("b", "authz", "llm-only", findings=[_off("authz", "vulnerable", "authz:1")]),
        ]
        summary = evaluate.summarize(rows)
        listed = json.dumps(_find_key(summary, "off_category"))
        assert "sqli:7" in listed
        assert "authz:1" not in listed
        assert (summary["overall"]["tp"], summary["overall"]["tn"]) == (1, 1)


class TestRunRecordsInCaseResults:
    RECORDS = [
        {"section": "s-1", "raw_answer": "answer one",
         "tool_calls": [{"tool": "read_file", "args": {"path": "app.py"}}]},
        {"section": "s-2", "raw_answer": "partial", "limit_hit": "tool_calls",
         "tool_calls": [{"tool": "grep", "args": {"pattern": "owner"}}] * 3},
        {"section": "investigator", "raw_answer": "", "limit_hit": "steps"},
    ]

    @staticmethod
    def _evaluate(monkeypatch, records):
        from lgtm.agents.base import RunRecord

        class Pipeline:
            def __init__(self, repo, config):
                pass

            def run(self, base, pr, output_dir=None):
                return SimpleNamespace(
                    findings=[], meta=ReviewMetadata(),
                    run_records=[RunRecord(**r) for r in records])

        monkeypatch.setattr(evaluate, "build_case_repo", lambda tmp, patch: None)
        monkeypatch.setattr(evaluate, "index_repo_docs", lambda tmp, cfg: 0)
        monkeypatch.setattr(evaluate, "run_pin", lambda *a, **k: {"code_sha": "abc"})
        monkeypatch.setattr(evaluate, "ReviewPipeline", Pipeline)
        monkeypatch.setattr(evaluate, "record_input_tokens", lambda p, c: {})
        case = {"id": "c", "category": "authz", "split": "dev",
                "expected_verdict": "safe", "patch_file": "x.patch"}
        return evaluate.evaluate_case(case, LGTMConfig(mode="lgtm"))

    def test_each_section_run_keeps_tool_calls_and_raw_answer(self, monkeypatch):
        row = self._evaluate(monkeypatch, self.RECORDS)
        runs = {r["section"]: r for r in row["run_records"]}
        assert set(runs) == {"s-1", "s-2", "investigator"}
        assert runs["s-1"]["tool_calls"] == [{"tool": "read_file", "args": {"path": "app.py"}}]
        assert runs["s-1"]["raw_answer"] == "answer one"
        assert len(runs["s-2"]["tool_calls"]) == 3

    def test_limit_hit_names_the_limit_and_the_section(self, monkeypatch):
        row = self._evaluate(monkeypatch, self.RECORDS)
        hits = {r["section"]: r["limit_hit"] for r in row["run_records"]}
        assert hits == {"s-1": None, "s-2": "tool_calls", "investigator": "steps"}

    def test_run_records_are_plain_json_objects(self, monkeypatch):
        row = self._evaluate(monkeypatch, self.RECORDS)
        assert json.loads(json.dumps(row))["run_records"] == row["run_records"]

    def test_existing_keys_are_kept(self, monkeypatch):
        row = self._evaluate(monkeypatch, self.RECORDS)
        for key in ("id", "category", "expected", "findings", "mode", "pin", "coverage",
                    "outcome", "case_label", "semgrep_findings_total", "graph_state"):
            assert key in row


class TestRescoreOfResultsWrittenBeforeScope:
    def test_rescore_succeeds_and_counts_rows_without_scope_as_in_scope(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            evaluate, "run_pin", lambda *a, **k: pytest.fail("no pin on rescore"))
        out = tmp_path / "run"
        out.mkdir()
        cases = [
            {"id": "a", "category": "authz", "split": "dev", "expected_verdict": "vulnerable",
             "file": ROW_FILE, "vulnerable_locations": [LOCATION], "diff_shape": "single_hunk"},
            {"id": "b", "category": "authz", "split": "dev", "expected_verdict": "safe"},
        ]
        old = _case_row("a", "vulnerable", findings=[_f("authz", "vulnerable")],
                        coverage=_coverage([_target_section()]), mode="lgtm")
        (out / "a.json").write_text(json.dumps(old), encoding="utf-8")
        (out / "b.json").write_text(json.dumps({
            "id": "b", "category": "authz", "expected": "safe",
            "findings": [_f("authz", "safe")], "latency_seconds": 1, "est_tokens": 1,
        }), encoding="utf-8")
        (out / "summary.json").write_text(json.dumps({
            "mode": "lgtm", "model": "m",
            "outcomes": {"a": "TP", "b": "TN"}, "summary": {},
        }), encoding="utf-8")

        evaluate.rescore(out, cases, "lgtm")

        saved = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        overall = saved["summary"]["overall"]
        assert (overall["cases"], overall["tp"], overall["tn"]) == (2, 1, 0)
        assert saved["outcomes"] == {"a": "TP", "b": "UNKNOWN"}


class TestIsJudgedRow:
    @staticmethod
    def _row(findings, mode="lgtm", pin=True):
        row = {"mode": mode, "findings": findings}
        if pin:
            row["pin"] = {"code_sha": "abc"}
        return row

    def test_row_without_a_pin_is_not_judged(self):
        assert evaluate.is_judged_row(self._row([_s("authz", True)], pin=False)) is False

    @pytest.mark.parametrize("mode", ["llm-only"])
    def test_baseline_modes_are_not_judged(self, mode):
        assert evaluate.is_judged_row(self._row([_s("authz", True)], mode=mode)) is False

    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_verdict_only_findings_on_a_pinned_row_are_not_judged(self, mode):
        findings = [_f("authz", "vulnerable"), _f("authz", "safe")]
        row = self._row(findings, mode=mode)
        assert evaluate.is_judged_row(row) is False
        assert evaluate.score_case(dict(row, category="authz", expected="vulnerable",
                                        latency_seconds=1.0, est_tokens=1))["outcome"] == "TP"

    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_supported_and_judged_findings_are_judged(self, mode):
        assert evaluate.is_judged_row(self._row([_s("authz", True), _s("authz", False)], mode=mode))

    @pytest.mark.parametrize("findings", [
        [{"category": "authz", "supported": False}],
        [{"category": "authz", "verdict": "vulnerable", "judged": False}],
    ])
    def test_a_finding_with_supported_or_judged_keeps_the_row_judged(self, findings):
        assert evaluate.is_judged_row(self._row(findings))

    def test_empty_findings_on_a_pinned_judged_row_stay_judged(self):
        assert evaluate.is_judged_row(self._row([])) is True

    def test_one_verdict_only_finding_among_judged_ones_makes_the_row_not_judged(self):
        assert evaluate.is_judged_row(self._row([_s("authz", True), _f("authz", "vulnerable")])) is False


class TestBenchmarkConditions:
    @pytest.mark.parametrize("mode", ["sast-only", "lgtm-no-sast", "policy"])
    def test_evaluate_rejects_dropped_modes(self, monkeypatch, mode, capsys):
        monkeypatch.setattr("sys.argv", ["evaluate.py", "--mode", mode])
        with pytest.raises(SystemExit) as exc:
            evaluate.main()
        assert exc.value.code == 2
        assert "invalid choice" in capsys.readouterr().err

    @pytest.mark.parametrize("script,args", [
        ("real_world/evaluate_real.py", ["--modes"]),
        ("field_trial/run_field_trial.py", ["--modes"]),
    ])
    @pytest.mark.parametrize("mode", ["sast-only", "lgtm-no-sast", "policy"])
    def test_other_benchmarks_reject_dropped_modes(self, monkeypatch, script, args, mode, capsys):
        path = Path(__file__).resolve().parent.parent / "benchmark" / script
        spec = importlib.util.spec_from_file_location("bench_cond_" + path.stem, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        monkeypatch.setattr("sys.argv", [path.name, *args, mode])
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 2
        assert "invalid choice" in capsys.readouterr().err

    def test_real_world_has_no_variants_option(self, monkeypatch, capsys):
        path = Path(__file__).resolve().parent.parent / "benchmark" / "real_world" / "evaluate_real.py"
        spec = importlib.util.spec_from_file_location("bench_cond_real", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert set(mod.MODES) == {"lgtm", "llm-only"}
        monkeypatch.setattr("sys.argv", [path.name, "--variants", "own"])
        with pytest.raises(SystemExit) as exc:
            mod.main()
        assert exc.value.code == 2

    def test_field_trial_modes_and_default(self):
        path = Path(__file__).resolve().parent.parent / "benchmark" / "field_trial" / "run_field_trial.py"
        spec = importlib.util.spec_from_file_location("bench_cond_ft", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert set(mod.MODES) == {"lgtm", "llm-only"}


def _flat(summary: dict, prefix: str = "") -> dict:
    flat = {}
    for key, value in summary.items():
        if isinstance(value, dict):
            flat.update(_flat(value, f"{prefix}{key}."))
        else:
            flat[f"{prefix}{key}"] = value
    return flat


def _count_values(summary: dict, *words: str, exclude=("rate", "safe", "unit", "mean")) -> set:
    """Ints under summary keys naming all of `words`; key names are not fixed by the contract."""
    return {
        v for k, v in _flat(summary).items()
        if all(w in k.lower() for w in words)
        and not any(x in k.lower() for x in exclude)
        and isinstance(v, int) and not isinstance(v, bool)
    }


def _tool_run(section, n):
    return {"section": section, "tool_calls": [{"tool": "read_file", "args": {}}] * n,
            "raw_answer": "", "limit_hit": None}


class TestFramingCounts:
    def _row(self, cid, mode, verdict, **extra):
        return evaluate.score_case(_case_row(
            cid, "vulnerable", mode=mode, raw=True,
            coverage=_coverage([_target_section()]),
            findings=[_f("authz", verdict)], **extra))

    @pytest.mark.parametrize("mode", ["lgtm", "llm-only"])
    def test_summary_counts_possible_verdicts_per_condition(self, mode):
        rows = [self._row("p1", mode, "possible"), self._row("p2", mode, "possible"),
                self._row("v1", mode, "vulnerable"), self._row("s1", mode, "safe")]

        assert 2 in _count_values(evaluate.summarize(rows), "possible")

    def test_lgtm_summary_counts_investigator_and_reviewer_tool_calls(self):
        runs = [_tool_run("investigator", 3), _tool_run("s1", 2), _tool_run("s2", 4)]
        rows = [self._row("v1", "lgtm", "vulnerable", run_records=runs)]
        rows[0]["coverage"]["investigator_tool_calls"] = 3

        summary = evaluate.summarize(rows)

        assert _count_values(summary, "investigator", "tool") == {3}
        assert _count_values(summary, "reviewer", "tool") == {6}

    def test_summary_counts_sast_triage_tool_calls_apart_from_reviewer(self):
        runs = [_tool_run("investigator", 1), _tool_run("s1", 2), _tool_run("route:users:12", 4),
                _tool_run("sast_triage:rule.x:app.py:10", 8),
                _tool_run("sast_triage:rule.y:app.py:20", 16)]
        rows = [self._row("v1", "lgtm", "vulnerable", run_records=runs)]

        tool_calls = evaluate.summarize(rows)["tool_calls"]

        assert tool_calls["investigator"]["total"] == 1
        assert tool_calls["reviewer"]["total"] == 6
        assert tool_calls["reviewer"]["per_unit_mean"] == 3
        assert tool_calls["sast_triage"] == {
            "total": 24, "per_case_mean": 24, "per_unit_mean": 12}

    def test_llm_only_summary_reports_zero_tool_calls(self):
        summary = evaluate.summarize([self._row("p1", "llm-only", "possible")])

        assert _count_values(summary, "investigator", "tool") == {0}
        assert _count_values(summary, "reviewer", "tool") == {0}
