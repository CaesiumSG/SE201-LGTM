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

from lgtm.agents.plain_reviewer import PlainLLMReviewer
from lgtm.agents.plain_reviewer import DEFAULT_CWE
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
        assert [(f.category, f.verdict) for f in findings] == [
            ("sqli", "vulnerable"), ("authz", "safe"),
        ]
        assert findings[0].line == 6 and findings[0].agent == "plain_llm"

    def test_category_inferred_from_cwe(self):
        raw = json.dumps({"assessments": [{"verdict": "vulnerable", "cwe_id": "CWE-89"}]})
        assert PlainLLMReviewer._parse(raw)[0].category == "sqli"

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
        assert sqli.evidence_valid is True  # snippet is in the PR's added lines


def _f(category, verdict, valid=True):
    return {"category": category, "verdict": verdict, "evidence_valid": valid}


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
                                 "findings": [_f("authz", "vulnerable", valid=False)],
                                 "latency_seconds": 1.0, "est_tokens": 10}),
            evaluate.score_case({"id": "b", "category": "authz", "split": "eval",
                                 "expected": "safe", "findings": [_f("authz", "safe")],
                                 "latency_seconds": 1.0, "est_tokens": 10}),
        ]
        assert rows[0]["outcome"] == "TP" and rows[0]["outcome_grounded"] == "FN"
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
        "--model", "qwen2.5:7b", "--mode", "lgtm-no-sast",
    ]
    if experiments:
        argv.extend(["--require-tool-use", "--static-facts", "--authz-role-guidance"])
    monkeypatch.setattr("sys.argv", argv)

    evaluate.main()

    assert config.ollama_base_url == "http://127.0.0.1:11435"
    assert config.ollama_model == "qwen2.5:7b"
    assert config.mode == "lgtm-no-sast"
    assert config.require_tool_use is experiments
    assert config.static_facts is experiments
    assert config.authz_role_guidance is experiments
    assert summary.call_args.args[4]["experiments"] == {
        "require_tool_use": experiments,
        "static_facts": experiments,
        "authz_role_guidance": experiments,
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
        }))
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
        assert saved["outcomes"] == {"a": "TP", "b": "ERROR"}

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
        assert row["outcome"] == "TN"
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
        "verdict": "insufficient_evidence", "evidence_valid": False,
        "explanation": explanation,
    }


class TestErrorAccounting:
    @staticmethod
    def _row(cid="a", expected="vulnerable", category="authz", findings=None,
             latency=1.0, tokens=10, **extra):
        if findings is None:
            findings = [_f(category, "vulnerable" if expected == "vulnerable" else "safe")]
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
        legacy = self._tn("b")
        legacy["findings"].append(_infra_finding("authz:9"))
        legacy.pop("infra_failures", None)
        legacy.pop("infra_failure_ids", None)
        assert legacy["outcome"] == "TN"
        summary = evaluate.summarize([self._tp("a"), legacy])
        assert summary["overall"]["tn"] == 0
        assert summary["overall"]["scored"] == 1
        assert summary["overall"]["errors"] == 1
        assert summary["error_cases"][0]["id"] == "b"

    def test_legacy_error_row_with_tn_outcome_is_excluded(self):
        legacy = self._tn("b", findings=[])
        legacy["predicted"] = "error"
        assert legacy["outcome"] == "TN"
        summary = evaluate.summarize([self._tp("a"), legacy])
        assert summary["overall"]["tn"] == 0
        assert summary["overall"]["accuracy"] == 1.0
        assert summary["overall"]["errors"] == 1

    def test_grounded_only_excludes_errors(self):
        legacy = self._tp("b", findings=[])
        legacy["predicted"] = "error"
        assert legacy["outcome_grounded"] == "FN"
        summary = evaluate.summarize([self._tp("a"), legacy])
        grounded = summary["grounded_only"]
        assert grounded["overall"]["fn"] == 0
        assert grounded["overall"]["scored"] == 1
        assert grounded["overall"]["errors"] == 1
        assert grounded["per_category"]["authz"]["fn"] == 0
        assert grounded["per_split"]["dev"]["errors"] == 1

    def test_summary_outcomes_marks_errors(self, tmp_path):
        legacy = self._tp("c", findings=[])
        legacy["predicted"] = "error"
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
        return {
            "id": cid, "category": "authz", "split": "dev", "expected": expected,
            "n_findings": 1, "verdicts": [verdict], "grounded": 1, "grounding_rate": 1.0,
            "latency_seconds": 1.0, "est_tokens": 10,
            "findings": [_f("authz", verdict)] if findings is None else findings,
        }

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
                   "--mode", "lgtm-no-sast")

        manifest = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert manifest["pin"] == _pin_for("m:1", "lgtm-no-sast", True)
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
        assert evaluate.is_done(empty) is True
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
        assert [(f.category, f.verdict) for f in findings] == [
            ("sqli", "vulnerable"), ("authz", "safe"),
        ]

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
        assert [(f.category, f.verdict) for f in findings] == [
            ("sqli", "vulnerable"), ("authz", "safe"),
        ]
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
        "verdicts": [], "finding_ids": [], "error": None,
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


def _case_row(cid="c", expected="vulnerable", findings=(), coverage="absent",
              mode="lgtm", locations="default", file=ROW_FILE, split="dev",
              **extra):
    """`locations=None` omits the vulnerable_locations key."""
    row = {
        "id": cid, "category": "authz", "split": split, "expected": expected,
        "findings": copy.deepcopy(list(findings)), "latency_seconds": 1.0,
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
            findings=[_f("authz", "possible")], coverage=complete),
        "insufficient_evidence": dict(
            findings=[_f("authz", "insufficient_evidence")], coverage=complete),
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


COVERAGE_MODES = ["lgtm", "lgtm-no-sast"]
ALL_LABELS = [
    "detected_vulnerability", "possible_vulnerability", "insufficient_evidence",
    "explicit_safe", "missing_review", "no_candidate", "scan_failure",
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
        ("possible_vulnerability", "possible"),
        ("insufficient_evidence", "insufficient_evidence"),
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
        assert _label(findings=[_f("authz", "safe")], coverage=_coverage([])) == "no_candidate"

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
        ([_f("authz", "possible"), _f("authz", "insufficient_evidence"),
          _f("authz", "safe")], "possible_vulnerability"),
        ([_f("authz", "insufficient_evidence"), _f("authz", "safe")], "explicit_safe"),
    ])
    @pytest.mark.parametrize("mode", COVERAGE_MODES)
    def test_non_vulnerable_verdict_precedence_in_coverage_modes(
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

    @pytest.mark.parametrize("mode", COVERAGE_MODES + ["llm-only", "sast-only"])
    @pytest.mark.parametrize("verdict", ["possible", "insufficient_evidence", "safe"])
    def test_coverage_gap_is_false_for_non_detected_labels(self, mode, verdict):
        cov = _coverage([_target_section()], hunks_leftover=3, complete=False)
        kwargs = {} if mode in ("llm-only", "sast-only") else {"coverage": cov}
        row = evaluate.score_case(_case_row(
            mode=mode, findings=[_f("authz", verdict)], **kwargs))
        assert row["coverage_gap"] is False

    @pytest.mark.parametrize("label", [
        "missing_review", "no_candidate", "scan_failure"])
    def test_coverage_gap_is_false_for_unreviewed_labels(self, label):
        row = evaluate.score_case(_case_row(**_scenario(label)))
        assert row["coverage_gap"] is False

    @pytest.mark.parametrize("mode", ["llm-only", "sast-only"])
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
    @pytest.mark.parametrize("mode", ["llm-only", "sast-only"])
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
        row = evaluate.score_case(_case_row(expected="safe", findings=[], mode="sast-only"))
        assert row["outcome"] == "TN"
        assert row["case_label"] == "no_candidate"

    def test_no_relevant_finding_on_vulnerable_case_is_a_miss(self):
        row = evaluate.score_case(_case_row(expected="vulnerable", findings=[], mode="llm-only"))
        assert row["outcome"] == "FN"


class TestOutcomeTable:
    @pytest.mark.parametrize("label,vulnerable_outcome,safe_outcome", [
        ("detected_vulnerability", "TP", "FP"),
        ("possible_vulnerability", "FN", "TN"),
        ("insufficient_evidence", "FN", "TN"),
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

    @pytest.mark.parametrize("expected,plain,grounded", [
        ("vulnerable", "TP", "FN"), ("safe", "FP", "TN"),
    ])
    def test_ungrounded_vulnerable_is_downgraded_to_possible_in_grounded_label(
            self, expected, plain, grounded):
        row = evaluate.score_case(_case_row(
            expected=expected, coverage=_coverage([_target_section()]),
            findings=[_f("authz", "vulnerable", valid=False)]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "possible_vulnerability"
        assert row["outcome"] == plain
        assert row["outcome_grounded"] == grounded

    def test_grounded_label_stays_detected_with_one_valid_vulnerable_finding(self):
        row = evaluate.score_case(_case_row(
            coverage=_coverage([_target_section()]),
            findings=[_f("authz", "vulnerable"), _f("authz", "vulnerable", valid=False)]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "detected_vulnerability"
        assert row["outcome_grounded"] == "TP"

    def test_grounded_label_prefers_a_valid_possible_over_an_invalid_vulnerable(self):
        row = evaluate.score_case(_case_row(
            coverage=_coverage([_target_section()]),
            findings=[_f("authz", "vulnerable", valid=False), _f("authz", "possible")]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "possible_vulnerability"

    def test_grounded_downgrade_applies_in_findings_only_modes(self):
        row = evaluate.score_case(_case_row(
            mode="llm-only", findings=[_f("authz", "vulnerable", valid=False)]))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "possible_vulnerability"


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
            findings=[dict(_f("sqli", "possible"), file="app/db.py")],
            coverage=_coverage([_target_section()])))
        assert row["case_label"] == "possible_vulnerability"

    def test_sqli_grounded_label_downgrades_an_ungrounded_detection(self):
        row = evaluate.score_case(_case_row(
            category="sqli", findings=[_f("sqli", "vulnerable", valid=False)],
            coverage=_coverage([_target_section()])))
        assert row["case_label"] == "detected_vulnerability"
        assert row["case_label_grounded"] == "possible_vulnerability"

    def test_sqli_row_without_coverage_is_a_scan_failure(self):
        row = evaluate.score_case(_case_row(
            category="sqli", findings=[_f("sqli", "vulnerable")], coverage=None))
        assert row["case_label"] == "scan_failure"


class TestSastErrorRows:
    @pytest.mark.parametrize("mode", ["lgtm", "sast-only"])
    def test_row_with_a_sast_error_is_an_error(self, mode):
        coverage = {"coverage": _coverage([_target_section()])} if mode == "lgtm" else {}
        row = evaluate.score_case(_case_row(
            mode=mode, category="sqli", findings=[_f("sqli", "safe")],
            sast_error="semgrep timed out after 60s", **coverage))
        assert evaluate.result_is_error(row)
        assert row["outcome"] == "ERROR"
        assert row["error"] == "SAST failed: semgrep timed out after 60s"
        assert row["case_label"] == "scan_failure"

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
            "sast_error": "semgrep exited 2", "semgrep_findings_total": 0}

    @pytest.mark.parametrize("review", [None, SimpleNamespace(meta=SimpleNamespace())])
    def test_sast_fields_default_for_missing_metadata(self, review):
        assert evaluate.sast_fields(review) == {
            "sast_error": None, "semgrep_findings_total": None}

    def test_error_record_carries_the_sast_fields(self):
        review = SimpleNamespace(meta=ReviewMetadata(
            sast_error="semgrep exited 2", semgrep_findings_total=0))
        case = {"id": "c", "category": "sqli", "expected_verdict": "vulnerable"}
        rec = evaluate.error_record(case, "sast-only", {}, review)
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

    def test_per_category_and_per_split_use_the_new_metrics(self):
        summary = evaluate.summarize(self._mixed_rows())
        assert summary["per_split"]["dev"]["excluded_on_safe"] == 0
        assert summary["per_split"]["dev"]["abstentions"] == 4
        assert summary["per_category"]["authz"]["safe_scored"] == 7

    def test_grounded_only_uses_the_grounded_outcome(self):
        cov = _coverage([_target_section()])
        rows = [
            evaluate.score_case(_case_row(
                "v", "vulnerable", coverage=cov,
                findings=[_f("authz", "vulnerable", valid=False)])),
            evaluate.score_case(_case_row(
                "s", "safe", coverage=cov,
                findings=[_f("authz", "vulnerable", valid=False)])),
        ]
        summary = evaluate.summarize(rows)
        assert (summary["overall"]["tp"], summary["overall"]["fp"]) == (1, 1)
        grounded = summary["grounded_only"]["overall"]
        assert (grounded["tp"], grounded["fp"], grounded["fn"]) == (0, 0, 1)

    def test_grounded_only_metrics_use_the_grounded_label(self):
        cov = _coverage([_target_section()])
        rows = [
            evaluate.score_case(_case_row(
                "s", "safe", coverage=cov,
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
                "ungrounded", "safe", coverage=gappy,
                findings=[_f("authz", "vulnerable", valid=False)])),
            evaluate.score_case(_case_row(
                "tn", "safe", coverage=gappy, findings=[_f("authz", "safe")])),
            evaluate.score_case(_case_row(
                "clean", "safe", **_scenario("detected_vulnerability"))),
        ]
        assert evaluate.summarize(rows)["coverage"]["detected_with_gap"] == 3

    def test_legacy_rows_count_in_outcome_metrics_but_not_label_metrics(self):
        safe = evaluate.score_case({
            "id": "ls", "category": "authz", "split": "dev", "expected": "safe",
            "findings": [_f("authz", "possible")], "latency_seconds": 1.0,
            "est_tokens": 10})
        vuln = evaluate.score_case({
            "id": "lv", "category": "authz", "split": "dev", "expected": "vulnerable",
            "findings": [_f("authz", "vulnerable")], "latency_seconds": 1.0,
            "est_tokens": 10})
        assert safe["case_label"] is None
        overall = evaluate.summarize([safe, vuln])["overall"]
        assert (overall["safe_scored"], overall["vulnerable_scored"]) == (1, 1)
        assert overall["excluded_on_safe"] == 0
        assert overall["abstentions"] == 0
        assert overall["possible_on_safe"] == 0

    def test_row_with_mode_and_coverage_but_no_pin_is_legacy(self):
        raw = _case_row(
            expected="vulnerable", coverage=_coverage([_target_section()]),
            findings=[_f("authz", "vulnerable")])
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

    def test_legacy_rows_keep_legacy_marker_and_scoring(self):
        row = _legacy_row()
        assert row["legacy"] is True
        assert row["case_label"] is None
        assert row["outcome"] == "TN"
        summary = evaluate.summarize([row])
        assert summary["legacy_rows"] == 1
        assert summary["case_labels"] == {"legacy": 1}
        assert summary["overall"]["accuracy"] == 1.0
        assert summary["coverage"]["rows"] == 0

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
