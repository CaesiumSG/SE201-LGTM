"""Tests for the plain LLM-only baseline and the benchmark scoring rules."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from lgtm.agents.plain_reviewer import PlainLLMReviewer
from lgtm.agents.plain_reviewer import DEFAULT_CWE
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import parse_unified_diff
from lgtm.pipeline import ReviewPipeline

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
             "split": "dev", "patch_file": f"patches/{cid}.patch"}
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
        assert set(manifest) == {"model", "ollama_base_url", "reasoning", "mode"}
        assert manifest["model"] == "m:1"
        assert manifest["ollama_base_url"] == "http://127.0.0.1:11435"
        assert manifest["reasoning"] is False
        assert manifest["mode"] == "lgtm"

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
