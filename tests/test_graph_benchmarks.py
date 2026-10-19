"""Benchmark consumers carry the graph metadata of each review onto new case
records, count graph states in summaries and leave historical results alone.
Fake review results only: no model, network, CodeGraph or Semgrep."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.reporting.report_builder import ReviewMetadata

BENCH = Path(__file__).resolve().parent.parent / "benchmark"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ev = _load("gb_evaluate", BENCH / "evaluate.py")
inj = _load("gb_injection", BENCH / "injection" / "run_injection_bench.py")

FIELDS = ("graph_state", "graph_index_seconds", "base_sha", "pr_sha")
BASE40, PR40 = "a" * 40, "b" * 40
SUMMARY_KEYS = {
    "overall", "per_category", "per_split", "grounded_only", "scored", "errors",
    "error_rate", "error_cases", "off_category_alarm_rate", "off_category_alarms",
    "evidence_grounding_rate", "possible_rate", "insufficient_evidence_rate",
    "median_latency_seconds", "median_est_tokens_per_pr",
}


class FakeFinding:
    def __init__(self, verdict="vulnerable", category="sqli", explanation="ok"):
        self.data = {"finding_id": f"{category}:1", "category": category,
                     "verdict": verdict, "evidence_valid": True,
                     "explanation": explanation}

    def model_dump(self, exclude=None):
        return dict(self.data)


def meta(state="ok", seconds=1.5, base=BASE40, pr=PR40):
    return ReviewMetadata(graph_state=state, graph_index_seconds=seconds,
                          base_sha=base, pr_sha=pr)


def review(m=None, findings=None):
    return SimpleNamespace(
        findings=[FakeFinding()] if findings is None else findings,
        meta=m if m is not None else meta())


class Script:
    """Fake ReviewPipeline class replaying one scripted outcome per run()."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.cleaned = 0

    def __call__(self, repo, config):
        return self

    def run(self, base, pr, output_dir=None):
        step = self.steps.pop(0)
        try:
            if isinstance(step, BaseException):
                raise step
            return step
        finally:
            self.cleaned += 1


def case(cid="sqli_01_vulnerable", expected="vulnerable"):
    return {"id": cid, "category": "sqli", "split": "dev",
            "expected_verdict": expected, "patch_file": "x.patch"}


def run_exit(fn, *args):
    """Exit code of a harness main; a leaked KeyboardInterrupt must not abort pytest."""
    try:
        ret = fn(*args)
    except SystemExit as exc:
        return exc.code
    except KeyboardInterrupt:
        return "KeyboardInterrupt propagated"
    return ret


def write_labels(tmp_path, cases):
    path = tmp_path / "labels.json"
    path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return path


@pytest.fixture
def synthetic(monkeypatch):
    monkeypatch.setattr(ev, "build_case_repo", lambda tmp, patch: None)
    monkeypatch.setattr(ev, "index_repo_docs", lambda tmp, cfg: 0)

    def install(*steps):
        script = Script(*steps)
        monkeypatch.setattr(ev, "ReviewPipeline", script)
        return script
    return install


@pytest.fixture
def injection(monkeypatch):
    monkeypatch.setattr(inj, "build_case_repo", lambda tmp, patch: None)
    monkeypatch.setattr(inj, "index_repo_docs", lambda tmp, cfg: 0)

    def install(*steps):
        script = Script(*steps)
        monkeypatch.setattr(inj, "ReviewPipeline", script)
        return script
    return install


def legacy(cid, outcome="TP", expected="vulnerable", predicted="vulnerable"):
    return {
        "id": cid, "category": "sqli", "split": "dev", "expected": expected,
        "predicted": predicted, "outcome": outcome,
        "correct": outcome in ("TP", "TN"), "predicted_grounded": predicted,
        "outcome_grounded": outcome, "n_findings": 1, "verdicts": [predicted],
        "grounded": 1, "grounding_rate": 1.0, "latency_seconds": 1.0,
        "est_tokens": 10, "findings": [FakeFinding(predicted).data],
    }


class TestSyntheticRecords:
    def test_new_record_copies_review_metadata(self, synthetic):
        synthetic(review(meta("degraded:pr:timeout", 12.34)))
        rec = ev.evaluate_case(case(), ev.LGTMConfig())
        assert rec["graph_state"] == "degraded:pr:timeout"
        assert rec["graph_index_seconds"] == 12.34
        assert rec["base_sha"] == BASE40 and rec["pr_sha"] == PR40

    def test_baseline_metadata_is_null_null_empty_empty(self, synthetic):
        synthetic(review(meta(None, None, "", "")))
        rec = ev.evaluate_case(case(), ev.LGTMConfig())
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == (None, None, "", "")

    def test_metadata_without_graph_fields_gets_defaults(self, synthetic):
        synthetic(review(SimpleNamespace(semgrep_findings_in_diff=0)))
        rec = ev.evaluate_case(case(), ev.LGTMConfig())
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == (None, None, "", "")

    def test_infra_failure_record_keeps_available_metadata(self, synthetic):
        bad = FakeFinding(explanation="LLM call failed: boom")
        synthetic(review(meta("ok", 2.0), [bad]))
        rec = ev.evaluate_case(case(), ev.LGTMConfig())
        assert rec["outcome"] == "ERROR"
        assert rec["graph_state"] == "ok" and rec["pr_sha"] == PR40

    def test_error_before_metadata_records_nulls_in_main(
            self, synthetic, monkeypatch, tmp_path):
        synthetic(RuntimeError("boom"))
        labels = write_labels(tmp_path, [case()])
        out = tmp_path / "out"
        monkeypatch.setattr(sys, "argv", [
            "evaluate.py", "--mode", "sast-only", "--labels", str(labels),
            "--output", str(out)])
        ev.main()
        rec = json.loads((out / "sqli_01_vulnerable.json").read_text("utf-8"))
        assert rec["outcome"] == "ERROR"
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == (None, None, "", "")


class TestSummaryGraphStates:
    def test_counts_by_state_with_missing_and_null_as_unknown(self):
        rows = [
            {**legacy("a"), "graph_state": "ok"},
            {**legacy("b"), "graph_state": "degraded:pr:timeout"},
            {**legacy("c"), "graph_state": "degraded:pr:timeout"},
            {**legacy("d"), "graph_state": None},
            legacy("e"),
        ]
        counts = ev.summarize(rows)["graph_states"]
        assert counts == {"ok": 1, "degraded:pr:timeout": 2, "unknown": 2}

    def test_historical_results_are_never_graph_ok(self):
        summary = ev.summarize([legacy("a"), legacy("b", "TN", "safe", "safe")])
        assert summary["graph_states"] == {"unknown": 2}

    def test_existing_summary_keys_are_kept(self):
        summary = ev.summarize([legacy("a")])
        assert SUMMARY_KEYS <= set(summary)
        assert summary["overall"]["tp"] == 1 and summary["scored"] == 1

    def test_write_summary_payload_carries_graph_states(self, tmp_path):
        ev.write_summary(tmp_path, [{**legacy("a"), "graph_state": "ok"}],
                         "lgtm", "m")
        payload = json.loads((tmp_path / "summary.json").read_text("utf-8"))
        assert payload["summary"]["graph_states"] == {"ok": 1}
        assert payload["outcomes"] == {"a": "TP"}


class TestHistoricalResults:
    def _saved_run(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        for cid, outcome in (("sqli_01_vulnerable", "TP"), ("sqli_01_safe", "TN")):
            expected = "vulnerable" if outcome == "TP" else "safe"
            rec = legacy(cid, outcome, expected, expected)
            (out / f"{cid}.json").write_text(json.dumps(rec), encoding="utf-8")
        return out, [case("sqli_01_vulnerable"), case("sqli_01_safe", "safe")]

    def test_rescore_adds_no_fields_to_old_records_and_counts_unknown(
            self, tmp_path):
        out, cases = self._saved_run(tmp_path)
        ev.rescore(out, cases, "lgtm")
        for c in cases:
            rec = json.loads((out / f"{c['id']}.json").read_text("utf-8"))
            assert not set(FIELDS) & set(rec)
            assert rec["outcome"] in ("TP", "TN")
        payload = json.loads((out / "summary.json").read_text("utf-8"))
        assert payload["summary"]["graph_states"] == {"unknown": 2}
        assert payload["summary"]["overall"]["scored"] == 2

    def test_rescore_preserves_new_fields(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        rec = {**legacy("sqli_01_vulnerable"), "graph_state": "ok",
               "graph_index_seconds": 3.0, "base_sha": BASE40, "pr_sha": PR40}
        (out / "sqli_01_vulnerable.json").write_text(json.dumps(rec), "utf-8")
        ev.rescore(out, [case()], "lgtm")
        saved = json.loads((out / "sqli_01_vulnerable.json").read_text("utf-8"))
        assert {k: saved[k] for k in FIELDS} == {k: rec[k] for k in FIELDS}
        payload = json.loads((out / "summary.json").read_text("utf-8"))
        assert payload["summary"]["graph_states"] == {"ok": 1}

    def test_resume_skips_historical_done_results_untouched(
            self, synthetic, monkeypatch, tmp_path):
        out, cases = self._saved_run(tmp_path)
        script = synthetic()
        labels = write_labels(tmp_path, cases)
        before = {p.name: p.read_text("utf-8") for p in out.glob("sqli_*.json")}
        monkeypatch.setattr(sys, "argv", [
            "evaluate.py", "--mode", "sast-only", "--labels", str(labels),
            "--output", str(out), "--resume"])
        ev.main()
        assert script.cleaned == 0
        assert {p.name: p.read_text("utf-8")
                for p in out.glob("sqli_*.json")} == before
        payload = json.loads((out / "summary.json").read_text("utf-8"))
        assert payload["summary"]["graph_states"] == {"unknown": 2}


class TestInjectionRecords:
    def test_single_case_record_carries_metadata(self, injection):
        injection(review(meta("ok", 4.0)))
        rec = inj.evaluate_single_case(case(), inj.LGTMConfig())
        assert rec["graph_state"] == "ok" and rec["graph_index_seconds"] == 4.0
        assert rec["base_sha"] == BASE40 and rec["pr_sha"] == PR40

    def test_single_case_error_has_nulls_and_no_invented_success(self, injection):
        injection(RuntimeError("boom"))
        rec = inj.evaluate_single_case(case(), inj.LGTMConfig())
        assert rec["predicted"].startswith("error")
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == (None, None, "", "")

    def test_summary_has_both_records_and_counts_two_per_pair(
            self, injection, monkeypatch, tmp_path):
        orig_pr, inj_pr = "c" * 40, "d" * 40
        injection(review(meta("ok", 1.0, BASE40, orig_pr)),
                  review(meta("degraded:pr:timeout", 2.0, BASE40, inj_pr)))
        out = tmp_path / "out"
        monkeypatch.setattr(sys, "argv", [
            "run_injection_bench.py", "--mode", "sast-only",
            "--cases", "inj_01_sqli_comment", "--output", str(out)])
        inj.main()
        summary = json.loads((out / "summary.json").read_text("utf-8"))
        assert len(summary["comparisons"]) == 1
        comp = json.dumps(summary["comparisons"][0])
        assert orig_pr in comp and inj_pr in comp
        assert "degraded:pr:timeout" in comp
        assert summary["graph_states"] == {"ok": 1, "degraded:pr:timeout": 1}


class TestInterruptExitsThree:
    def test_synthetic_harness(self, synthetic, monkeypatch, tmp_path):
        script = synthetic(review(), KeyboardInterrupt())
        labels = write_labels(tmp_path, [
            case("sqli_01_vulnerable"), case("sqli_01_safe", "safe")])
        out = tmp_path / "out"
        monkeypatch.setattr(sys, "argv", [
            "evaluate.py", "--mode", "sast-only", "--labels", str(labels),
            "--output", str(out)])
        assert run_exit(ev.main) == 3
        assert script.cleaned == 2
        assert (out / "sqli_01_vulnerable.json").exists()

    def test_injection_harness(self, injection, monkeypatch, tmp_path):
        script = injection(KeyboardInterrupt())
        monkeypatch.setattr(sys, "argv", [
            "run_injection_bench.py", "--mode", "sast-only", "--cases",
            "inj_01_sqli_comment", "--output", str(tmp_path / "out")])
        assert run_exit(inj.main) == 3
        assert script.cleaned == 1


class TestNoGraphSwitch:
    @pytest.mark.parametrize("module", [ev, inj], ids=["synthetic", "injection"])
    def test_help_has_no_graph_option(self, module, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["prog", "--help"])
        with pytest.raises(SystemExit):
            module.main()
        assert "graph" not in capsys.readouterr().out.lower()


class TestPostReviewFailureKeepsReviewMetadata:
    @staticmethod
    def _broken_review():
        class Broken(FakeFinding):
            def model_dump(self, exclude=None):
                raise RuntimeError("cannot serialise finding")
        return review(meta("degraded:pr:timeout", 7.5, BASE40, PR40),
                      findings=[Broken()])

    def test_synthetic_error_record_keeps_the_four_graph_fields(self, synthetic):
        synthetic(self._broken_review())
        rec = ev.evaluate_case(case(), ev.LGTMConfig())
        assert rec["outcome"] == "ERROR" and rec["error"]
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == (
            "degraded:pr:timeout", 7.5, BASE40, PR40)


class TestErrorRecordsInGraphStates:
    def test_summarize_counts_error_rows_under_state_or_unknown(self):
        rows = [
            {**legacy("a"), "graph_state": "ok"},
            ev.mark_error({**legacy("b"), "graph_state": "ok"}, "boom"),
            ev.mark_error({**legacy("c"), "graph_state": None}, "boom"),
        ]
        summary = ev.summarize(rows)
        assert summary["errors"] == 2
        assert summary["graph_states"] == {"ok": 2, "unknown": 1}


class TestInjectionSummaryUnknownState:
    def test_failed_review_is_counted_unknown_with_null_graph(
            self, injection, monkeypatch, tmp_path):
        injection(review(meta("ok", 1.0, BASE40, "c" * 40)),
                  RuntimeError("boom"))
        out = tmp_path / "out"
        monkeypatch.setattr(sys, "argv", [
            "run_injection_bench.py", "--mode", "sast-only",
            "--cases", "inj_01_sqli_comment", "--output", str(out)])
        inj.main()
        summary = json.loads((out / "summary.json").read_text("utf-8"))
        assert summary["graph_states"] == {"ok": 1, "unknown": 1}
        assert summary["comparisons"][0]["injected_graph"] == {
            "graph_state": None, "graph_index_seconds": None,
            "base_sha": "", "pr_sha": ""}
