"""No-network, no-model guards for benchmark/real_world/evaluate_real.py:
the planning, resume, index-skip, scrubbing and summary logic."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from lgtm.review.coverage import SectionResult, build_coverage
from lgtm.review.sections import Exclusion, HunkRef, ScanPlan, Section

RW = Path(__file__).resolve().parent.parent / "benchmark" / "real_world"
_spec = importlib.util.spec_from_file_location("rw_evaluate_real", RW / "evaluate_real.py")
er = importlib.util.module_from_spec(_spec)
sys.modules["rw_evaluate_real"] = er
_spec.loader.exec_module(er)


class TestScrub:
    def test_replaces_longest_path_first_in_nested_values(self):
        repl = [("C:\\Users\\bob", "<home>"), ("C:\\Users\\bob\\cache\\x", "<cache>")]
        obj = {"error": "git -C C:\\Users\\bob\\cache\\x failed",
               "list": ["C:\\Users\\bob\\y", 3]}
        assert er.scrub(obj, repl) == {
            "error": "git -C <cache> failed", "list": ["<home>\\y", 3]}

    def test_replacement_list_covers_both_slash_forms(self, tmp_path):
        pairs = dict(er.path_replacements(tmp_path / "cache", tmp_path / "out"))
        assert str(tmp_path / "cache") in pairs
        assert (tmp_path / "cache").as_posix() in pairs


class TestPlanning:
    def test_unit_counts_and_policy_only_where_it_applies(self):
        cases = er.fetch.load_cases()
        units = list(er.work_units(cases, list(er.MODES), ["own", "policy"]))
        own = [u for u in units if u[1] == "own"]
        policy = [(c["id"], m) for c, v, m in units if v == "policy"]
        assert len(own) == 12 * 4
        assert len(policy) == 6 * 2  # 6 authz cases x (lgtm, lgtm-no-sast)
        assert {m for _i, m in policy} == set(er.DOC_MODES)
        assert all("_authz_" in i for i, _m in policy)

    def test_resume_skips_existing_results(self, tmp_path):
        cases = er.fetch.load_cases()[:2]
        units = list(er.work_units(cases, ["sast-only"], ["own"]))
        out = er.out_dir_for(tmp_path, "sast-only", "own")
        out.mkdir(parents=True)
        (out / f"{cases[0]['id']}.json").write_text("{}", encoding="utf-8")
        resumed = [c["id"] for c, _v, _m in er.pending_units(units, tmp_path, True)]
        assert resumed == [cases[1]["id"]]
        assert len(list(er.pending_units(units, tmp_path, False))) == 2

    def test_resume_reruns_error_results(self, tmp_path):
        cases = er.fetch.load_cases()[:2]
        units = list(er.work_units(cases, ["sast-only"], ["own"]))
        out = er.out_dir_for(tmp_path, "sast-only", "own")
        out.mkdir(parents=True)
        done = TestResultsAndSummary._result(cases[0]["id"], "vulnerable", "TP")
        failed = {**TestResultsAndSummary._result(cases[1]["id"], "safe", "TN"),
                  "predicted": "error"}
        (out / f"{cases[0]['id']}.json").write_text(json.dumps(done), encoding="utf-8")
        (out / f"{cases[1]['id']}.json").write_text(json.dumps(failed), encoding="utf-8")
        resumed = [c["id"] for c, _v, _m in er.pending_units(units, tmp_path, True)]
        assert resumed == [cases[1]["id"]]

    def test_resume_reruns_unreadable_json(self, tmp_path):
        cases = er.fetch.load_cases()[:2]
        units = list(er.work_units(cases, ["sast-only"], ["own"]))
        out = er.out_dir_for(tmp_path, "sast-only", "own")
        out.mkdir(parents=True)
        done = TestResultsAndSummary._result(cases[1]["id"], "safe", "TN")
        (out / f"{cases[0]['id']}.json").write_text("{not json", encoding="utf-8")
        (out / f"{cases[1]['id']}.json").write_text(json.dumps(done), encoding="utf-8")
        resumed = [c["id"] for c, _v, _m in er.pending_units(units, tmp_path, True)]
        assert resumed == [cases[0]["id"]]

    @pytest.mark.parametrize("stored", [
        {"model": "other:1b", "reasoning": None},
        {"model": "x:1", "reasoning": True},
    ])
    def test_resume_refuses_different_model(self, tmp_path, monkeypatch, capsys, stored):
        cache = tmp_path / "cache"
        (cache / "aegra" / ".git").mkdir(parents=True)
        out = tmp_path / "out"
        out.mkdir()
        manifest = out / "run.json"
        manifest.write_text(json.dumps({
            "ollama_base_url": "http://127.0.0.1:11435", "mode": None,
            "modes": ["lgtm"], **stored}), encoding="utf-8")
        ran = []
        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        monkeypatch.setattr(er, "run_unit", lambda *a, **k: ran.append(a))

        with pytest.raises(SystemExit) as exc:
            er.main(["--resume", "--cache", str(cache), "--output", str(out),
                     "--modes", "lgtm", "--variants", "own",
                     "--cases", "aegra_authz_safe", "--model", "x:1"])

        assert exc.value.code == 2
        assert "different model or reasoning setting" in capsys.readouterr().err
        assert ran == []
        assert [p.name for p in out.rglob("*.json")] == ["run.json"]

    def test_expected_ids_per_directory(self):
        cases = er.fetch.load_cases()
        assert len(er.expected_ids(cases, "lgtm", "own")) == 12
        assert len(er.expected_ids(cases, "lgtm", "policy")) == 6
        assert er.expected_ids(cases, "llm-only", "policy") == set()


class TestIndexMarker:
    def _repo(self, tmp_path):
        repo = tmp_path / "proj"
        repo.mkdir()
        ident = {"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@t.local",
                 "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t.local"}
        g = lambda *a: er.fetch.git(repo, *a, env=ident)  # noqa: E731
        g("init", "-q", "-b", "main")
        (repo / "a.md").write_text("doc\n", encoding="utf-8", newline="\n")
        g("add", "-A")
        g("commit", "-q", "-m", "one")
        return repo, g

    def test_builds_once_then_reuses_and_rebuilds_on_new_base(self, tmp_path):
        repo, g = self._repo(tmp_path)
        calls: list[str] = []

        def fake_index(clone, cfg):
            calls.append(cfg.chroma_persist_dir)
            return 7

        idx = tmp_path / "idx"
        cfg = er.LGTMConfig()
        first = er.ensure_index(repo, "main", idx, cfg, index_fn=fake_index)
        again = er.ensure_index(repo, "main", idx, cfg, index_fn=fake_index)
        assert len(calls) == 1 and calls[0] == str(idx)
        assert first["reused"] is False and again["reused"] is True
        assert again["chunks"] == 7

        (repo / "a.md").write_text("changed\n", encoding="utf-8", newline="\n")
        g("add", "-A")
        g("commit", "-q", "-m", "two")
        er.ensure_index(repo, "main", idx, cfg, index_fn=fake_index)
        assert len(calls) == 2  # base moved, the old index is not trusted

    def test_does_not_mutate_the_callers_config(self, tmp_path):
        repo, _g = self._repo(tmp_path)
        cfg = er.LGTMConfig()
        before = cfg.chroma_persist_dir
        er.ensure_index(repo, "main", tmp_path / "idx", cfg, index_fn=lambda c, k: 1)
        assert cfg.chroma_persist_dir == before


class TestIndexOnlyNeverWritesResults:
    """Regression: an --index-only failure fell through to the normal result
    path and wrote an *error case result*, which --resume then skipped."""

    def test_failure_is_printed_not_recorded(self, tmp_path, monkeypatch, capsys):
        cache = tmp_path / "cache"
        (cache / "aegra" / ".git").mkdir(parents=True)
        out = tmp_path / "out"

        def boom(*args, **kwargs):
            raise ValueError("Batch size of 6011 is greater than max batch size of 5461")

        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        monkeypatch.setattr(er, "run_unit", boom)
        code = er.main(["--cache", str(cache), "--output", str(out), "--modes", "lgtm",
                        "--variants", "own", "--cases", "aegra_authz_safe",
                        "--index-only"])
        assert code == 0
        assert "ERROR" in capsys.readouterr().out
        assert not list(out.rglob("*.json"))

    def test_normal_run_still_records_a_crash_as_a_result(self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        (cache / "aegra" / ".git").mkdir(parents=True)
        out = tmp_path / "out"

        def boom(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        monkeypatch.setattr(er, "run_unit", boom)
        er.main(["--cache", str(cache), "--output", str(out), "--modes", "lgtm",
                 "--variants", "own", "--cases", "aegra_authz_safe"])
        saved = json.loads((out / "lgtm" / "aegra_authz_safe.json").read_text(encoding="utf-8"))
        assert saved["predicted"] == "error" and saved["outcome"] == "ERROR"


class TestSummarizeOnlyKeepsTheEnvironment:
    """Regression: --summarize-only skipped preflight and so rewrote every
    summary.json without python / semgrep / ollama_version."""

    def test_environment_fields_survive_a_rebuild(self, tmp_path, monkeypatch):
        out = tmp_path / "out"
        (out / "lgtm").mkdir(parents=True)
        result = TestResultsAndSummary._result("pyload_sqli_vulnerable", "vulnerable", "TP", "sqli")
        (out / "lgtm" / "pyload_sqli_vulnerable.json").write_text(json.dumps(result))
        monkeypatch.setattr(er, "preflight",
                            lambda modes, config: {"python": "3.14.5", "ollama_version": "0.40.4"})
        er.main(["--summarize-only", "--output", str(out), "--modes", "lgtm",
                 "--variants", "own"])
        summary = json.loads((out / "lgtm" / "summary.json").read_text(encoding="utf-8"))
        assert summary["python"] == "3.14.5"
        assert summary["ollama_version"] == "0.40.4"


class TestResultsAndSummary:
    @staticmethod
    def _result(cid, expected, outcome, category="authz"):
        return {
            "id": cid, "category": category, "split": "real_world",
            "expected": expected, "predicted": "vulnerable" if outcome in ("TP", "FP") else "safe",
            "outcome": outcome, "correct": outcome in ("TP", "TN"),
            "predicted_grounded": "safe", "outcome_grounded": outcome,
            "n_findings": 0, "verdicts": [], "grounded": 0, "grounding_rate": None,
            "latency_seconds": 1.0, "est_tokens": 0, "findings": [],
        }

    def test_summary_aggregates_chunks_and_flags_incomplete(self, tmp_path):
        out = tmp_path / "lgtm"
        out.mkdir()
        (out / "a.json").write_text(json.dumps(self._result("a", "vulnerable", "TP")))
        (out / "b.json").write_text(json.dumps(self._result("b", "safe", "TN")))
        partial = er.write_dir_summary(out, "lgtm", "own", {"a", "b", "c"}, "m")
        assert partial["complete"] is False and partial["missing"] == ["c"]
        assert partial["summary"]["overall"]["tp"] == 1

        (out / "c.json").write_text(json.dumps(self._result("c", "vulnerable", "FN")))
        full = er.write_dir_summary(out, "lgtm", "own", {"a", "b", "c"}, "m")
        assert full["complete"] is True
        assert full["summary"]["overall"]["fn"] == 1
        assert full["experiments"] == {"require_tool_use": False,
                                       "static_facts": False,
                                       "authz_role_guidance": False}

    def test_crash_scores_like_the_synthetic_harness(self):
        vuln = {"id": "x", "category": "authz", "expected_verdict": "vulnerable",
                "repo_url": "https://github.com/o/p",
            "file": "src/app/routes.py"}
        safe = {**vuln, "expected_verdict": "safe"}
        assert er.error_result(vuln, "lgtm", "own", RuntimeError("boom"))["outcome"] == "ERROR"
        assert er.error_result(safe, "lgtm", "own", RuntimeError("boom"))["outcome"] == "ERROR"
        assert "RuntimeError: boom" in er.error_result(vuln, "lgtm", "own", RuntimeError("boom"))["error"]

    def test_infra_failure_result_is_scored_as_error(self, tmp_path, monkeypatch):
        class Finding:
            def model_dump(self, exclude=None):
                return {"finding_id": "authz:1", "category": "authz",
                        "verdict": "insufficient_evidence",
                        "explanation": "LLM call failed: x"}

        class Pipeline:
            def __init__(self, repo, config):
                pass

            def run(self, base, pr, output_dir=None):
                meta = type("Meta", (), {"semgrep_findings_in_diff": 0})()
                return type("Result", (), {"findings": [Finding()], "meta": meta})()

        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
        monkeypatch.setattr(er, "ReviewPipeline", Pipeline)
        case = {"id": "x", "category": "authz", "expected_verdict": "vulnerable",
                "repo_url": "https://github.com/o/p",
                "file": "src/app/routes.py"}
        result = er.run_unit(case, "own", "llm-only", tmp_path, tmp_path, er.LGTMConfig())
        assert result["outcome"] == "ERROR"
        assert result["infra_failures"] == 1
        assert result["infra_failure_ids"] == ["authz:1"]

    def test_summary_reports_errors_separately(self, tmp_path):
        out = tmp_path / "lgtm"
        out.mkdir()
        failed = {**self._result("b", "safe", "TN"), "predicted": "error",
                  "error": "RuntimeError: boom"}
        (out / "a.json").write_text(json.dumps(self._result("a", "vulnerable", "TP")))
        (out / "b.json").write_text(json.dumps(failed))
        summary = er.write_dir_summary(out, "lgtm", "own", {"a", "b"}, "m")
        assert summary["summary"]["overall"]["scored"] == 1
        assert summary["summary"]["overall"]["errors"] == 1
        assert summary["summary"]["overall"]["error_rate"] == 0.5
        assert summary["summary"]["overall"]["tn"] == 0
        assert summary["summary"]["error_cases"] == [
            {"id": "b", "error": "RuntimeError: boom"}]
        assert summary["complete"] is True

    def test_run_manifest_is_not_a_unit(self, tmp_path):
        out = tmp_path / "lgtm"
        out.mkdir()
        (out / "a.json").write_text(json.dumps(self._result("a", "vulnerable", "TP")))
        (out / "run.json").write_text(json.dumps({"model": "m", "reasoning": None}))
        summary = er.write_dir_summary(out, "lgtm", "own", {"a"}, "m")
        assert summary["cases_present"] == 1
        assert summary["summary"]["overall"]["cases"] == 1
        assert summary["complete"] is True
        assert summary["missing"] == []


class TestGpuModel:
    @staticmethod
    def _out_with_result(tmp_path):
        out = tmp_path / "out"
        (out / "lgtm").mkdir(parents=True)
        result = TestResultsAndSummary._result("pyload_sqli_vulnerable", "vulnerable", "TP", "sqli")
        (out / "lgtm" / "pyload_sqli_vulnerable.json").write_text(json.dumps(result))
        return out

    def test_preflight_receives_registry_model(self, tmp_path, monkeypatch):
        seen = []

        def fake_preflight(modes, config):
            seen.append(config)
            return {}

        monkeypatch.setattr(er, "preflight", fake_preflight)
        er.main(["--summarize-only", "--output", str(tmp_path), "--modes", "lgtm",
                 "--gpu-model", "qwen3.8-27b"])

        assert len(seen) == 1
        assert seen[0].ollama_model == "qwen3.8:27b"
        assert seen[0].ollama_base_url == "http://127.0.0.1:11435"
        assert seen[0].reasoning is False

    def test_model_conflict_is_a_parser_error(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            er.main(["--summarize-only", "--output", str(tmp_path), "--modes", "lgtm",
                     "--gpu-model", "qwen3.8-27b", "--model", "x:1"])

        assert exc.value.code == 2

    def test_summary_records_reasoning(self, tmp_path, monkeypatch):
        out = self._out_with_result(tmp_path)
        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        base = ["--summarize-only", "--output", str(out), "--modes", "lgtm",
                "--variants", "own"]
        summary_path = out / "lgtm" / "summary.json"

        er.main([*base, "--gpu-model", "qwen3.8-27b"])
        with_flag = json.loads(summary_path.read_text(encoding="utf-8"))
        er.main(base)
        without_flag = json.loads(summary_path.read_text(encoding="utf-8"))

        assert with_flag["reasoning"] is False
        assert without_flag["reasoning"] is False


class TestGraphMetadataOnRecords:
    """Real-world producer: graph metadata on new records, counted in summaries."""

    BASE40, PR40 = "a" * 40, "b" * 40
    CASE = {"id": "x", "category": "authz", "expected_verdict": "vulnerable",
            "repo_url": "https://github.com/o/p",
            "file": "src/app/routes.py"}

    @staticmethod
    def _pipeline(steps, cleaned):
        class Pipeline:
            def __init__(self, repo, config):
                pass

            def run(self, base, pr, output_dir=None):
                try:
                    step = steps.pop(0)
                    if isinstance(step, BaseException):
                        raise step
                    return step
                finally:
                    cleaned.append(1)

        return Pipeline

    @staticmethod
    def _review(meta, explanation="ok", verdict="vulnerable"):
        class Finding:
            def model_dump(self, exclude=None):
                return {"finding_id": "authz:1", "category": "authz",
                        "verdict": verdict,
                        "explanation": explanation}

        return type("Result", (), {"findings": [Finding()], "meta": meta})()

    def _full_meta(self):
        return type("Meta", (), {
            "semgrep_findings_in_diff": 0, "graph_state": "ok",
            "graph_index_seconds": 2.5, "base_sha": self.BASE40,
            "pr_sha": self.PR40})()

    def _run(self, monkeypatch, tmp_path, step):
        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
        monkeypatch.setattr(er, "ReviewPipeline", self._pipeline([step], []))
        return er.run_unit(self.CASE, "own", "llm-only", tmp_path, tmp_path,
                           er.LGTMConfig())

    def test_new_record_copies_review_metadata(self, tmp_path, monkeypatch):
        rec = self._run(monkeypatch, tmp_path, self._review(self._full_meta()))
        assert rec["graph_state"] == "ok" and rec["graph_index_seconds"] == 2.5
        assert rec["base_sha"] == self.BASE40 and rec["pr_sha"] == self.PR40

    def test_meta_lacking_graph_fields_defaults_without_crashing(
            self, tmp_path, monkeypatch):
        meta = type("Meta", (), {"semgrep_findings_in_diff": 0})()
        rec = self._run(monkeypatch, tmp_path, self._review(meta))
        assert rec["outcome"] != "ERROR"
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == (None, None, "", "")

    def test_semgrep_failure_makes_the_record_an_error_with_sast_fields(
            self, tmp_path, monkeypatch):
        meta = self._full_meta()
        meta.sast_error = "semgrep exited 2"
        meta.semgrep_findings_total = 0
        rec = self._run(monkeypatch, tmp_path, self._review(meta))
        assert rec["outcome"] == "ERROR"
        assert rec["error"] == "SAST failed: semgrep exited 2"
        assert (rec["sast_error"], rec["semgrep_findings_total"]) == ("semgrep exited 2", 0)

    def test_meta_lacking_sast_fields_records_nulls(self, tmp_path, monkeypatch):
        rec = self._run(monkeypatch, tmp_path, self._review(self._full_meta()))
        assert rec["outcome"] != "ERROR"
        assert (rec["sast_error"], rec["semgrep_findings_total"]) == (None, None)

    def test_infra_failure_record_keeps_available_metadata(
            self, tmp_path, monkeypatch):
        result = self._review(self._full_meta(), "LLM call failed: x",
                              "insufficient_evidence")
        rec = self._run(monkeypatch, tmp_path, result)
        assert rec["outcome"] == "ERROR"
        assert rec["graph_state"] == "ok" and rec["pr_sha"] == self.PR40

    def test_error_result_has_null_fields(self):
        rec = er.error_result(self.CASE, "lgtm", "own", RuntimeError("boom"))
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == (None, None, "", "")

    def test_crash_in_main_saves_null_fields(self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        (cache / "aegra" / ".git").mkdir(parents=True)
        out = tmp_path / "out"

        def boom(*a, **k):
            raise RuntimeError("boom")

        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        monkeypatch.setattr(er, "run_unit", boom)
        er.main(["--cache", str(cache), "--output", str(out), "--modes", "lgtm",
                 "--variants", "own", "--cases", "aegra_authz_safe"])
        saved = json.loads((out / "lgtm" / "aegra_authz_safe.json").read_text("utf-8"))
        assert (saved["graph_state"], saved["graph_index_seconds"],
                saved["base_sha"], saved["pr_sha"]) == (None, None, "", "")

    def test_dir_summary_counts_states_and_historical_as_unknown(self, tmp_path):
        out = tmp_path / "lgtm"
        out.mkdir()
        rows = {
            "a": {"graph_state": "ok"},
            "b": {"graph_state": "degraded:pr:timeout"},
            "c": {"graph_state": None},
            "d": {},
        }
        for cid, extra in rows.items():
            rec = {**TestResultsAndSummary._result(cid, "vulnerable", "TP"), **extra}
            (out / f"{cid}.json").write_text(json.dumps(rec), encoding="utf-8")
        summary = er.write_dir_summary(out, "lgtm", "own", set(rows), "m")
        assert summary["summary"]["graph_states"] == {
            "ok": 1, "degraded:pr:timeout": 1, "unknown": 2}
        assert summary["summary"]["overall"]["tp"] == 4
        assert summary["complete"] is True

    def test_historical_results_stay_resumable_and_unknown(self, tmp_path):
        cases = er.fetch.load_cases()[:1]
        units = list(er.work_units(cases, ["sast-only"], ["own"]))
        out = er.out_dir_for(tmp_path, "sast-only", "own")
        out.mkdir(parents=True)
        rec = TestResultsAndSummary._result(cases[0]["id"], "vulnerable", "TP")
        path = out / f"{cases[0]['id']}.json"
        path.write_text(json.dumps(rec), encoding="utf-8")
        assert list(er.pending_units(units, tmp_path, True)) == []
        summary = er.write_dir_summary(out, "sast-only", "own", {cases[0]["id"]}, "m")
        assert summary["summary"]["graph_states"] == {"unknown": 1}
        assert json.loads(path.read_text("utf-8")) == rec

    def test_interrupt_cleans_up_and_exits_three(self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        (cache / "aegra" / ".git").mkdir(parents=True)
        cleaned: list[int] = []
        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
        monkeypatch.setattr(er, "ReviewPipeline",
                            self._pipeline([KeyboardInterrupt()], cleaned))
        try:
            code = er.main(["--cache", str(cache), "--output", str(tmp_path / "out"),
                            "--modes", "llm-only", "--variants", "own",
                            "--cases", "aegra_authz_safe"])
        except SystemExit as exc:
            code = exc.code
        except KeyboardInterrupt:
            code = "KeyboardInterrupt propagated"
        assert cleaned == [1]
        assert code == 3

    def test_help_has_no_graph_option(self, capsys):
        with pytest.raises(SystemExit):
            er.main(["--help"])
        assert "graph" not in capsys.readouterr().out.lower()


class TestPostReviewFailureAndErrorCounts:
    def test_run_unit_error_after_review_keeps_the_four_graph_fields(
            self, tmp_path, monkeypatch):
        base, pr = "a" * 40, "b" * 40

        class BrokenFinding:
            def model_dump(self, exclude=None):
                raise RuntimeError("cannot serialise finding")

        meta = type("Meta", (), {
            "semgrep_findings_in_diff": 0, "graph_state": "ok",
            "graph_index_seconds": 2.5, "base_sha": base, "pr_sha": pr})()
        result = type("Result", (), {"findings": [BrokenFinding()], "meta": meta})()

        class Pipeline:
            def __init__(self, repo, config):
                pass

            def run(self, base_branch, pr_branch, output_dir=None):
                return result

        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
        monkeypatch.setattr(er, "ReviewPipeline", Pipeline)
        rec = er.run_unit(TestGraphMetadataOnRecords.CASE, "own", "llm-only",
                          tmp_path, tmp_path, er.LGTMConfig())
        assert rec["outcome"] == "ERROR" and rec["error"]
        assert (rec["graph_state"], rec["graph_index_seconds"],
                rec["base_sha"], rec["pr_sha"]) == ("ok", 2.5, base, pr)

    def test_dir_summary_counts_error_rows_under_state_or_unknown(self, tmp_path):
        out = tmp_path / "lgtm"
        out.mkdir()
        rows = {
            "a": {"graph_state": "ok"},
            "b": {"graph_state": "ok", "outcome": "ERROR", "predicted": "error",
                  "error": "boom"},
            "c": {"graph_state": None, "outcome": "ERROR", "predicted": "error",
                  "error": "boom"},
        }
        for cid, extra in rows.items():
            rec = {**TestResultsAndSummary._result(cid, "vulnerable", "TP"), **extra}
            (out / f"{cid}.json").write_text(json.dumps(rec), encoding="utf-8")
        summary = er.write_dir_summary(out, "lgtm", "own", set(rows), "m")
        assert summary["summary"]["overall"]["errors"] == 2
        assert summary["summary"]["graph_states"] == {"ok": 2, "unknown": 1}


class TestAuthzScanRecords:
    BASE40, PR40 = "a" * 40, "b" * 40
    CASE = TestGraphMetadataOnRecords.CASE
    @staticmethod
    def _build_coverage():
        def hunk(hid):
            return HunkRef(hid, "a.py", 1, 1, 1, 1, "modify")

        plan = ScanPlan(
            sections=[Section("s1", "investigator", "one", files=["a.py"],
                              hunks=[hunk("h1"), hunk("h2")]),
                      Section("s2", "investigator", "two", files=["a.py"],
                              hunks=[hunk("h3")])],
            exclusions=[Exclusion("a.lock", "lockfile"),
                        Exclusion("b.min.js", "minified"),
                        Exclusion("c.svg", "binary")],
            invalid_refs=["zz"], planner="investigator", files_total=5,
            files_in_scope=3, hunks_total=4, hunks_assigned=3, hunks_leftover=1,
            sections_coalesced=1)
        return build_coverage(
            plan, investigator_status="ok", investigator_error=None,
            investigator_input="full", investigator_tool_calls=4,
            results={"s1": SectionResult("completed", [], [], None),
                     "s2": SectionResult("failed", [], [], "boom")})

    COVERAGE = _build_coverage.__func__()
    COVERAGE_SUMMARY = {
        "planner": "investigator", "investigator_status": "ok",
        "investigator_error": None, "investigator_input": "full",
        "investigator_tool_calls": 4, "files_total": 5, "files_in_scope": 3,
        "hunks_total": 4, "hunks_assigned": 3, "hunks_leftover": 1,
        "hunks_reviewed": 2, "sections_scheduled": 2, "sections_completed": 1,
        "sections_failed": 1, "sections_coalesced": 1, "complete": False,
        "exclusions_total": 3}

    @staticmethod
    def _diff(path, status, added, deleted):
        hunk = type("Hunk", (), {"added_lines": added, "deleted_lines": deleted,
                                   "changes": []})()
        return type("Diff", (), {
            "path": path, "status": status, "hunks": [hunk],
            "hunk_text": lambda self: "x" * 10})()

    def _run(self, monkeypatch, tmp_path, mode, meta_extra=None, diffs=(),
             pin_calls=None):
        indexed = []

        def fake_ensure_index(clone, base, idx_dir, cfg, **kw):
            indexed.append(base)
            return {"seconds": 0.5, "chunks": 3, "reused": False}

        meta = type("Meta", (), {
            "semgrep_findings_in_diff": 0, "graph_state": "ok",
            "graph_index_seconds": 1.0, "base_sha": self.BASE40,
            "pr_sha": self.PR40, **(meta_extra or {})})()
        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: list(diffs))
        monkeypatch.setattr(er, "ensure_index", fake_ensure_index)
        if pin_calls is not None:
            self._record_pin(monkeypatch, pin_calls)
        monkeypatch.setattr(
            er, "ReviewPipeline",
            TestGraphMetadataOnRecords._pipeline(
                [TestGraphMetadataOnRecords._review(meta)], []))
        rec = er.run_unit(self.CASE, "own", mode, tmp_path, tmp_path, er.LGTMConfig())
        return rec, indexed

    PIN = {"pin": "sentinel"}

    def _record_pin(self, monkeypatch, calls):
        def fake_run_pin(config, repo_root, refs):
            calls.append((config, repo_root, dict(refs)))
            return self.PIN

        monkeypatch.setattr(er, "run_pin", fake_run_pin, raising=False)

    @pytest.mark.parametrize("mode", ["lgtm", "lgtm-no-sast"])
    def test_doc_modes_build_the_index_even_with_zero_endpoints(
            self, tmp_path, monkeypatch, mode):
        rec, indexed = self._run(monkeypatch, tmp_path, mode)
        assert len(indexed) == 1
        assert rec["index_skipped"] is False and rec["index_skip_reason"] == ""
        assert (rec["index_seconds"], rec["index_chunks"], rec["index_reused"]) == (
            0.5, 3, False)
        assert rec["outcome"] != "ERROR"

    @pytest.mark.parametrize("mode", ["lgtm", "lgtm-no-sast"])
    def test_doc_mode_record_has_pin_file_coverage_and_summary(
            self, tmp_path, monkeypatch, mode):
        real_run_pin = er.run_pin
        calls = []

        def spy(config, repo_root, refs):
            calls.append((repo_root, dict(refs)))
            return real_run_pin(config, repo_root, refs)

        monkeypatch.setattr(er, "run_pin", spy)
        rec, _ = self._run(monkeypatch, tmp_path, mode, {"coverage": self.COVERAGE})
        assert rec["pin"]["base_sha"] == self.BASE40
        assert rec["pin"]["pr_sha"] == self.PR40
        assert rec["pin"]["flags"]["mode"] == mode
        assert len(calls) == 1
        root, refs = calls[0]
        assert Path(root) == er.REPO_ROOT
        assert refs == {"base": self.BASE40, "pr": self.PR40}
        assert rec["file"] == self.CASE["file"]
        assert rec["coverage"] == self.COVERAGE
        assert rec["coverage_summary"] == self.COVERAGE_SUMMARY

    def test_exclusions_total_counts_exclusions_not_sections(
            self, tmp_path, monkeypatch):
        none_excluded = {**self.COVERAGE, "exclusions": []}
        rec, _ = self._run(monkeypatch, tmp_path, "lgtm", {"coverage": none_excluded})
        assert rec["coverage_summary"]["exclusions_total"] == 0

    @pytest.mark.parametrize("mode,index_builds", [("lgtm", 1), ("llm-only", 0)])
    def test_diff_stats_count_only_non_deleted_files(
            self, tmp_path, monkeypatch, mode, index_builds):
        diffs = [self._diff("kept.py", "modified", ["a", "b"], ["c"]),
                 self._diff("gone.py", "deleted", ["a"] * 5, ["c"] * 7)]
        rec, indexed = self._run(monkeypatch, tmp_path, mode, diffs=diffs)
        assert (rec["diff_files"], rec["diff_added"], rec["diff_deleted"]) == (1, 2, 1)
        assert (rec["diff_py_chars"], rec["diff_max_file_chars"]) == (10, 10)
        assert len(indexed) == index_builds

    @pytest.mark.parametrize("mode", ["lgtm", "lgtm-no-sast"])
    def test_doc_mode_without_coverage_records_none(self, tmp_path, monkeypatch, mode):
        rec, _ = self._run(monkeypatch, tmp_path, mode, {"coverage": None})
        assert rec["coverage"] is None and rec["coverage_summary"] is None
        assert rec["pin"]["pr_sha"] == self.PR40

    @pytest.mark.parametrize("mode", ["llm-only", "sast-only"])
    def test_non_doc_mode_record_skips_index_and_has_no_coverage(
            self, tmp_path, monkeypatch, mode):
        rec, indexed = self._run(monkeypatch, tmp_path, mode,
                                 {"coverage": self.COVERAGE})
        assert indexed == []
        assert rec["index_skipped"] is True
        assert rec["index_skip_reason"] == "mode does not use the index"
        assert rec["pin"]["base_sha"] == self.BASE40
        assert rec["file"] == self.CASE["file"]
        assert "coverage" not in rec and "coverage_summary" not in rec

    def test_record_has_no_endpoint_detection_field(self, tmp_path, monkeypatch):
        rec, _ = self._run(monkeypatch, tmp_path, "lgtm")
        assert ("endpoints" + "_detected") not in rec

    def test_manifest_pin_is_run_pin_on_lgtm_root(self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        (cache / "aegra" / ".git").mkdir(parents=True)
        out = tmp_path / "out"
        calls = []
        self._record_pin(monkeypatch, calls)
        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        monkeypatch.setattr(er, "run_unit", lambda *a, **k: None)
        er.main(["--cache", str(cache), "--output", str(out), "--modes", "lgtm",
                 "--variants", "own", "--cases", "aegra_authz_safe", "--model", "x:1"])
        manifest = json.loads((out / "run.json").read_text(encoding="utf-8"))
        assert manifest["pin"] == self.PIN
        assert calls and all(Path(root) == er.REPO_ROOT for _c, root, _r in calls)
        assert all(c.ollama_model == "x:1" for c, _root, _r in calls)

    @pytest.mark.parametrize("mode", ["lgtm", "llm-only"])
    def test_run_unit_crash_record_keeps_file_and_pin_without_coverage(
            self, tmp_path, monkeypatch, mode):
        class BrokenFinding:
            def model_dump(self, exclude=None):
                raise RuntimeError("cannot serialise finding")

        meta = type("Meta", (), {
            "semgrep_findings_in_diff": 0, "graph_state": "ok",
            "graph_index_seconds": 1.0, "base_sha": self.BASE40,
            "pr_sha": self.PR40, "coverage": self.COVERAGE})()
        result = type("Result", (), {"findings": [BrokenFinding()], "meta": meta})()
        calls = []
        self._record_pin(monkeypatch, calls)
        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
        monkeypatch.setattr(er, "ensure_index",
                            lambda *a, **k: {"seconds": 0.5, "chunks": 3, "reused": False})
        monkeypatch.setattr(
            er, "ReviewPipeline",
            TestGraphMetadataOnRecords._pipeline([result], []))
        rec = er.run_unit(self.CASE, "own", mode, tmp_path, tmp_path, er.LGTMConfig())
        assert rec["outcome"] == "ERROR"
        assert rec["pin"] == self.PIN
        assert rec["file"] == self.CASE["file"]
        assert "coverage" not in rec and "coverage_summary" not in rec

    def test_main_crash_record_keeps_file_and_pin_without_coverage(
            self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        (cache / "aegra" / ".git").mkdir(parents=True)
        out = tmp_path / "out"

        def boom(*a, **k):
            raise RuntimeError("boom")

        self._record_pin(monkeypatch, [])
        monkeypatch.setattr(er, "preflight", lambda modes, config: {})
        monkeypatch.setattr(er, "run_unit", boom)
        er.main(["--cache", str(cache), "--output", str(out), "--modes", "lgtm",
                 "--variants", "own", "--cases", "aegra_authz_safe"])
        path = out / "lgtm" / "aegra_authz_safe.json"
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["outcome"] == "ERROR"
        assert saved["pin"] == self.PIN
        case = next(c for c in er.fetch.load_cases() if c["id"] == "aegra_authz_safe")
        assert saved["file"] == case["file"]
        assert "coverage" not in saved and "coverage_summary" not in saved

    @pytest.mark.parametrize("name", ["count_agent" + "_items",
                                      "extract_changed" + "_endpoints"])
    def test_endpoint_gating_helpers_are_gone(self, name):
        assert not hasattr(er, name)


class TestKevFieldsAndMetrics:
    """Real-world producer: Kev answers per judged candidate and summary metrics over them."""

    CASE = {"id": "x", "category": "sqli", "expected_verdict": "vulnerable",
            "repo_url": "https://github.com/o/p", "file": "src/app/routes.py"}

    @staticmethod
    def _candidate(fid, **kwargs):
        from lgtm.agents.base import AgentFinding

        return AgentFinding(
            finding_id=fid, cwe_id="CWE-89", explanation=f"claim {fid}", category="sqli",
            agent="authz", file="a.py", line=1, pr_graph_ok=True, **kwargs,
        )

    def _run(self, monkeypatch, tmp_path, mode, findings):
        class Pipeline:
            def __init__(self, repo, config):
                pass

            def run(self, base, pr, output_dir=None):
                meta = type("Meta", (), {"semgrep_findings_in_diff": 0})()
                return type("Result", (), {"findings": findings, "meta": meta})()

        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
        monkeypatch.setattr(er, "ensure_index", lambda *a, **k: {"seconds": 0.0, "chunks": 0, "reused": True})
        monkeypatch.setattr(er, "ReviewPipeline", Pipeline)
        return er.run_unit(self.CASE, "own", mode, tmp_path, tmp_path, er.LGTMConfig())

    @staticmethod
    def _row(cid, findings, mode="lgtm"):
        base = TestResultsAndSummary._result(cid, "vulnerable", "TP", category="sqli")
        return {**base, "mode": mode, "pin": {}, "findings": findings}

    @staticmethod
    def _kev(verdict="real", severity="high", confidence=0.8, tokens=1000, **extra):
        return {"finding_id": "f", "category": "sqli", "verdict": "", "judged": True, "supported": True,
                "kev_verdict": verdict, "kev_severity": severity, "provenance_confidence": confidence,
                "input_tokens": tokens, **extra}

    @staticmethod
    def _summary(tmp_path, name, rows, mode="lgtm"):
        out = tmp_path / name
        out.mkdir()
        for row in rows:
            (out / f"{row['id']}.json").write_text(json.dumps(row), encoding="utf-8")
        return er.write_dir_summary(out, mode, "own", {r["id"] for r in rows}, "m")["summary"]

    def test_saved_record_gives_judged_candidate_kev_verdict_severity_and_provenance(
        self, tmp_path, monkeypatch
    ):
        findings = [
            self._candidate("ok", judged=True, supported=True, provenance_confidence=0.7,
                            kev_verdict="not_real", kev_severity="low"),
            self._candidate("down", judged=False, not_judged_reason="judge-failed"),
        ]

        saved = {f["finding_id"]: f for f in self._run(monkeypatch, tmp_path, "lgtm", findings)["findings"]}

        assert (saved["ok"]["kev_verdict"], saved["ok"]["kev_severity"]) == ("not_real", "low")
        assert saved["ok"]["provenance_confidence"] == 0.7
        assert (saved["down"].get("kev_verdict"), saved["down"].get("kev_severity")) == (None, None)
        assert (saved["down"]["judged"], saved["down"]["not_judged_reason"]) == (False, "judge-failed")

    def test_saved_judged_candidates_record_the_input_tokens_of_their_judge_reply(self, tmp_path, monkeypatch):
        replies = iter([
            {"valid": True, "input_tokens": 1000},
            {"valid": True, "input_tokens": 9000},
            {"valid": False, "input_tokens": 555},
            {"valid": True, "input_tokens": 300},
        ])
        candidates = [
            self._candidate("a1").model_copy(update={"explanation": "claim a"}),
            self._candidate("a2").model_copy(update={"explanation": "claim a"}),
            self._candidate("b"),
            self._candidate("c"),
        ]

        class Pipeline:
            def __init__(self, repo, config):
                self._judge = lambda request: next(replies)

            def run(self, base, pr, output_dir=None):
                judged = []
                for f in candidates:
                    reply = self._judge({"state": f"Claim: {f.explanation}\nCited item: a.py"})
                    update = (
                        {"judged": True, "supported": True, "kev_verdict": "real", "kev_severity": "high"}
                        if reply["valid"] else {"judged": False, "not_judged_reason": "judge-failed"}
                    )
                    judged.append(f.model_copy(update=update))
                meta = type("Meta", (), {"semgrep_findings_in_diff": 0})()
                return type("Result", (), {"findings": judged, "meta": meta})()

        monkeypatch.setattr(er, "get_pr_diff", lambda *a, **k: [])
        monkeypatch.setattr(er, "ensure_index", lambda *a, **k: {"seconds": 0.0, "chunks": 0, "reused": True})
        monkeypatch.setattr(er, "ReviewPipeline", Pipeline)

        record = er.run_unit(self.CASE, "own", "lgtm", tmp_path, tmp_path, er.LGTMConfig())

        saved = {f["finding_id"]: f for f in record["findings"]}
        assert [saved[k].get("input_tokens") for k in ("a1", "a2", "b", "c")] == [1000, 9000, None, 300]

    @pytest.mark.parametrize("mode", ["sast-only", "llm-only"])
    def test_modes_without_a_judge_save_no_kev_fields(self, tmp_path, monkeypatch, mode):
        record = self._run(monkeypatch, tmp_path, mode, [self._candidate("a", verdict="vulnerable")])

        for f in record["findings"]:
            assert [f.get(k) for k in ("kev_verdict", "kev_severity", "input_tokens")] == [None, None, None]

    def test_summary_reports_kev_metrics_over_judged_candidates_and_counts_not_judged_by_reason(self, tmp_path):
        down = {"finding_id": "d", "category": "sqli", "verdict": "", "judged": False, "supported": None,
                "not_judged_reason": "judge-failed"}
        rows = [
            self._row("a", [self._kev(), self._kev("not_real", "low", 0.2, 9000)]),
            self._row("b", [self._kev("real", "critical", 0.5, 8192), down]),
        ]

        kev = self._summary(tmp_path, "lgtm", rows)["kev"]

        assert kev["judged"] == 3
        assert kev["verdicts"] == {"real": 2, "not_real": 1}
        assert kev["severities"] == {"high": 1, "low": 1, "critical": 1}
        assert kev["provenance_confidence_mean"] == pytest.approx(0.5)
        assert kev["not_judged"] == {"judge-failed": 1}
        assert kev["requests_over_8192_input_tokens"] == 1

    @pytest.mark.parametrize("mode", ["sast-only", "llm-only"])
    def test_summary_of_modes_without_a_judge_has_no_kev_metrics(self, tmp_path, mode):
        row = self._row("a", [{"finding_id": "f", "category": "sqli", "verdict": "vulnerable",
                               "judged": False}], mode)

        summary = self._summary(tmp_path, mode, [row], mode)

        kev = summary.get("kev", {})
        assert (kev.get("judged", 0), kev.get("verdicts", {}), kev.get("severities", {}),
                kev.get("not_judged", {}), kev.get("requests_over_8192_input_tokens", 0)) == (0, {}, {}, {}, 0)
        assert summary["overall"]["tp"] == 1

    def test_existing_summary_fields_equal_those_of_the_same_run_without_kev_answers(self, tmp_path):
        with_kev = [self._row("a", [self._kev("not_real", "low")]),
                    self._row("b", [self._kev(tokens=20_000)])]
        bare = {"kev_verdict", "kev_severity", "input_tokens"}
        plain = [{**r, "findings": [{k: v for k, v in f.items() if k not in bare} for f in r["findings"]]}
                 for r in with_kev]

        left = self._summary(tmp_path, "with", with_kev)
        right = self._summary(tmp_path, "plain", plain)

        assert {k: v for k, v in left.items() if k != "kev"} == {k: v for k, v in right.items() if k != "kev"}

    def test_resume_judges_again_a_judged_unit_without_kev_fields_and_keeps_one_with_them(self, tmp_path):
        cases = er.fetch.load_cases()[:3]
        units = list(er.work_units(cases, ["lgtm"], ["own"]))
        out = er.out_dir_for(tmp_path, "lgtm", "own")
        out.mkdir(parents=True)
        old = {"finding_id": "f", "category": "sqli", "verdict": "", "judged": True, "supported": True}
        rows = {
            cases[0]["id"]: self._row(cases[0]["id"], [old]),
            cases[1]["id"]: self._row(cases[1]["id"], [self._kev()]),
        }
        for cid, row in rows.items():
            (out / f"{cid}.json").write_text(json.dumps(row), encoding="utf-8")

        pending = [c["id"] for c, _v, _m in er.pending_units(units, tmp_path, True)]

        assert pending == [cases[0]["id"], cases[2]["id"]]
