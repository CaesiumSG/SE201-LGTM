"""No-network, no-model guards for benchmark/real_world/evaluate_real.py:
the planning, resume, index-skip, scrubbing and summary logic."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from lgtm.diff.git_diff import parse_unified_diff

RW = Path(__file__).resolve().parent.parent / "benchmark" / "real_world"
_spec = importlib.util.spec_from_file_location("rw_evaluate_real", RW / "evaluate_real.py")
er = importlib.util.module_from_spec(_spec)
sys.modules["rw_evaluate_real"] = er
_spec.loader.exec_module(er)

DIFF_ENDPOINT_AND_SINK = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,5 @@
 import x
+@app.get("/items")
+def items():
+    cur.execute(f"SELECT * FROM t WHERE id = {i}")
"""

DIFF_COMMENT_ONLY = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 import x
+# just a comment
"""


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


class TestAgentItems:
    def test_no_sast_counts_endpoints_and_heuristic_sinks(self):
        diffs = parse_unified_diff(DIFF_ENDPOINT_AND_SINK)
        work = er.count_agent_items("lgtm-no-sast", diffs, [])
        assert work["endpoint_ids"] and work["sink_count"] == 1
        assert work["agent_items"] == 2

    def test_lgtm_uses_the_semgrep_findings_it_is_given(self):
        diffs = parse_unified_diff(DIFF_COMMENT_ONLY)
        assert er.count_agent_items("lgtm", diffs, [])["agent_items"] == 0
        assert er.count_agent_items("lgtm", diffs, ["finding"])["agent_items"] == 1

    def test_nothing_to_review_means_zero(self):
        diffs = parse_unified_diff(DIFF_COMMENT_ONLY)
        assert er.count_agent_items("lgtm-no-sast", diffs, [])["agent_items"] == 0


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
                "repo_url": "https://github.com/o/p"}
        safe = {**vuln, "expected_verdict": "safe"}
        assert er.error_result(vuln, "lgtm", "own", RuntimeError("boom"))["outcome"] == "ERROR"
        assert er.error_result(safe, "lgtm", "own", RuntimeError("boom"))["outcome"] == "ERROR"
        assert "RuntimeError: boom" in er.error_result(vuln, "lgtm", "own", RuntimeError("boom"))["error"]

    def test_infra_failure_result_is_scored_as_error(self, tmp_path, monkeypatch):
        class Finding:
            def model_dump(self, exclude=None):
                return {"finding_id": "authz:1", "category": "authz",
                        "verdict": "insufficient_evidence", "evidence_valid": False,
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
                "repo_url": "https://github.com/o/p"}
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
            "repo_url": "https://github.com/o/p"}

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
                        "verdict": verdict, "evidence_valid": True,
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
