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
        assert saved["predicted"] == "error" and saved["outcome"] == "TN"


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
        assert er.error_result(vuln, "lgtm", "own", RuntimeError("boom"))["outcome"] == "FN"
        assert er.error_result(safe, "lgtm", "own", RuntimeError("boom"))["outcome"] == "TN"
        assert "RuntimeError: boom" in er.error_result(vuln, "lgtm", "own", RuntimeError("boom"))["error"]
