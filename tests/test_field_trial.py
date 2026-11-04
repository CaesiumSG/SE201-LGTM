"""The field-trial case list and harness helpers (no network, no model)."""

import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "benchmark" / "field_trial"


def _load():
    spec = importlib.util.spec_from_file_location("lgtm_field_trial", HERE / "run_field_trial.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cases_are_well_formed():
    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))["cases"]
    assert len(cases) >= 10
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids))
    for c in cases:
        assert re.fullmatch(r"[0-9a-f]{40}", c["merge_commit"]), c["id"]
        assert c["url"] == f"https://github.com/{c['repo']}/pull/{c['pr']}"
        assert c["framework"] in ("Flask", "FastAPI", "Django")
    assert len({c["repo"] for c in cases}) >= 2


def test_summary_counts_crashes_and_flags():
    mod = _load()
    records = [
        {"id": "a", "crashed": False, "latency_seconds": 10.0, "n_findings": 2,
         "verdicts": {"vulnerable": 1, "safe": 1},
         "vulnerable_findings": [{"supported": True}],
         "semgrep_findings_in_diff": 1, "changed_endpoints": 1, "index_seconds": 5.0},
        {"id": "b", "crashed": False, "latency_seconds": 30.0, "n_findings": 0,
         "verdicts": {}, "vulnerable_findings": [], "index_seconds": 0.0},
        {"id": "c", "crashed": True, "error": "boom", "findings": []},
    ]
    s = mod.summarize(records)
    assert s["cases"] == 3 and s["crashed"] == 1
    assert s["prs_with_vulnerable_verdict"] == 1
    assert s["vulnerable_findings_total"] == 1
    assert s["grounded_vulnerable_findings"] == 1
    assert s["latency_median_seconds"] == 20.0
    assert [p["id"] for p in s["per_case"]] == ["a", "b", "c"]


def test_summary_counts_review_reach_and_graph_state():
    mod = _load()
    cov = {"planner": "investigator", "investigator_status": "ok", "hunks_total": 4,
           "hunks_reviewed": 4, "sections_scheduled": 2, "sections_completed": 2,
           "sections_failed": 0, "complete": True, "sections": [{"section_id": "s1"}]}
    brief = mod.coverage_brief(cov)
    assert brief["sections_completed"] == 2 and brief["complete"] is True
    assert "sections" not in brief
    assert mod.coverage_brief(None) is None

    records = [
        {"id": "a", "crashed": False, "latency_seconds": 1.0, "graph_state": "ok",
         "coverage": brief, "judged": {"supported": 1, "unsupported": 0, "not_judged": 1}},
        {"id": "b", "crashed": False, "latency_seconds": 1.0, "graph_state": "unavailable:missing",
         "coverage": mod.coverage_brief({**cov, "sections_completed": 0, "sections_failed": 2,
                                         "hunks_reviewed": 0, "complete": False})},
        {"id": "c", "crashed": False, "latency_seconds": 1.0, "graph_state": None, "coverage": None},
    ]
    s = mod.summarize(records)
    assert s["prs_reviewed_by_agent"] == 1
    assert s["prs_coverage_complete"] == 1
    assert s["sections_failed_total"] == 2
    assert s["graph_states"] == {"ok": 1, "unavailable:missing": 1, "none": 1}
    assert s["judge"] == {"supported": 1, "unsupported": 0, "not_judged": 1}
    assert s["per_case"][0]["sections_completed"] == 2
    assert s["per_case"][2]["graph_state"] is None


def test_judge_counts_only_when_findings_carry_a_judge_result():
    mod = _load()
    assert mod.judge_counts([{"verdict": "safe"}]) is None
    counts = mod.judge_counts([{"supported": True}, {"supported": False}, {"supported": None}])
    assert counts == {"supported": 1, "unsupported": 1, "not_judged": 1}


def test_scrub_replaces_cache_paths():
    mod = _load()
    out = mod.scrub({"x": ["/Users/me/cache/repo/file.py"]}, ["/Users/me/cache"])
    assert out == {"x": ["<cache>/repo/file.py"]}


def test_llm_only_case_without_changed_endpoints_completes_with_zero(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from lgtm.reporting.report_builder import ReviewMetadata

    mod = _load()
    meta = ReviewMetadata(semgrep_findings_total=0, semgrep_findings_in_diff=0)

    class Pipeline:
        def __init__(self, *a, **k):
            pass

        def run(self, base, pr, output_dir=None):
            return SimpleNamespace(findings=[], meta=meta, run_records=[])

    monkeypatch.setattr(mod, "ensure_case", lambda case, cache: ("b" * 40, "p" * 40))
    monkeypatch.setattr(mod, "get_pr_diff", lambda *a, **k: [])
    monkeypatch.setattr(mod, "ReviewPipeline", Pipeline)
    case = {"id": "x-1", "repo": "o/x", "pr": 1}

    record = mod.run_case(case, "llm-only", tmp_path, mod.LGTMConfig())

    assert record["crashed"] is False
    assert record["changed_endpoints"] == 0


def test_summary_counts_sast_triage_tool_calls_apart_from_reviewer(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from lgtm.reporting.report_builder import ReviewMetadata

    mod = _load()
    meta = ReviewMetadata(semgrep_findings_total=0, semgrep_findings_in_diff=0)

    def rec(section, n):
        return SimpleNamespace(section=section, tool_calls=[{"tool": "read_file"}] * n)

    records = [rec("investigator", 1), rec("s1", 2), rec("route:users:12", 4),
               rec("sast_triage:rule.x:app.py:10", 8), rec("sast_triage:rule.y:app.py:20", 16)]

    class Pipeline:
        def __init__(self, *a, **k):
            pass

        def run(self, base, pr, output_dir=None):
            return SimpleNamespace(findings=[], meta=meta, run_records=records)

    monkeypatch.setattr(mod, "ensure_case", lambda case, cache: ("b" * 40, "p" * 40))
    monkeypatch.setattr(mod, "get_pr_diff", lambda *a, **k: [])
    monkeypatch.setattr(mod, "ReviewPipeline", Pipeline)
    record = mod.run_case({"id": "x-1", "repo": "o/x", "pr": 1}, "llm-only", tmp_path, mod.LGTMConfig())

    tool_calls = mod.summarize([record])["tool_calls"]

    assert tool_calls["investigator"]["total"] == 1
    assert tool_calls["reviewer"]["total"] == 6
    assert tool_calls["reviewer"]["per_unit_mean"] == 3
    assert tool_calls["sast_triage"] == {"total": 24, "per_case_mean": 24, "per_unit_mean": 12}


def _fake_run(mod, monkeypatch, findings):
    from types import SimpleNamespace

    from lgtm.reporting.report_builder import ReviewMetadata

    class Pipeline:
        def __init__(self, *a, **k):
            pass

        def run(self, base, pr, output_dir=None):
            return SimpleNamespace(findings=findings, meta=ReviewMetadata(), run_records=[])

    monkeypatch.setattr(mod, "ensure_case", lambda case, cache: ("b" * 40, "p" * 40))
    monkeypatch.setattr(mod, "get_pr_diff", lambda *a, **k: [])
    monkeypatch.setattr(mod, "ensure_index", lambda *a, **k: {})
    monkeypatch.setattr(mod, "ReviewPipeline", Pipeline)


def test_lgtm_findings_count_as_vulnerable_by_the_judge_not_the_verdict_field(monkeypatch, tmp_path):
    from lgtm.agents.base import AgentFinding

    mod = _load()
    findings = [
        AgentFinding(finding_id="kept", supported=True, kev_verdict="real"),
        AgentFinding(finding_id="ruled-out", supported=True, kev_verdict="not_real"),
        AgentFinding(finding_id="unsupported", supported=False),
    ]
    _fake_run(mod, monkeypatch, findings)

    record = mod.run_case({"id": "x-1", "repo": "o/x", "pr": 1}, "lgtm", tmp_path, mod.LGTMConfig())

    assert [f["finding_id"] for f in record["vulnerable_findings"]] == ["kept"]
    assert mod.summarize([record])["prs_with_vulnerable_verdict"] == 1


def test_infrastructure_failure_is_recorded_as_a_crash(monkeypatch, tmp_path):
    from lgtm.agents.base import AgentFinding

    mod = _load()
    _fake_run(mod, monkeypatch, [AgentFinding(finding_id="f", explanation="LLM call failed: timeout")])

    record = mod.run_case({"id": "x-1", "repo": "o/x", "pr": 1}, "llm-only", tmp_path, mod.LGTMConfig())

    assert record["crashed"] is True
    assert "f" in record["error"]


def test_resume_reruns_crashed_cases_only(monkeypatch, tmp_path):
    mod = _load()
    case_ids = [c["id"] for c in mod.load_cases()][:2]
    out = tmp_path / "out" / "llm-only"
    out.mkdir(parents=True)
    (out / f"{case_ids[0]}.json").write_text(json.dumps({"id": case_ids[0], "crashed": False,
                                                         "latency_seconds": 1.0}), encoding="utf-8")
    (out / f"{case_ids[1]}.json").write_text(json.dumps({"id": case_ids[1], "crashed": True,
                                                         "error": "boom"}), encoding="utf-8")
    ran = []

    def run_case(case, mode, cache, config):
        ran.append(case["id"])
        return {"id": case["id"], "crashed": False, "latency_seconds": 2.0, "n_findings": 0}

    monkeypatch.setattr(mod, "run_case", run_case)
    mod.main(["--modes", "llm-only", "--cases", *case_ids, "--output", str(tmp_path / "out"), "--resume"])

    assert ran == [case_ids[1]]
