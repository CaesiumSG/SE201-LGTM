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
         "vulnerable_findings": [{"evidence_valid": True}],
         "semgrep_findings_in_diff": 1, "endpoints_reviewed": 1, "index_seconds": 5.0},
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
