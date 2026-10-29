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


def test_scrub_replaces_cache_paths():
    mod = _load()
    out = mod.scrub({"x": ["/Users/me/cache/repo/file.py"]}, ["/Users/me/cache"])
    assert out == {"x": ["<cache>/repo/file.py"]}


def test_llm_only_case_without_endpoints_reviewed_completes_with_zero(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from lgtm.reporting.report_builder import ReviewMetadata

    mod = _load()
    meta = ReviewMetadata(semgrep_findings_total=0, semgrep_findings_in_diff=0)
    assert not hasattr(meta, "endpoints_reviewed")

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
    assert record["endpoints_reviewed"] == 0


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
