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
