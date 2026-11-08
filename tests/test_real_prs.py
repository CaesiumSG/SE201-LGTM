"""The real vulnerable-PR case list and its scoring (no network, no model)."""

import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "benchmark" / "real_prs"


def _load():
    spec = importlib.util.spec_from_file_location("lgtm_real_prs", HERE / "run_real_prs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cases_are_well_formed():
    cases = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))["cases"]
    assert len(cases) >= 10
    assert len({c["id"] for c in cases}) == len(cases)
    assert len({c["repo"] for c in cases}) >= 6
    for c in cases:
        assert c["category"] in ("sqli", "authz"), c["id"]
        assert re.fullmatch(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", c["ghsa"]), c["id"]
        for side in ("introducing", "fix"):
            assert re.fullmatch(r"[0-9a-f]{40}", c[side]["base_commit"]), (c["id"], side)
            assert re.fullmatch(r"[0-9a-f]{40}", c[side]["merge_commit"]), (c["id"], side)
            assert c[side]["base_commit"] != c[side]["merge_commit"]
        assert c["vulnerable_files"] and all(f.endswith(".py") for f in c["vulnerable_files"])


def test_each_advisory_expands_to_a_vulnerable_and_a_fixed_case():
    mod = _load()
    case = mod.load_cases()[0]
    rows = mod.expand(case)
    assert [r["id"] for r in rows] == [f"{case['id']}-vulnerable", f"{case['id']}-fixed"]
    assert [r["expected"] for r in rows] == ["vulnerable", "safe"]
    assert rows[0]["merge_commit"] == case["introducing"]["merge_commit"]
    assert rows[1]["base_commit"] == case["fix"]["base_commit"]


def test_score_marks_outcome_and_whether_the_flag_is_in_the_advisory_file():
    mod = _load()
    vuln = {"advisory": "a", "url": "u", "category": "sqli", "cwe": "CWE-89", "ghsa": "g",
            "expected": "vulnerable", "vulnerable_files": ["app/db.py"]}
    hit = mod.score(vuln, {"vulnerable_findings": [{"file": "app/db.py"}]})
    assert hit["outcome"] == "TP" and hit["on_target"] is True
    elsewhere = mod.score(vuln, {"vulnerable_findings": [{"file": "app/other.py"}]})
    assert elsewhere["outcome"] == "TP" and elsewhere["on_target"] is False
    assert mod.score(vuln, {"vulnerable_findings": []})["outcome"] == "FN"
    assert mod.score({**vuln, "expected": "safe"}, {"vulnerable_findings": [{"file": "x.py"}]})["outcome"] == "FP"
    assert mod.score(vuln, {"crashed": True})["outcome"] == "ERROR"


def test_summary_counts_outcomes_and_on_target_hits():
    mod = _load()
    records = [
        {"id": "a-vulnerable", "outcome": "TP", "on_target": True, "latency_seconds": 10.0},
        {"id": "a-fixed", "outcome": "TN", "latency_seconds": 20.0},
        {"id": "b-vulnerable", "outcome": "FN", "latency_seconds": 30.0},
        {"id": "b-fixed", "outcome": "FP", "latency_seconds": 40.0},
        {"id": "c-vulnerable", "outcome": "ERROR"},
    ]
    s = mod.summarize(records)
    o = s["overall"]
    assert (o["tp"], o["fp"], o["fn"], o["tn"], o["errors"]) == (1, 1, 1, 1, 1)
    assert o["precision"] == 0.5 and o["recall"] == 0.5 and o["f1"] == 0.5
    assert o["false_positive_rate_on_safe"] == 0.5
    assert s["vulnerable_caught_on_target"] == 1
    assert s["median_latency_seconds"] == 25.0


def test_explicit_base_commit_is_used_for_the_diff(monkeypatch, tmp_path):
    mod = _load()
    ft = mod.ft
    calls = []

    def fake_git(repo, *args, **kwargs):
        calls.append(args)
        if args[0] == "rev-parse":
            return args[1] + "\n"
        return ""

    monkeypatch.setattr(ft, "git", fake_git)
    monkeypatch.setattr(ft, "has_commit", lambda repo, sha: False)
    (tmp_path / "x" / ".git").mkdir(parents=True)
    base, pr = ft.ensure_case({"id": "c", "repo": "o/x", "base_commit": "b" * 40, "merge_commit": "m" * 40}, tmp_path)
    assert (base, pr) == ("b" * 40, "m" * 40)
    fetched = [a[-1] for a in calls if a[0] == "fetch"]
    assert fetched == ["b" * 40, "m" * 40]
