"""Unit tests for the investigator component benchmark: run, written results, rubric, rating ingestion."""

from __future__ import annotations

import importlib
import json
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.diff.git_diff import parse_unified_diff
from lgtm.review.sections import _SHAPE_ERROR, ProposedSection, _hunk_ref

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "benchmark" / "component_bench"


def bench(name: str):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module(f"benchmark.component_bench.{name}")


def diff_text(case_id: str) -> str:
    return (
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,2 @@\n"
        f" import os\n+marker_{case_id} = 1\n"
    )


def fake_loader(case, config):
    return parse_unified_diff(diff_text(case["id"])), SimpleNamespace(calls_used=0)


def ok_result(diffs, title="Add marker"):
    ref = _hunk_ref(diffs[0], 0)
    section = ProposedSection("s1", title, "why this belongs together", [ref.hunk_id])
    return SimpleNamespace(
        proposed=[section], status="ok", error=None, input_mode="full", tool_calls=0, run_record=None
    )


def failed_result(error):
    return SimpleNamespace(
        proposed=None, status="failed", error=error, input_mode="full", tool_calls=0, run_record=None
    )


@pytest.fixture
def inv(tmp_path, monkeypatch):
    mod = bench("investigator")
    monkeypatch.setattr(bench("run"), "_preflight", lambda case: None)
    monkeypatch.setattr(mod, "load_case_diffs", fake_loader)
    monkeypatch.setattr(mod, "run_investigator", lambda diffs, config, toolbox, llm: ok_result(diffs))
    return mod


def run_all(inv, tmp_path, results=None, **kw):
    run, reg = bench("run"), bench("registry")
    registry = {"investigator": reg.Entry(module=inv, source="cases", aggregate=inv.aggregate)}
    results = results or tmp_path / "results"
    summary = run.run_benchmark(
        results_dir=results, registry=registry, llm=object(), components=["investigator"], **kw
    )
    return summary["components"]["investigator"], results


def result_files(results: Path) -> dict[str, dict]:
    out = {}
    for path in results.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "sections" in doc:
            out[doc["case_id"]] = doc
    return out


def write_rating(results: Path, case_id: str, rating, reason="reasonable grouping"):
    d = results / "investigator" / "ratings"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{case_id}.json").write_text(
        json.dumps({"case_id": case_id, "rating": rating, "reason": reason}), encoding="utf-8"
    )


def unit(case_id, status="scored"):
    return {"case_id": case_id, "label_id": None, "status": status, "scores": {}}


# AC-S3-1
def test_result_is_self_contained_with_diff_and_investigator_sections(inv, tmp_path):
    run_all(inv, tmp_path)
    doc = result_files(tmp_path / "results")["pyload_sqli_vulnerable"]
    assert "marker_pyload_sqli_vulnerable = 1" in json.dumps(doc)
    assert "app.py" in json.dumps(doc)
    (section,) = doc["sections"]
    assert section["title"] == "Add marker"
    assert section["rationale"] == "why this belongs together"
    assert "marker_pyload_sqli_vulnerable" in json.dumps(section["hunks"])


def test_rubric_copy_is_written_next_to_results(inv, tmp_path):
    run_all(inv, tmp_path)
    copy = tmp_path / "results" / "investigator" / "investigator_rubric.md"
    assert copy.read_bytes() == (PKG / "investigator_rubric.md").read_bytes()


# AC-S3-3
def test_unparsable_plan_is_not_scored_and_writes_no_result(inv, monkeypatch, tmp_path):
    monkeypatch.setattr(inv, "run_investigator", lambda *a: failed_result(_SHAPE_ERROR))
    section, _ = run_all(inv, tmp_path)
    assert section["units_not_scored"] == 25
    assert section["units_scored"] == 0
    assert section["units_errored"] == 0
    assert result_files(tmp_path / "results") == {}


@pytest.mark.parametrize("sections", ["empty", "unknown_hunk"])
def test_plan_without_a_section_holding_a_diff_hunk_is_not_scored(inv, monkeypatch, tmp_path, sections):
    def plan(diffs, config, toolbox, llm):
        proposed = [] if sections == "empty" else [ProposedSection("s1", "T", "r", ["no-such-hunk"])]
        return SimpleNamespace(
            proposed=proposed, status="ok", error=None, input_mode="full", tool_calls=0, run_record=None
        )

    monkeypatch.setattr(inv, "run_investigator", plan)
    section, _ = run_all(inv, tmp_path)
    assert section["units_not_scored"] == 25
    assert section["units_scored"] == 0
    assert len(section["aggregate"]["plan_invalid"]) == 25
    assert result_files(tmp_path / "results") == {}


# AC-S3-4
def test_unreachable_model_is_an_error_not_a_result(inv, monkeypatch, tmp_path):
    monkeypatch.setattr(inv, "run_investigator", lambda *a: failed_result("Connection refused"))
    section, results = run_all(inv, tmp_path)
    assert section["units_errored"] == 25
    assert section["units_not_scored"] == 0
    assert result_files(tmp_path / "results") == {}
    stored = json.loads((results / "investigator.json").read_text())["units"]
    assert {u["status"] for u in stored} == {"error"}


def test_outputs_and_ratings_resolve_under_a_non_default_results_dir(inv, tmp_path):
    default = PKG / "results" / "investigator"
    before = sorted(p.name for p in default.rglob("*")) if default.exists() else []
    run_dir = tmp_path / "runs" / "component-bench-x"
    run_all(inv, tmp_path, results=run_dir)
    write_rating(run_dir, "pyload_sqli_vulnerable", 0.7)
    section, _ = run_all(inv, tmp_path, results=run_dir, resume=True)
    assert len(result_files(run_dir / "investigator")) == 25
    assert (run_dir / "investigator" / "investigator_rubric.md").is_file()
    agg = section["aggregate"]
    assert agg["ratings"] == {"pyload_sqli_vulnerable": 0.7}
    assert "pyload_sqli_vulnerable" not in agg["unrated"]
    assert (agg["rated"], agg["with_result"]) == (1, 25)
    after = sorted(p.name for p in default.rglob("*")) if default.exists() else []
    assert after == before


def test_rerunning_a_case_discards_its_existing_rating(inv, tmp_path):
    run_all(inv, tmp_path)
    write_rating(tmp_path / "results", "pyload_sqli_vulnerable", 0.7)
    write_rating(tmp_path / "results", "aegra_authz_vulnerable", 0.4)
    section, _ = run_all(inv, tmp_path)
    agg = section["aggregate"]
    assert agg["ratings"] == {}
    assert {"pyload_sqli_vulnerable", "aegra_authz_vulnerable"} <= set(agg["unrated"])


# AC-S3-5
def test_all_twenty_five_cases_run_and_each_result_names_its_case_id(inv, tmp_path):
    section, _ = run_all(inv, tmp_path)
    cases = bench("schema").load_cases()
    assert len(cases) == 25
    assert section["units_scored"] == 25
    docs = result_files(tmp_path / "results")
    assert set(docs) == {c["id"] for c in cases}
    for case_id, doc in docs.items():
        assert f"marker_{case_id}" in json.dumps(doc)


# AC-S9-1
def test_rubric_file_states_criteria_and_scale_anchors():
    text = (PKG / "investigator_rubric.md").read_text(encoding="utf-8")
    assert "logical" in text.lower()
    for anchor in ("0.00", "0.50", "1.00"):
        assert anchor in text


# AC-S9-2
@pytest.mark.parametrize("rating", [0.0, 0.5, 1.0])
def test_rating_in_range_is_ingested(inv, tmp_path, rating):
    write_rating(tmp_path, "pyload_sqli_vulnerable", rating)
    out = inv.aggregate([unit("pyload_sqli_vulnerable")], tmp_path)
    assert out["ratings"] == {"pyload_sqli_vulnerable": rating}


@pytest.mark.parametrize(
    "rating, reason",
    [(-0.01, "x"), (1.01, "x"), (5, "x"), ("high", "x"), (None, "x"), (True, "x"), (0.5, ""), (0.5, None)],
)
def test_invalid_rating_record_is_rejected(inv, tmp_path, rating, reason):
    write_rating(tmp_path, "pyload_sqli_vulnerable", rating, reason)
    with pytest.raises(ValueError):
        inv.aggregate([unit("pyload_sqli_vulnerable")], tmp_path)


def test_rating_record_without_reason_field_is_rejected(inv, tmp_path):
    write_rating(tmp_path, "pyload_sqli_vulnerable", 0.5)
    path = tmp_path / "investigator" / "ratings" / "pyload_sqli_vulnerable.json"
    path.write_text(json.dumps({"case_id": "pyload_sqli_vulnerable", "rating": 0.5}), encoding="utf-8")
    with pytest.raises(ValueError):
        inv.aggregate([unit("pyload_sqli_vulnerable")], tmp_path)


def test_rating_file_with_other_case_id_is_rejected(inv, tmp_path):
    write_rating(tmp_path, "pyload_sqli_vulnerable", 0.5)
    d = tmp_path / "investigator" / "ratings"
    (d / "pyload_sqli_vulnerable.json").write_text(
        json.dumps({"case_id": "aegra_authz_vulnerable", "rating": 0.5, "reason": "x"}), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        inv.aggregate([unit("pyload_sqli_vulnerable")], tmp_path)


# AC-S9-3
def test_summary_reports_per_case_ratings_and_mean_over_rated(inv, tmp_path):
    write_rating(tmp_path, "pyload_sqli_vulnerable", 0.8)
    write_rating(tmp_path, "aegra_authz_vulnerable", 0.4)
    out = inv.aggregate([unit("pyload_sqli_vulnerable"), unit("aegra_authz_vulnerable")], tmp_path)
    assert out["ratings"] == {"pyload_sqli_vulnerable": 0.8, "aegra_authz_vulnerable": 0.4}
    assert out["mean"] == pytest.approx(0.6)


# AC-S9-4
def test_unrated_cases_are_listed_counted_and_excluded_from_mean(inv, tmp_path):
    write_rating(tmp_path, "pyload_sqli_vulnerable", 0.8)
    units = [unit("pyload_sqli_vulnerable"), unit("aegra_authz_vulnerable"), unit("alerta_sqli_safe")]
    out = inv.aggregate(units, tmp_path)
    assert sorted(out["unrated"]) == ["aegra_authz_vulnerable", "alerta_sqli_safe"]
    assert (out["rated"], out["with_result"]) == (1, 3)
    assert out["mean"] == pytest.approx(0.8)


def test_plan_invalid_cases_are_listed_separately_and_never_rated_zero(inv, tmp_path):
    write_rating(tmp_path, "pyload_sqli_vulnerable", 0.6)
    units = [unit("pyload_sqli_vulnerable"), unit("aegra_authz_vulnerable", "not_scored")]
    out = inv.aggregate(units, tmp_path)
    assert out["plan_invalid"] == ["aegra_authz_vulnerable"]
    assert "aegra_authz_vulnerable" not in out["unrated"]
    assert "aegra_authz_vulnerable" not in out["ratings"]
    assert (out["rated"], out["with_result"]) == (1, 1)
    assert out["mean"] == pytest.approx(0.6)


def test_no_ratings_gives_no_mean_not_zero(inv, tmp_path):
    out = inv.aggregate([unit("pyload_sqli_vulnerable")], tmp_path)
    assert out["mean"] is None
    assert out["rated"] == 0


# AC-S9-5
def test_benchmark_has_no_anthropic_dependency_or_key_use():
    source = (PKG / "investigator.py").read_text(encoding="utf-8").lower()
    assert "anthropic" not in source
    assert "api_key" not in source
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert not any("anthropic" in dep.lower() for dep in project["dependencies"])


def test_registry_declares_investigator_on_case_source_with_aggregate():
    bench("investigator")
    entry = bench("registry").REGISTRY["investigator"]
    assert entry.source == "cases"
    assert entry.aggregate is not None
