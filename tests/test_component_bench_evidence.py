"""Unit tests for the evidence validator benchmark: labels, run_item verdicts, scoring, run rows."""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.config import LGTMConfig

ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "benchmark" / "component_bench" / "labels" / "evidence.json"
CASE = "pyload_sqli_vulnerable"
PROJECT = "pyload"

BASE_A = "".join(f"base_line_{n} = {n}\n" for n in range(1, 11))
QUERY = "query = 'SELECT * FROM links WHERE id IN (' + ids + ')'"
PR_A = BASE_A + QUERY + "\n"
PR_NEW = "def added():\n    return 1\n"


def bench(name: str):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module(f"benchmark.component_bench.{name}")


def git(repo: Path, *args: str) -> None:
    cmd = ["git", "-c", "user.name=t", "-c", "user.email=t@localhost", "-c", "commit.gpgsign=false"]
    subprocess.run([*cmd, *args], cwd=repo, check=True, capture_output=True)


def make_clone(cache: Path, case_id: str = CASE, project: str = PROJECT, roles=("base", "pr")) -> Path:
    """Clone-cache layout: <cache>/<project> with local branches rw/<case>/base and rw/<case>/pr."""
    repo = cache / project
    (repo / "src").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "src" / "a.py").write_text(BASE_A)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    if "base" in roles:
        git(repo, "branch", f"rw/{case_id}/base")
    (repo / "src" / "a.py").write_text(PR_A)
    (repo / "src" / "new.py").write_text(PR_NEW)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "pr")
    if "pr" in roles:
        git(repo, "branch", f"rw/{case_id}/pr")
    return repo


def item(evidence: dict, *, label_id="E1", case_id=CASE, accept=True, fault=None, reason=None) -> dict:
    gold = {"accept": accept}
    if not accept:
        gold.update(fault=fault, reason=reason)
    out = {
        "label_id": label_id,
        "case_id": case_id,
        "source": "fix commit",
        "review_state": "draft",
        "gold_input": {"evidence": evidence},
        "gold": gold,
    }
    if not accept:
        out["distractor"] = True
    return out


def ctx():
    return SimpleNamespace(config=LGTMConfig(), metrics=None, llm=None, judge=None)


@pytest.fixture
def ev(monkeypatch, tmp_path):
    module = bench("evidence")
    cache = tmp_path / "cache"
    make_clone(cache)
    monkeypatch.setattr(module, "CLONE_CACHE", cache)
    return module


GOOD_PR = {"type": "code", "file": "src/a.py", "lines": [11, 11], "snapshot": "pr", "content": QUERY}
GOOD_BASE = {"type": "code", "file": "src/a.py", "lines": [2, 3], "snapshot": "base", "content": "base_line_2 = 2\nbase_line_3 = 3"}
NEW_FILE = {"type": "code", "file": "src/new.py", "lines": [1, 2], "snapshot": "pr", "content": "def added():\n    return 1"}


# AC-S6-1
@pytest.mark.parametrize("evidence", [GOOD_PR, GOOD_BASE, NEW_FILE], ids=["pr", "base", "pr-new-file"])
def test_gold_citation_is_accepted(ev, evidence):
    out = ev.run_item(item(evidence), ctx())
    assert out["accepted"] is True


# AC-S6-2: fault kind -> (distractor evidence, fragment expected in the validator reason)
FAULTS = {
    "snippet_not_in_file": ({**GOOD_PR, "content": "cursor.execute(totally_unrelated_text_that_is_nowhere)"}, "code snippet not found in src/a.py at pr snapshot"),
    "nonexistent_file": ({**GOOD_PR, "file": "src/missing.py"}, "src/missing.py does not exist at pr snapshot"),
    "lines_out_of_range": ({**GOOD_BASE, "lines": [90, 95]}, "lines 90-95 out of range for src/a.py at base snapshot"),
    "wrong_snapshot": ({**NEW_FILE, "snapshot": "base"}, "src/new.py does not exist at base snapshot"),
}


@pytest.mark.parametrize("fault", FAULTS)
def test_each_distractor_kind_is_rejected_with_both_reasons(ev, fault):
    evidence, fragment = FAULTS[fault]
    stated = f"stated reason for {fault}"
    out = ev.run_item(item(evidence, accept=False, fault=fault, reason=stated), ctx())
    assert out["accepted"] is False
    assert out["detail"]["stated_reason"] == stated
    assert any(fragment in r for r in out["detail"]["validator_reasons"])


# AC-S6-2: the runner persists the reasons on the unit record
def test_evidence_unit_record_holds_reasons_under_detail(tmp_path, monkeypatch):
    def verdict(it, c):
        return {"accepted": False, "detail": {"validator_reasons": ["v"], "stated_reason": "s"}}

    rows = run_registered(tmp_path, monkeypatch, verdict)
    assert {json.dumps(r["detail"]) for r in rows} == {json.dumps({"validator_reasons": ["v"], "stated_reason": "s"})}


# AC-S6-1, AC-S6-3
@pytest.mark.parametrize(
    "gold_accept, accepted, expect",
    [
        (True, True, {"tp": 1, "fn": 0, "fp": 0, "tn": 0}),
        (True, False, {"tp": 0, "fn": 1, "fp": 0, "tn": 0}),
        (False, True, {"tp": 0, "fn": 0, "fp": 1, "tn": 0}),
        (False, False, {"tp": 0, "fn": 0, "fp": 0, "tn": 1}),
    ],
    ids=["gold-accepted", "gold-rejected-miss", "distractor-accepted-fp", "distractor-rejected"],
)
def test_score_maps_miss_and_false_positive(gold_accept, accepted, expect):
    it = item({}, accept=gold_accept, fault="f", reason="r")
    scores = bench("evidence").score(it, {"accepted": accepted, "validator_reasons": [], "stated_reason": None})
    assert {k: scores[k] for k in expect} == expect


def test_distractor_the_validator_accepts_scores_as_false_positive(ev):
    it = item(GOOD_PR, accept=False, fault="snippet_not_in_file", reason="r")
    out = ev.run_item(it, ctx())
    assert out["accepted"] is True
    assert ev.score(it, out)["fp"] == 1


# AC-S6-3: positive class is accept
def unit(tp=0, fn=0, fp=0, tn=0, status="scored"):
    scores = {"tp": tp, "fn": fn, "fp": fp, "tn": tn} if status == "scored" else None
    return {"status": status, "scores": scores}


def test_aggregate_pins_precision_recall_f1(tmp_path):
    units = [unit(tp=1)] * 3 + [unit(fn=1), unit(fp=1), unit(tn=1), unit(status="error")]
    agg = bench("evidence").aggregate(units, tmp_path)
    assert (agg["tp"], agg["fn"], agg["fp"], agg["tn"]) == (3, 1, 1, 1)
    assert (agg["precision"], agg["recall"], agg["f1"]) == (0.75, 0.75, 0.75)


def test_aggregate_f1_is_zero_not_none_when_precision_and_recall_are_zero(tmp_path):
    agg = bench("evidence").aggregate([unit(fn=1), unit(fp=1)], tmp_path)
    assert (agg["precision"], agg["recall"]) == (0.0, 0.0)
    assert agg["f1"] == 0.0


def test_aggregate_precision_is_none_without_predicted_positives(tmp_path):
    agg = bench("evidence").aggregate([unit(fn=1), unit(tn=1)], tmp_path)
    assert agg["precision"] is None
    assert agg["recall"] == 0.0


# AC-S6-5
def test_missing_clone_is_infra_error_with_reason(ev, monkeypatch, tmp_path):
    monkeypatch.setattr(ev, "CLONE_CACHE", tmp_path / "empty")
    with pytest.raises(bench("outcomes").InfraError) as exc:
        ev.run_item(item(GOOD_PR), ctx())
    assert str(exc.value)


@pytest.mark.parametrize("roles", [("base",), ("pr",)])
def test_missing_case_branch_is_infra_error_naming_branch(ev, monkeypatch, tmp_path, roles):
    cache = tmp_path / "partial"
    make_clone(cache, roles=roles)
    monkeypatch.setattr(ev, "CLONE_CACHE", cache)
    missing = ({"base", "pr"} - set(roles)).pop()
    with pytest.raises(bench("outcomes").InfraError) as exc:
        ev.run_item(item(GOOD_PR), ctx())
    assert f"rw/{CASE}/{missing}" in str(exc.value)


# AC-S1-9
def labels() -> dict:
    return json.loads(LABELS.read_text(encoding="utf-8"))


def test_label_file_is_valid_and_every_case_has_a_gold_label():
    doc = labels()
    bench("schema").validate_labels(doc)
    assert doc["component"] == "evidence"
    cases = {c["id"] for c in bench("schema").load_cases()}
    assert len(cases) == 12
    assert {i["case_id"] for i in doc["items"] if not i.get("distractor")} == cases


def test_each_distractor_states_one_fault_and_reason():
    for it in labels()["items"]:
        if it.get("distractor"):
            assert it["gold"]["accept"] is False
            assert it["gold"]["fault"] in FAULTS
            assert it["gold"]["reason"].strip()
        else:
            assert it["gold"]["accept"] is True


# AC-S6-4, AC-S6-5 through the runner
def run_registered(tmp_path, monkeypatch, run_item=None):
    run, reg, ev = bench("run"), bench("registry"), bench("evidence")
    monkeypatch.setattr(ev, "CLONE_CACHE", tmp_path / "no_clones")
    if run_item:
        monkeypatch.setattr(ev, "run_item", run_item)
    results = tmp_path / "results"
    run.run_benchmark(results_dir=results, registry={"evidence": reg.REGISTRY["evidence"]})
    return json.loads((results / "evidence.json").read_text())["units"]


def test_run_covers_all_12_cases_with_case_and_label_ids(tmp_path, monkeypatch):
    def verdict(it, c):
        return {"accepted": it["gold"]["accept"], "validator_reasons": [], "stated_reason": None}

    rows = run_registered(tmp_path, monkeypatch, verdict)
    assert {(r["case_id"], r["label_id"]) for r in rows} == {(i["case_id"], i["label_id"]) for i in labels()["items"]}
    assert {r["case_id"] for r in rows} == {c["id"] for c in bench("schema").load_cases()}
    assert all(r["status"] == "scored" for r in rows)


def test_unfetched_cases_are_errors_with_reason_and_no_scores(tmp_path, monkeypatch):
    rows = run_registered(tmp_path, monkeypatch)
    assert rows
    for r in rows:
        assert r["status"] == "error"
        assert r["reason"]
        assert r["scores"] is None
