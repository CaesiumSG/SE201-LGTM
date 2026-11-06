"""Unit tests for the policy retrieval benchmark: gold labels, hit@k / recall@k / MRR, applicability."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "benchmark" / "component_bench" / "labels" / "retrieval.json"
CASES = json.loads((ROOT / "benchmark" / "real_world" / "cases.json").read_text(encoding="utf-8"))["cases"]
AUTHZ = sorted(c["id"] for c in CASES if c["category"] == "authz")
SQLI = sorted(c["id"] for c in CASES if c["category"] == "sqli")
POLICY = "SECURITY.md"


def retrieval():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module("benchmark.component_bench.retrieval")


def gold(label_id, start, end):
    return {"label_id": label_id, "gold": {"source": POLICY, "start_line": start, "end_line": end}}


def chunk(start, end, source=POLICY):
    return SimpleNamespace(source=source, start_line=start, end_line=end, content="", score=0.5)


def case_item(*labels, case_id="aegra_authz_vulnerable"):
    return {"case_id": case_id, "label_id": None, "labels": list(labels)}


class FakeRetriever:
    """Stands in for PolicyRetriever: no Chroma index, no embeddings."""

    ranked: list = []
    calls: list = []

    def __init__(self, repo, config=None):
        pass

    def retrieve(self, query, top_k=None, collection_name=None):
        FakeRetriever.calls.append(top_k)
        return FakeRetriever.ranked[:top_k]


@pytest.fixture
def run(monkeypatch):
    mod = retrieval()
    monkeypatch.setattr(mod, "PolicyRetriever", FakeRetriever)
    FakeRetriever.calls = []

    def go(item, ranked, k=3):
        FakeRetriever.ranked = ranked
        ctx = SimpleNamespace(config=SimpleNamespace(rag_top_k=k), metrics=None, llm=None, judge=None)
        output = mod.run_item(item, ctx)
        return output, mod.score(item, output)

    return go


def test_every_authz_case_has_a_gold_passage_label_and_no_sqli_case_does():
    items = json.loads(LABELS.read_text(encoding="utf-8"))["items"]
    labelled = {i["case_id"] for i in items}
    assert labelled == set(AUTHZ)
    assert not labelled & set(SQLI)


def test_gold_passage_ranked_first_gives_full_hit_and_reciprocal_rank(run):
    _, scores = run(case_item(gold("G1", 10, 20)), [chunk(12, 18), chunk(40, 50), chunk(60, 70)])
    assert (scores["hit_at_k"], scores["recall_at_k"], scores["mrr"]) == (1, 1, 1)


def test_chunk_overlapping_a_gold_passage_counts_as_a_hit_at_its_rank(run):
    _, scores = run(case_item(gold("G1", 10, 20)), [chunk(40, 50), chunk(18, 30), chunk(60, 70)])
    assert scores["hit_at_k"] == 1
    assert scores["mrr"] == pytest.approx(0.5)


@pytest.mark.parametrize(
    "ranked",
    [
        [chunk(21, 30)],
        [chunk(1, 9)],
        [chunk(10, 20, source="OTHER.md")],
    ],
)
def test_chunk_not_overlapping_the_gold_passage_is_not_a_hit(run, ranked):
    _, scores = run(case_item(gold("G1", 10, 20)), ranked)
    assert scores["hit_at_k"] == 0


def test_recall_is_the_fraction_of_gold_passages_found_in_top_k(run):
    item = case_item(gold("G1", 10, 20), gold("G2", 100, 110), gold("G3", 200, 210), gold("G4", 300, 310))
    ranked = [chunk(10, 15), chunk(500, 510), chunk(205, 206), chunk(300, 305)]
    _, scores = run(item, ranked, k=3)
    assert scores["recall_at_k"] == pytest.approx(2 / 4)
    assert scores["hit_at_k"] == 1


def test_gold_passage_below_top_k_is_not_counted(run):
    item = case_item(gold("G1", 10, 20), gold("G2", 100, 110))
    ranked = [chunk(10, 15), chunk(500, 510), chunk(100, 105)]
    _, scores = run(item, ranked, k=2)
    assert scores["recall_at_k"] == pytest.approx(1 / 2)


def test_no_gold_passage_retrieved_scores_zero_and_is_not_an_error(run):
    output, scores = run(case_item(gold("G1", 10, 20), gold("G2", 100, 110)), [chunk(500, 510), chunk(600, 610)])
    assert (scores["hit_at_k"], scores["recall_at_k"], scores["mrr"]) == (0, 0, 0)
    assert not isinstance(output, retrieval().NotScored)


def test_empty_retrieval_scores_zero(run):
    _, scores = run(case_item(gold("G1", 10, 20)), [])
    assert (scores["hit_at_k"], scores["recall_at_k"], scores["mrr"]) == (0, 0, 0)


def test_retrieval_uses_the_configured_top_k(run):
    run(case_item(gold("G1", 10, 20)), [chunk(10, 15)], k=7)
    assert FakeRetriever.calls == [7]


@pytest.mark.parametrize("case_id", SQLI)
def test_sqli_case_is_not_run_and_reported_not_applicable(run, case_id):
    mod = retrieval()
    ctx = SimpleNamespace(config=SimpleNamespace(rag_top_k=3), metrics=None, llm=None, judge=None)
    result = mod.run_item(case_item(case_id=case_id), ctx)
    assert isinstance(result, mod.NotScored)
    assert "not applicable" in result.reason.lower()
    assert FakeRetriever.calls == []


def test_scored_output_names_case_id_and_gold_label_ids(run):
    output, _ = run(case_item(gold("G1", 10, 20), gold("G2", 100, 110)), [chunk(10, 15)])
    assert output["case_id"] == "aegra_authz_vulnerable"
    assert sorted(output["label_ids"]) == ["G1", "G2"]


@pytest.fixture
def bench(monkeypatch, tmp_path):
    monkeypatch.setattr(retrieval(), "PolicyRetriever", FakeRetriever)
    FakeRetriever.calls = []
    from benchmark.component_bench.run import run_benchmark

    def go(labels_dir=None, ranked=()):
        FakeRetriever.ranked = list(ranked)
        results = tmp_path / "results"
        kwargs = {"labels_dir": labels_dir} if labels_dir else {}
        summary = run_benchmark(
            results, components=["retrieval"], config=SimpleNamespace(rag_top_k=3), **kwargs
        )
        rows = json.loads((results / "retrieval.json").read_text(encoding="utf-8"))["units"]
        return rows, summary

    return go


def test_every_scored_row_names_its_case_id_and_gold_label_ids(bench):
    default = json.loads(LABELS.read_text(encoding="utf-8"))["items"]
    rows, _ = bench()
    scored = [r for r in rows if r["status"] == "scored"]
    assert {r["case_id"] for r in scored} == set(AUTHZ)
    for row in scored:
        expected = [i["label_id"] for i in default if i["case_id"] == row["case_id"]]
        text = json.dumps(row)
        assert expected and all(label_id in text for label_id in expected), row


def test_labels_are_read_from_the_given_labels_dir_not_the_default_file(bench, tmp_path):
    case_id = AUTHZ[0]
    labels_dir = tmp_path / "custom-labels"
    labels_dir.mkdir()
    doc = {
        "component": "retrieval",
        "items": [
            {
                "label_id": "custom-label-1",
                "case_id": case_id,
                "review_state": "approved",
                "gold": {"source": POLICY, "start_line": 1000, "end_line": 1010},
            }
        ],
    }
    (labels_dir / "retrieval.json").write_text(json.dumps(doc), encoding="utf-8")

    rows, summary = bench(labels_dir, ranked=[chunk(1000, 1005)])

    row = next(r for r in rows if r["case_id"] == case_id)
    assert row["status"] == "scored"
    assert row["scores"]["hit_at_k"] == 1
    assert "custom-label-1" in json.dumps(row)
    assert not any(r["status"] == "scored" for r in rows if r["case_id"] != case_id)
    aggregate = json.dumps(summary["components"]["retrieval"])
    assert "custom-label-1" in aggregate
    assert "retrieval-" + case_id not in aggregate


def test_development_authz_cases_without_a_policy_file_are_not_scored_not_errors():
    dev = json.loads((ROOT / "benchmark" / "real_prs" / "cases.json").read_text(encoding="utf-8"))["cases"]
    authz_id = next(c["id"] for c in dev if c["category"] == "authz")
    mod = retrieval()
    out = mod.run_item({"case_id": authz_id, "label_id": None}, SimpleNamespace(labels_dir=None))
    assert isinstance(out, mod.NotScored)
