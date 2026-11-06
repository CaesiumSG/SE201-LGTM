"""Unit tests for the policy retrieval benchmark: gold labels, hit@k / recall@k / MRR, applicability."""

from __future__ import annotations

import importlib
import json
import subprocess
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


def snapshot(repo) -> dict[str, str]:
    root = Path(repo)
    if not root.is_dir():
        return {}
    return {
        p.relative_to(root).as_posix(): p.read_text(encoding="utf-8", errors="replace")
        for p in root.rglob("*")
        if p.is_file() and not {".git", ".lgtm"} & set(p.relative_to(root).parts)
    }


class FakeRetriever:
    """Stands in for PolicyRetriever: no Chroma index, no embeddings. Records what it was built over."""

    ranked: list = []
    calls: list = []
    built_over: list = []

    def __init__(self, repo, config=None):
        FakeRetriever.built_over.append(snapshot(repo))

    def retrieve(self, query, top_k=None, collection_name=None):
        FakeRetriever.calls.append(top_k)
        return FakeRetriever.ranked[:top_k]


BASE_TEXT = "BASE-REVISION-POLICY"
PR_TEXT = "PR-REVISION-POLICY"


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture(scope="module")
def template_repo(tmp_path_factory):
    """Repo whose checked-out head is the base revision; the PR revision is a later commit."""
    repo = tmp_path_factory.mktemp("template")
    git(repo, "init", "-q")
    (repo / "SECURITY.md").write_text(f"# Policy\n{BASE_TEXT}\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "SECURITY.md").write_text(f"# Policy\n{PR_TEXT}\n", encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "docs" / "pr-only.md").write_text("added by the PR\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "pr")
    pr = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", base)
    return repo, base, pr


@pytest.fixture
def clones(monkeypatch, tmp_path, template_repo):
    """A local clone of the template repo for every case project, and every case pinned to its revisions."""
    template, base, pr = template_repo
    cache = tmp_path / "clone-cache"
    cache.mkdir()
    schema = importlib.import_module("benchmark.component_bench.schema")
    real_cases = list(schema.load_cases())

    def load_cases():
        out = []
        for c in real_cases:
            project = c["repo_url"].rstrip("/").rsplit("/", 1)[-1]
            if not (cache / project).exists():
                subprocess.run(["git", "clone", "-q", str(template), str(cache / project)], check=True, capture_output=True)
            out.append({**c, "base_ref": base, "pr_ref": pr})
        return out

    for mod in (retrieval(), importlib.import_module("benchmark.component_bench.run"), schema):
        monkeypatch.setattr(mod, "CLONE_CACHE", cache, raising=False)
    monkeypatch.setattr(schema, "load_cases", load_cases)
    return SimpleNamespace(cache=cache, base=base, pr=pr)


@pytest.fixture
def run(monkeypatch, clones):
    mod = retrieval()
    monkeypatch.setattr(mod, "PolicyRetriever", FakeRetriever)
    monkeypatch.setattr(mod, "index_repo_docs", lambda repo, config=None: FakeRetriever.built_over.append(snapshot(repo)))
    FakeRetriever.calls = []
    FakeRetriever.built_over = []

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
def bench(monkeypatch, tmp_path, clones):
    monkeypatch.setattr(retrieval(), "PolicyRetriever", FakeRetriever)
    monkeypatch.setattr(retrieval(), "index_repo_docs", lambda repo, config=None: 0)
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


NO_LABELS_REASON = "no gold labels for the case-repo index"


def test_real_labels_naming_the_removed_side_index_are_not_scored_instead_of_scoring_zero(bench):
    rows, summary = bench(ranked=[chunk(1, 100000), chunk(1, 100000, source="README.md")])
    authz_rows = [r for r in rows if r["case_id"] in AUTHZ]
    assert authz_rows
    for row in authz_rows:
        assert row["status"] == "not_scored", row
        assert NO_LABELS_REASON in row["reason"]
        assert row["scores"] is None
    assert summary["components"]["retrieval"]["units_scored"] == 0


def test_labels_whose_source_is_absent_from_the_case_repo_at_pr_ref_are_not_scored(run):
    mod = retrieval()
    item = case_item({"label_id": "G1", "gold": {"source": "security-policy.md", "start_line": 1, "end_line": 5}})
    FakeRetriever.ranked = [chunk(1, 5, source="SECURITY.md")]
    ctx = SimpleNamespace(config=SimpleNamespace(rag_top_k=3), metrics=None, llm=None, judge=None)
    result = mod.run_item(item, ctx)
    assert isinstance(result, mod.NotScored)
    assert NO_LABELS_REASON in result.reason


def test_labels_naming_a_case_repo_document_at_pr_ref_are_still_scored(run):
    output, scores = run(case_item(gold("G1", 10, 20)), [chunk(12, 18)])
    assert not isinstance(output, retrieval().NotScored)
    assert scores["hit_at_k"] == 1


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



def authz_item():
    return case_item(gold("G1", 10, 20))


def test_retrieval_indexes_the_case_repo_at_the_pr_revision(run):
    run(authz_item(), [chunk(10, 15)])
    assert FakeRetriever.built_over
    for files in FakeRetriever.built_over:
        assert PR_TEXT in files["SECURITY.md"]
        assert BASE_TEXT not in files["SECURITY.md"]
        assert "docs/pr-only.md" in files


def test_retrieval_does_not_index_the_policies_side_directory(run):
    side = {p.name: p.read_text(encoding="utf-8") for p in retrieval().POLICY_DIR.glob("*.md")}
    assert side
    run(authz_item(), [chunk(10, 15)])
    assert FakeRetriever.built_over
    for files in FakeRetriever.built_over:
        assert not any(files.get(name) == text for name, text in side.items())


def test_development_authz_case_without_a_policy_side_file_is_retrieved_from_its_repo(run):
    dev = json.loads((ROOT / "benchmark" / "real_prs" / "cases.json").read_text(encoding="utf-8"))["cases"]
    authz_id = next(c["id"] for c in dev if c["category"] == "authz")
    output, scores = run(case_item(gold("G1", 10, 20), case_id=authz_id), [chunk(10, 15)])
    assert output["case_id"] == authz_id
    assert scores["hit_at_k"] == 1


def failing_retriever(reason, in_index):
    class Failing(FakeRetriever):
        def __init__(self, repo, config=None):
            if not in_index:
                raise RuntimeError(reason)
            super().__init__(repo, config)

    return Failing


@pytest.mark.parametrize("in_index", [True, False], ids=["index-step", "retriever-build"])
def test_index_build_failure_is_recorded_as_error_with_its_reason_not_a_zero_score(monkeypatch, bench, in_index):
    mod = retrieval()
    reason = "embedder-offline-xyz"

    def boom(repo, config=None):
        raise RuntimeError(reason)

    monkeypatch.setattr(mod, "PolicyRetriever", failing_retriever(reason, in_index))
    monkeypatch.setattr(mod, "index_repo_docs", boom if in_index else (lambda repo, config=None: 0))
    rows, summary = bench(ranked=[chunk(10, 15)])
    authz_rows = [r for r in rows if r["case_id"] in AUTHZ]
    assert authz_rows
    for row in authz_rows:
        assert row["status"] == "error", row
        assert reason in row["reason"]
        assert row["scores"] is None
    section = summary["components"]["retrieval"]
    assert section["units_errored"] >= len(AUTHZ)
    assert section["units_scored"] == 0


def test_index_build_failure_for_one_case_leaves_other_cases_scored(monkeypatch, bench, tmp_path):
    mod = retrieval()
    labels_dir = tmp_path / "fixture-labels"
    labels_dir.mkdir()
    items = [
        {"label_id": f"fx-{cid}", "case_id": cid, "review_state": "approved",
         "gold": {"source": POLICY, "start_line": 1, "end_line": 2}}
        for cid in AUTHZ
    ]
    (labels_dir / "retrieval.json").write_text(json.dumps({"component": "retrieval", "items": items}), encoding="utf-8")
    state = {"n": 0}

    class FailsOnce(FakeRetriever):
        def __init__(self, repo, config=None):
            state["n"] += 1
            if state["n"] == 1:
                raise RuntimeError("first-case-index-broke")
            super().__init__(repo, config)

    monkeypatch.setattr(mod, "PolicyRetriever", FailsOnce)
    rows, _ = bench(labels_dir, ranked=[chunk(1, 2)])
    errors = [r for r in rows if r["case_id"] in AUTHZ and r["status"] == "error"]
    assert len(errors) == 1 and "first-case-index-broke" in errors[0]["reason"]
    assert errors[0]["scores"] is None
    assert any(r["status"] == "scored" for r in rows if r["case_id"] in AUTHZ)
