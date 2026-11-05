"""Unit tests for the authz reviewer benchmark: labels, scoring, run_item, registration."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILE = "app/runs.py"
OTHER_FILE = "app/other.py"
LOCATION = {"file": FILE, "start": 50, "end": 60}
KNOWN = {"id": "known_1", "file": FILE, "start": 100, "end": 108}
RUN_ITEM = {"case_id": "c", "label_id": "L", "gold_input": {}}


def bench(name: str):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module(f"benchmark.component_bench.{name}")


def cases() -> list[dict]:
    return bench("schema").load_cases()


def authz_ids() -> set[str]:
    return {c["id"] for c in cases() if c["category"] == "authz"}


def label_doc() -> dict:
    path = ROOT / "benchmark" / "component_bench" / "labels" / "authz.json"
    return json.loads(path.read_text(encoding="utf-8"))


def vulnerable_item() -> dict:
    return {
        "case_id": "c_vuln",
        "label_id": "L1",
        "gold": {"vulnerable": True, "locations": [dict(LOCATION)], "known_issues": []},
    }


def safe_item(known=(KNOWN,)) -> dict:
    return {
        "case_id": "c_safe",
        "label_id": "L2",
        "gold": {"vulnerable": False, "locations": [], "known_issues": list(known)},
    }


def finding(line: int, file: str = FILE) -> dict:
    return {"file": file, "line": line}


def score(item: dict, findings: list[dict]) -> dict:
    return bench("authz").score(item, findings)


# AC-S1-7: labels


def test_authz_label_file_is_valid_and_scoped_to_authz_cases():
    doc = label_doc()
    assert doc["component"] == "authz"
    bench("schema").validate_labels(doc, authz_ids())


def test_every_authz_case_has_a_label_and_no_sqli_case_has_one():
    labelled = {i["case_id"] for i in label_doc()["items"]}
    assert labelled == authz_ids()
    assert len(authz_ids()) == 6
    assert not labelled & {c["id"] for c in cases() if c["category"] == "sqli"}


def test_labels_are_drafts_with_gold_section_and_policy_passages():
    for item in label_doc()["items"]:
        assert item["review_state"] == "draft"
        assert item["gold_input"]["section"]
        assert item["gold_input"]["policy_passages"]


def test_vulnerable_labels_cover_every_vulnerable_line_of_the_case():
    by_id = {c["id"]: c for c in cases()}
    for item in label_doc()["items"]:
        case, gold = by_id[item["case_id"]], item["gold"]
        if case["expected_verdict"] != "vulnerable":
            continue
        assert gold["vulnerable"] is True
        for line in case["vulnerable_lines"]:
            assert any(
                loc["file"] == case["file"] and loc["start"] <= line <= loc["end"]
                for loc in gold["locations"]
            ), f"{item['label_id']}: line {line} not covered"


def test_safe_labels_have_no_locations_and_list_the_case_known_issues():
    by_id = {c["id"]: c for c in cases()}
    for item in label_doc()["items"]:
        case, gold = by_id[item["case_id"]], item["gold"]
        if case["expected_verdict"] != "safe":
            continue
        assert gold["vulnerable"] is False
        assert gold["locations"] == []
        assert {k["id"] for k in gold["known_issues"]} == {k["id"] for k in case["known_issues"]}


# AC-S4-1, AC-S4-2: vulnerable case


@pytest.mark.parametrize("line", [50, 55, 60], ids=["start", "inside", "end"])
def test_finding_on_gold_location_is_a_true_positive(line):
    s = score(vulnerable_item(), [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


@pytest.mark.parametrize(
    "bad",
    [finding(49), finding(61), finding(55, OTHER_FILE)],
    ids=["line-below", "line-above", "other-file"],
)
def test_finding_only_elsewhere_is_a_miss_and_a_false_positive(bad):
    s = score(vulnerable_item(), [bad])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


def test_each_stray_finding_counts_as_a_false_positive():
    s = score(vulnerable_item(), [finding(1), finding(2), finding(3, OTHER_FILE)])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 3)


def test_vulnerable_case_with_no_findings_is_a_miss():
    s = score(vulnerable_item(), [])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 0)


def test_any_one_of_several_gold_locations_is_enough():
    item = vulnerable_item()
    item["gold"]["locations"].append({"file": FILE, "start": 200, "end": 200})
    s = score(item, [finding(200)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


# AC-S4-3, AC-S4-4, AC-S4-5: safe case


def test_safe_case_with_no_findings_is_a_true_negative():
    s = score(safe_item(), [])
    assert (s["tn"], s["fp"], s["tp"], s["fn"]) == (1, 0, 0, 0)


@pytest.mark.parametrize("line", [100, 104, 108], ids=["start", "inside", "end"])
def test_finding_matching_a_known_issue_is_not_a_false_positive(line):
    s = score(safe_item(), [finding(line)])
    assert (s["fp"], s["tp"], s["fn"]) == (0, 0, 0)


@pytest.mark.parametrize(
    "bad",
    [finding(99), finding(109), finding(104, OTHER_FILE)],
    ids=["line-below", "line-above", "other-file"],
)
def test_safe_case_finding_outside_known_issues_is_a_false_positive(bad):
    s = score(safe_item(), [bad])
    assert (s["fp"], s["tn"]) == (1, 0)


def test_safe_case_without_known_issues_flags_every_finding():
    s = score(safe_item(known=()), [finding(104), finding(5)])
    assert s["fp"] == 2


def test_known_issue_finding_does_not_hide_another_false_positive():
    s = score(safe_item(), [finding(104), finding(5)])
    assert s["fp"] == 1


# run_item


class FakeToolbox:
    def build_tools(self):
        return [SimpleNamespace(name="read_file"), SimpleNamespace(name="grep")]


def make_agent(findings, errors=()):
    class FakeAgent:
        def __init__(self, toolbox, config=None, llm=None):
            self.llm, self.errors, self.run_records = llm, list(errors), [SimpleNamespace(turns=[])]

        def review_section(self, section, semgrep_notes=""):
            return findings

    return FakeAgent


class Spy:
    def __init__(self):
        self.calls = []

    def add_agent(self, name, records, offered):
        self.calls.append((name, len(list(records)), [getattr(t, "name", t) for t in offered]))


@pytest.fixture
def patched(monkeypatch):
    authz = bench("authz")
    monkeypatch.setattr(authz, "build_section", lambda gold_input: SimpleNamespace(section_id="s"))
    monkeypatch.setattr(authz, "build_toolbox", lambda item, ctx: FakeToolbox())
    return authz


def test_run_item_returns_file_and_line_of_each_finding(patched, monkeypatch):
    found = [SimpleNamespace(file=FILE, line=55, explanation="x")]
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent(found))
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy())
    out = patched.run_item(RUN_ITEM, ctx)
    assert [(f["file"], f["line"]) for f in out] == [(FILE, 55)]


def test_run_item_hands_run_records_and_offered_tools_to_metrics(patched, monkeypatch):
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent([]))
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy())
    patched.run_item(RUN_ITEM, ctx)
    assert ctx.metrics.calls == [("reviewer", 1, ["read_file", "grep"])]


def test_agent_error_is_an_infra_error_not_an_empty_result(patched, monkeypatch):
    errors = [{"source": "s", "message": "model unreachable"}]
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent([], errors))
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy())
    with pytest.raises(bench("outcomes").InfraError):
        patched.run_item(RUN_ITEM, ctx)


# AC-S4-6: only the authz cases run


def test_authz_is_registered_for_exactly_the_authz_cases():
    entry = bench("registry").REGISTRY["authz"]
    assert entry.source == "labels"
    assert set(entry.applicable) == authz_ids()


def test_run_covers_only_the_six_authz_cases_with_case_and_label_ids(patched, monkeypatch, tmp_path):
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent([]))
    summary = bench("run").run_benchmark(results_dir=tmp_path, components=["authz"], llm=object())
    rows = json.loads((tmp_path / "authz.json").read_text())["units"]
    items = label_doc()["items"]
    assert {r["case_id"] for r in rows} == authz_ids()
    assert [(r["case_id"], r["label_id"]) for r in rows] == [(i["case_id"], i["label_id"]) for i in items]
    assert summary["components"]["authz"]["units_scored"] == len(items)


# final-01: removed-line findings cite base-side numbers

OLD_LOCATION = {"file": FILE, "start": 200, "end": 206}


def two_sided_item() -> dict:
    item = vulnerable_item()
    item["gold"]["old_locations"] = [dict(OLD_LOCATION)]
    return item


@pytest.mark.parametrize("line", [200, 203, 206], ids=["start", "inside", "end"])
def test_finding_on_base_side_range_of_removed_check_is_a_true_positive(line):
    s = score(two_sided_item(), [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


@pytest.mark.parametrize("line", [50, 55, 60], ids=["start", "inside", "end"])
def test_finding_on_pr_side_range_still_scores_with_base_side_range_present(line):
    s = score(two_sided_item(), [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


@pytest.mark.parametrize(
    "bad",
    [finding(199), finding(207), finding(203, OTHER_FILE)],
    ids=["below", "above", "other-file"],
)
def test_finding_outside_both_sides_is_a_miss_and_a_false_positive(bad):
    s = score(two_sided_item(), [bad])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


@pytest.mark.parametrize(
    "case_id, file, line",
    [
        ("aegra_authz_vulnerable", "libs/aegra-api/src/aegra_api/api/runs.py", 54),
        ("aegra_authz_vulnerable", "libs/aegra-api/src/aegra_api/api/runs.py", 57),
        ("litellm_authz_vulnerable", "litellm/proxy/management_endpoints/internal_user_endpoints.py", 1138),
        ("litellm_authz_vulnerable", "litellm/proxy/management_endpoints/internal_user_endpoints.py", 1521),
        ("litellm_authz_vulnerable", "litellm/proxy/management_endpoints/internal_user_endpoints.py", 1536),
    ],
)
def test_shipped_label_scores_a_finding_on_the_removed_check_old_line(case_id, file, line):
    item = next(i for i in label_doc()["items"] if i["case_id"] == case_id)
    s = score(item, [finding(line, file)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


# final-02: missing clone or unreachable SHA is an infra error, not a score


def unscored_run(authz, monkeypatch):
    class NeverRuns:
        def __init__(self, *a, **k):
            raise AssertionError("agent must not run without a usable clone")

    monkeypatch.setattr(authz, "build_section", lambda gold_input: SimpleNamespace(section_id="s"))
    monkeypatch.setattr(authz, "AuthzReviewerAgent", NeverRuns)
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy())
    item = {"case_id": "aegra_authz_vulnerable", "label_id": "L", "gold_input": {"policy_passages": ["p"]}}
    return item, ctx


def test_missing_case_clone_is_an_infra_error(monkeypatch, tmp_path):
    authz = bench("authz")
    monkeypatch.setattr(authz, "CLONE_CACHE", tmp_path)
    item, ctx = unscored_run(authz, monkeypatch)
    with pytest.raises(bench("outcomes").InfraError):
        authz.run_item(item, ctx)
    assert ctx.metrics.calls == []


@pytest.mark.parametrize("missing", ["base_ref", "pr_ref"])
def test_unreachable_sha_in_existing_clone_is_an_infra_error(monkeypatch, tmp_path, missing):
    authz = bench("authz")
    case = next(c for c in cases() if c["id"] == "aegra_authz_vulnerable")
    project = case["repo_url"].rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    (tmp_path / project).mkdir()
    monkeypatch.setattr(authz, "CLONE_CACHE", tmp_path)

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=1 if case[missing] in " ".join(cmd) else 0)

    monkeypatch.setattr(authz.subprocess, "run", fake_run)
    item, ctx = unscored_run(authz, monkeypatch)
    with pytest.raises(bench("outcomes").InfraError):
        authz.run_item(item, ctx)
    assert ctx.metrics.calls == []
