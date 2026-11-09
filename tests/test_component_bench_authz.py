"""Unit tests for the authz reviewer benchmark: labels, scoring, run_item, registration."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.agents.registry import render

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


def test_nine_development_authz_cases_carry_draft_labels_and_are_registered():
    dev = {c["id"] for c in cases() if c["split"] == "real_prs" and c["category"] == "authz"}
    assert len(dev) == 9
    items = label_doc()["items"]
    assert dev <= {i["case_id"] for i in items}
    assert {i["review_state"] for i in items if i["case_id"] in dev} == {"draft"}
    assert dev <= set(bench("registry").REGISTRY["authz"].applicable)


def test_authz_label_file_is_valid_and_scoped_to_authz_cases():
    doc = label_doc()
    assert doc["component"] == "authz"
    bench("schema").validate_labels(doc, authz_ids())


def test_every_authz_case_has_a_label_and_no_sqli_case_has_one():
    labelled = {i["case_id"] for i in label_doc()["items"]}
    assert labelled == authz_ids()
    assert len(authz_ids()) == 15
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
        if case.get("expected_verdict") != "vulnerable":
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
        if case.get("expected_verdict") != "safe":
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


@pytest.mark.parametrize(
    "item, findings, expect",
    [
        (vulnerable_item(), [finding(55)], 1.0),
        (vulnerable_item(), [], 0.0),
        (safe_item(), [], 1.0),
        (safe_item(), [finding(5)], 0.0),
    ],
    ids=["vuln-hit", "vuln-miss", "safe-clean", "safe-false-positive"],
)
def test_verdict_correct_is_one_only_when_the_verdict_matches_gold(item, findings, expect):
    assert score(item, findings)["verdict_correct"] == expect


def unit(tp=0, fn=0, fp=0, tn=0, status="scored"):
    scores = {"tp": tp, "fn": fn, "fp": fp, "tn": tn} if status == "scored" else None
    return {"status": status, "scores": scores}


def test_aggregate_pins_precision_recall_f1_over_summed_counts_of_scored_units(tmp_path):
    units = [unit(tp=1)] * 3 + [unit(fn=1), unit(fp=1), unit(tn=1), unit(status="error")]
    agg = bench("authz").aggregate(units, tmp_path)
    assert (agg["precision"], agg["recall"], agg["f1"]) == (0.75, 0.75, 0.75)


def test_aggregate_is_none_where_undefined(tmp_path):
    agg = bench("authz").aggregate([unit(fn=1), unit(tn=1)], tmp_path)
    assert agg["precision"] is None
    assert agg["f1"] is None
    assert agg["recall"] == 0.0


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
    errors = [{"source": "s", "kind": "failed", "message": "model unreachable"}]
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent([], errors))
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy())
    with pytest.raises(bench("outcomes").InfraError):
        patched.run_item(RUN_ITEM, ctx)


def test_unparsable_reviewer_answer_is_not_scored(patched, monkeypatch):
    message = render("authz_reviewer.unparsable_explanation", where="section s")
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent([], [{"source": "s", "kind": "unparsable", "message": message}]))
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy())
    assert isinstance(patched.run_item(RUN_ITEM, ctx), bench("outcomes").NotScored)


# AC-S4-6: only the authz cases run


def test_authz_is_registered_for_exactly_the_authz_cases():
    entry = bench("registry").REGISTRY["authz"]
    assert entry.source == "labels"
    assert set(entry.applicable) == authz_ids()


def test_run_covers_only_the_fifteen_authz_cases_with_case_and_label_ids(patched, monkeypatch, tmp_path):
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent([]))
    monkeypatch.setattr(bench("run"), "_preflight", lambda case: None)
    summary = bench("run").run_benchmark(results_dir=tmp_path, components=["authz"], llm=object())
    rows = json.loads((tmp_path / "authz.json").read_text())["units"]
    items = label_doc()["items"]
    assert {r["case_id"] for r in rows} == authz_ids()
    assert [(r["case_id"], r["label_id"]) for r in rows] == [(i["case_id"], i["label_id"]) for i in items]
    assert summary["components"]["authz"]["units_scored"] == len(items)
    assert summary["components"]["authz"]["aggregate"]["recall"] == 0.0


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


def unscored_run(authz, monkeypatch, tmp_path):
    class NeverRuns:
        def __init__(self, *a, **k):
            raise AssertionError("agent must not run without a usable clone")

    monkeypatch.setattr(authz, "build_section", lambda gold_input: SimpleNamespace(section_id="s"))
    monkeypatch.setattr(authz, "AuthzReviewerAgent", NeverRuns)
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy(), results_dir=tmp_path)
    item = {"case_id": "aegra_authz_vulnerable", "label_id": "L", "gold_input": {"policy_passages": ["p"]}}
    return item, ctx


def test_missing_case_clone_is_an_infra_error(monkeypatch, tmp_path):
    authz = bench("authz")
    monkeypatch.setattr(authz, "CLONE_CACHE", tmp_path)
    item, ctx = unscored_run(authz, monkeypatch, tmp_path)
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
    item, ctx = unscored_run(authz, monkeypatch, tmp_path)
    with pytest.raises(bench("outcomes").InfraError):
        authz.run_item(item, ctx)
    assert ctx.metrics.calls == []


def test_gold_lines_of_every_label_sit_on_added_or_context_lines_of_a_shown_hunk():
    authz = bench("authz")
    problems = []
    for item in label_doc()["items"]:
        section = authz.build_section(item["gold_input"])
        shown = {}
        for h in section.hunks:
            assert h.new_count == sum(c.kind != "del" for c in h.changes), item["label_id"]
            assert h.old_count == sum(c.kind != "add" for c in h.changes), item["label_id"]
            shown.setdefault(h.file, set()).update(
                c.new_lineno for c in h.changes if c.kind != "del"
            )
        gold = item["gold"]
        for r in gold.get("locations", []) + gold.get("known_issues", []):
            missing = [n for n in (r["start"], r["end"]) if n not in shown.get(r["file"], ())]
            if missing:
                problems.append(f"{item['label_id']} {r['file']} {r['start']}-{r['end']}: {missing}")
    assert not problems, "\n".join(problems)


# AC-3-1, AC-3-2, AC-3-6: same-function tolerance. The enclosing function is derived from the source text
# returned by read_source(file, side), side "pr" for gold and known-issue ranges, "base" for old_locations.


def source_with(functions: dict[str, tuple[int, int]]) -> str:
    """Python source whose named functions occupy the given inclusive line ranges."""
    lines = ["# filler"] * max(end for _, end in functions.values())
    for name, (start, end) in functions.items():
        lines[start - 1] = f"def {name}():"
        lines[start:end] = ["    pass"] * (end - start)
    return "\n".join(lines) + "\n"


PR_FUNCTIONS = {"create_run": (40, 70), "cancel_run": (80, 130)}
BASE_FUNCTIONS = {"create_run": (190, 230), "cancel_run": (240, 300)}


def read_source(file: str, side: str) -> str:
    if file != FILE:
        raise FileNotFoundError(file)
    return source_with(PR_FUNCTIONS if side == "pr" else BASE_FUNCTIONS)


def tscore(item: dict, findings: list[dict]) -> dict:
    return bench("authz").score(item, findings, read_source=read_source)


@pytest.mark.parametrize("line", [40, 49, 61, 70], ids=["fn-start", "below-range", "above-range", "fn-end"])
def test_finding_in_the_gold_function_outside_the_exact_range_is_a_true_positive(line):
    s = tscore(vulnerable_item(), [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)
    assert s["verdict_correct"] == 1.0


@pytest.mark.parametrize("line", [55, 50, 60], ids=["inside", "start", "end"])
def test_exact_range_hit_stays_a_hit_with_source_available(line):
    s = tscore(vulnerable_item(), [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


@pytest.mark.parametrize("line", [71, 85, 39], ids=["after-function", "other-function", "before-function"])
def test_finding_in_another_function_or_outside_any_is_a_miss_and_a_false_positive(line):
    s = tscore(vulnerable_item(), [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)
    assert s["verdict_correct"] == 0.0


def test_finding_in_the_same_function_span_of_another_file_is_a_miss_and_a_false_positive():
    s = tscore(vulnerable_item(), [finding(65, OTHER_FILE)])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


def test_base_side_finding_in_the_function_of_the_removed_check_outside_its_range_is_a_true_positive():
    s = tscore(two_sided_item(), [finding(215)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


def test_base_side_line_in_another_base_function_is_a_miss_and_a_false_positive():
    s = tscore(two_sided_item(), [finding(250)])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


def test_hit_and_stray_findings_together_score_one_true_positive_and_one_false_positive_per_stray():
    s = tscore(vulnerable_item(), [finding(65), finding(85), finding(95, OTHER_FILE)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 2)


def test_safe_case_finding_in_the_function_of_a_known_issue_is_not_counted():
    s = tscore(safe_item(), [finding(85)])
    assert (s["fp"], s["tn"], s["tp"], s["fn"]) == (0, 1, 0, 0)
    assert s["verdict_correct"] == 1.0


def test_safe_case_finding_in_another_function_is_a_false_positive():
    s = tscore(safe_item(), [finding(55)])
    assert (s["fp"], s["tn"]) == (1, 0)
    assert s["verdict_correct"] == 0.0


def test_safe_case_finding_in_another_file_is_a_false_positive():
    s = tscore(safe_item(), [finding(104, OTHER_FILE)])
    assert s["fp"] == 1


# AC-3-3, AC-3-4: unparsable is read from the error kind, never from the message wording


def run_with_errors(patched, monkeypatch, errors):
    monkeypatch.setattr(patched, "AuthzReviewerAgent", make_agent([], errors))
    ctx = SimpleNamespace(llm=object(), config=None, metrics=Spy())
    return patched.run_item(RUN_ITEM, ctx)


@pytest.mark.parametrize(
    "message",
    ["Reviewer answer could not be parsed.", "", render("authz_reviewer.unparsable_explanation", where="section s")],
    ids=["reworded", "empty", "current-prompt-text"],
)
def test_unparsable_kind_is_not_scored_whatever_the_message(patched, monkeypatch, message):
    out = run_with_errors(patched, monkeypatch, [{"source": "s", "kind": "unparsable", "message": message}])
    assert isinstance(out, bench("outcomes").NotScored)


@pytest.mark.parametrize(
    "message",
    ["model unreachable", render("authz_reviewer.unparsable_explanation", where="section s")],
    ids=["unreachable", "unparsable-wording"],
)
def test_failed_kind_is_an_infra_error_even_when_the_message_reads_as_unparsable(patched, monkeypatch, message):
    with pytest.raises(bench("outcomes").InfraError):
        run_with_errors(patched, monkeypatch, [{"source": "s", "kind": "failed", "message": message}])


def test_a_failed_error_alongside_an_unparsable_one_is_an_infra_error(patched, monkeypatch):
    errors = [
        {"source": "s", "kind": "unparsable", "message": "x"},
        {"source": "s", "kind": "failed", "message": "model unreachable"},
    ]
    with pytest.raises(bench("outcomes").InfraError):
        run_with_errors(patched, monkeypatch, errors)


# run path hands score the case reader


def run_unit_with(module, item):
    run = bench("run")
    return run._run_unit(module, item, None, None, None, lambda: 0.0, Path("."))


def test_run_path_passes_the_case_reader_to_score():
    reader, seen = object(), {}

    def fake_score(item, output, read_source=None):
        seen["read_source"] = read_source
        return {"tp": 1}

    module = SimpleNamespace(
        run_item=lambda item, ctx: [],
        score=fake_score,
        case_reader=lambda item: reader if item["case_id"] == "c" else None,
    )
    unit = run_unit_with(module, {"case_id": "c", "label_id": "L"})
    assert unit["status"] == "scored"
    assert seen["read_source"] is reader


def base_only_item() -> dict:
    item = vulnerable_item()
    item["gold"]["locations"] = []
    item["gold"]["old_locations"] = [{"file": FILE, "start": 200, "end": 210}]
    return item


def test_pr_side_finding_in_the_function_named_like_the_base_range_function_is_a_true_positive():
    s = tscore(base_only_item(), [finding(65)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


def test_pr_side_finding_in_a_differently_named_function_is_a_miss_and_a_false_positive():
    s = tscore(base_only_item(), [finding(85)])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


def test_line_in_the_base_function_by_number_but_in_a_differently_named_pr_function_is_a_miss_and_a_false_positive():
    pr_functions = {"create_run": (40, 70), "cancel_run": (190, 230)}

    def reader(file: str, side: str) -> str:
        return source_with(pr_functions if side == "pr" else BASE_FUNCTIONS)

    s = bench("authz").score(base_only_item(), [finding(215)], read_source=reader)
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


@pytest.mark.parametrize("line, expect", [(205, (1, 0, 0)), (215, (0, 1, 1))], ids=["in-range", "off-range"])
def test_unreadable_source_keeps_the_exact_range_check_on_a_base_side_range(line, expect):
    def failing_reader(file: str, side: str) -> str:
        raise OSError(file)

    s = bench("authz").score(base_only_item(), [finding(line)], read_source=failing_reader)
    assert (s["tp"], s["fn"], s["fp"]) == expect


def test_line_inside_the_exact_base_side_range_but_in_a_differently_named_pr_function_is_a_miss_and_a_false_positive():
    pr_functions = {"create_run": (40, 70), "cancel_run": (190, 230)}

    def reader(file: str, side: str) -> str:
        return source_with(pr_functions if side == "pr" else BASE_FUNCTIONS)

    s = bench("authz").score(base_only_item(), [finding(205)], read_source=reader)
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


# AC-S1-2, AC-S4-1: production toolbox and per-unit verdict
def test_search_policy_no_longer_answers_from_gold_policy_passages(bench_env):
    result = bench_env.run("authz")
    toolbox = result.agents.toolboxes[0]
    answer = toolbox.search_policy_impl("who may delete")
    assert "GOLD-PASSAGE-SENTINEL" not in answer
    assert "pr only policy" in answer


def test_scored_unit_carries_the_agent_verdict_and_explanation(bench_env):
    result = bench_env.run("authz", findings=["delete route lacks an owner check"])
    unit = result.unit
    assert unit["status"] == "scored"
    assert unit["verdict"] == "vulnerable"
    assert "delete route lacks an owner check" in unit["explanation"]


def test_scored_unit_without_findings_carries_the_safe_verdict(bench_env):
    unit = bench_env.run("authz", findings=[]).unit
    assert unit["status"] == "scored"
    assert unit["verdict"] == "safe"
    assert unit["explanation"] == "no finding reported"
