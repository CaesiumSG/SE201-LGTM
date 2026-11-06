"""Unit tests for the sqli-review benchmark component: registration, labels, hit rule, run_item, summary."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILE = "app/db.py"
OTHER_FILE = "app/other.py"
FUNCTION = {"file": FILE, "start": 40, "end": 70}
KNOWN = {"id": "known_1", "file": FILE, "start": 100, "end": 120}
RUN_ITEM = {"case_id": "c", "label_id": "L", "gold_input": {}}


def bench(name: str):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module(f"benchmark.component_bench.{name}")


def cases() -> list[dict]:
    return bench("schema").load_cases()


def sqli_ids() -> set[str]:
    return {c["id"] for c in cases() if c["category"] == "sqli"}


def label_doc() -> dict:
    path = ROOT / "benchmark" / "component_bench" / "labels" / "sqli-review.json"
    return json.loads(path.read_text(encoding="utf-8"))


def vulnerable_item() -> dict:
    return {
        "case_id": "c_vuln",
        "label_id": "L1",
        "gold": {"vulnerable": True, "locations": [dict(FUNCTION)], "known_issues": []},
    }


def safe_item(known=(KNOWN,)) -> dict:
    return {
        "case_id": "c_safe",
        "label_id": "L2",
        "gold": {"vulnerable": False, "locations": [], "known_issues": list(known)},
    }


def finding(line: int, file: str = FILE, sast_also: bool = False) -> dict:
    return {"file": file, "line": line, "sast_also": sast_also}


def source_with(functions: dict[str, tuple[int, int]]) -> str:
    """Python source whose named functions occupy the given inclusive line ranges."""
    lines = ["# filler"] * max(end for _, end in functions.values())
    for name, (start, end) in functions.items():
        lines[start - 1] = f"def {name}():"
        lines[start:end] = ["    pass"] * (end - start)
    return "\n".join(lines) + "\n"


PR_FUNCTIONS = {"query_user": (40, 70), "query_other": (80, 130)}
BASE_FUNCTIONS = {"query_user": (190, 230), "query_other": (240, 300)}


def read_source(file: str, side: str) -> str:
    if file != FILE:
        raise FileNotFoundError(file)
    return source_with(PR_FUNCTIONS if side == "pr" else BASE_FUNCTIONS)


def score(item: dict, findings: list[dict]) -> dict:
    return bench("sqli_review").score(item, findings, read_source=read_source)


def test_sqli_review_is_registered_for_exactly_the_sqli_cases():
    entry = bench("registry").REGISTRY["sqli-review"]
    assert entry.source == "labels"
    assert set(entry.applicable) == sqli_ids()
    assert entry.aggregate is not None


def test_sqli_review_label_file_is_valid_draft_and_scoped_to_sqli_cases():
    doc = label_doc()
    assert doc["component"] == "sqli-review"
    bench("schema").validate_labels(doc, sqli_ids())
    assert {i["review_state"] for i in doc["items"]} == {"draft"}


def test_every_sqli_case_has_a_label_including_the_development_cases():
    dev = {c["id"] for c in cases() if c["split"] == "real_prs" and c["category"] == "sqli"}
    assert len(dev) == 4
    assert {i["case_id"] for i in label_doc()["items"]} == sqli_ids()


def test_labels_carry_a_gold_section_and_a_verdict():
    for item in label_doc()["items"]:
        assert item["gold_input"]["section"]
        assert isinstance(item["gold"]["vulnerable"], bool)
        if item["gold"]["vulnerable"]:
            assert item["gold"]["locations"]


def test_run_writes_component_file_and_summary_section_for_sqli_cases_only(monkeypatch, tmp_path):
    mod = bench("sqli_review")
    monkeypatch.setattr(mod, "run_item", lambda item, ctx: [])
    monkeypatch.setattr(bench("run"), "_preflight", lambda case: None)
    summary = bench("run").run_benchmark(results_dir=tmp_path, components=["sqli-review"], llm=object())
    rows = json.loads((tmp_path / "sqli-review.json").read_text())["units"]
    assert {r["case_id"] for r in rows} == sqli_ids()
    assert summary["components"]["sqli-review"]["units_scored"] == len(label_doc()["items"])
    assert json.loads((tmp_path / "summary.json").read_text())["components"]["sqli-review"]


@pytest.mark.parametrize("line", [40, 55, 70], ids=["start", "inside", "end"])
def test_finding_in_the_gold_sink_function_is_a_hit(line):
    s = score(vulnerable_item(), [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


@pytest.mark.parametrize(
    "bad",
    [finding(39), finding(71), finding(55, OTHER_FILE)],
    ids=["above-function", "below-function", "other-file"],
)
def test_finding_outside_the_gold_function_is_a_miss_and_a_false_positive(bad):
    s = score(vulnerable_item(), [bad])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


def test_vulnerable_unit_without_findings_is_a_miss_with_no_false_positive():
    s = score(vulnerable_item(), [])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 0)


@pytest.mark.parametrize("line", [40, 49, 61, 70], ids=["fn-start", "below-range", "above-range", "fn-end"])
def test_finding_in_the_gold_function_outside_the_exact_range_is_a_hit(line):
    item = vulnerable_item()
    item["gold"]["locations"] = [{"file": FILE, "start": 50, "end": 60}]
    s = score(item, [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


@pytest.mark.parametrize("line", [85, 125], ids=["other-function", "other-function-end"])
def test_finding_in_another_function_than_a_narrow_gold_range_is_a_miss_and_a_false_positive(line):
    item = vulnerable_item()
    item["gold"]["locations"] = [{"file": FILE, "start": 50, "end": 60}]
    s = score(item, [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


def test_base_side_finding_in_the_function_of_the_removed_check_outside_its_range_is_a_hit():
    item = vulnerable_item()
    item["gold"]["locations"] = []
    item["gold"]["old_locations"] = [{"file": FILE, "start": 200, "end": 210}]
    s = score(item, [finding(65)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


@pytest.mark.parametrize("line", [85, 250], ids=["pr-other-function", "base-other-function"])
def test_base_side_finding_in_another_function_than_the_removed_check_is_a_miss_and_a_false_positive(line):
    item = vulnerable_item()
    item["gold"]["locations"] = []
    item["gold"]["old_locations"] = [{"file": FILE, "start": 200, "end": 210}]
    s = score(item, [finding(line)])
    assert (s["tp"], s["fn"], s["fp"]) == (0, 1, 1)


def test_finding_far_from_the_sink_line_but_in_the_same_function_is_a_hit():
    item = vulnerable_item()
    item["gold"]["locations"] = [{"file": FILE, "start": 10, "end": 500}]
    assert score(item, [finding(400)])["tp"] == 1


def test_hit_alongside_stray_findings_counts_each_stray_finding_once():
    s = score(vulnerable_item(), [finding(55), finding(1), finding(2, OTHER_FILE)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 2)


def test_repeated_finding_of_the_same_sink_counts_once():
    s = score(vulnerable_item(), [finding(1), finding(1), finding(55), finding(55)])
    assert (s["tp"], s["fp"]) == (1, 1)


@pytest.mark.parametrize(
    "found, tag",
    [([finding(55, sast_also=True)], "sast_also"), ([finding(55)], "reviewer_only")],
)
def test_hit_is_tagged_sast_also_or_reviewer_only(found, tag):
    s = score(vulnerable_item(), found)
    other = "reviewer_only" if tag == "sast_also" else "sast_also"
    assert (s[tag], s[other]) == (1, 0)


def test_miss_carries_neither_tag():
    s = score(vulnerable_item(), [finding(1, sast_also=True)])
    assert not s.get("sast_also") and not s.get("reviewer_only")


def test_safe_unit_without_findings_is_a_correct_negative():
    s = score(safe_item(), [])
    assert (s["tn"], s["fp"], s["tp"], s["fn"]) == (1, 0, 0, 0)


@pytest.mark.parametrize("line", [100, 110, 120], ids=["start", "inside", "end"])
def test_safe_unit_finding_inside_known_issue_is_not_a_false_positive(line):
    s = score(safe_item(), [finding(line)])
    assert (s["fp"], s["tn"]) == (0, 1)


@pytest.mark.parametrize("line", [80, 99, 121, 130], ids=["function-start", "above-range", "below-range", "function-end"])
def test_safe_unit_finding_in_the_function_of_a_known_issue_is_not_a_false_positive(line):
    s = score(safe_item(), [finding(line)])
    assert (s["fp"], s["tn"]) == (0, 1)


@pytest.mark.parametrize(
    "bad",
    [finding(55), finding(79), finding(131), finding(110, OTHER_FILE)],
    ids=["other-function", "above-function", "below-function", "other-file"],
)
def test_safe_unit_finding_outside_the_function_of_known_issues_is_a_false_positive(bad):
    s = score(safe_item(), [bad])
    assert (s["fp"], s["tn"]) == (1, 0)


def test_known_issue_finding_does_not_hide_another_false_positive():
    s = score(safe_item(), [finding(110), finding(5)])
    assert (s["fp"], s["tn"]) == (1, 0)


def test_repeated_safe_unit_false_positive_counts_once():
    assert score(safe_item(), [finding(5), finding(5)])["fp"] == 1


class FakeToolbox:
    def build_tools(self):
        return [SimpleNamespace(name="read_file")]


def make_agent(findings, errors=(), seen=None):
    class FakeAgent:
        def __init__(self, toolbox, config=None, llm=None):
            self.llm, self.errors, self.run_records = llm, list(errors), [SimpleNamespace(turns=[])]
            if seen is not None:
                seen.append(self)

        def review_section(self, section, semgrep_notes=""):
            return findings

    return FakeAgent


def agent_finding(line, file=FILE):
    return SimpleNamespace(file=file, line=line, agent="sqli_reviewer", cwe_id="CWE-89", explanation="x", evidence=[], supported=None)


class Spy:
    def __init__(self):
        self.calls = []

    def add_agent(self, name, records, offered):
        self.calls.append((name, len(list(records))))


@pytest.fixture
def patched(monkeypatch):
    mod = bench("sqli_review")
    monkeypatch.setattr(mod, "build_section", lambda gold_input: SimpleNamespace(section_id="s"))
    monkeypatch.setattr(mod, "build_toolbox", lambda item, ctx: FakeToolbox())
    monkeypatch.setattr(mod, "needs_sql_review", lambda section, toolbox: True)
    return mod


def ctx():
    return SimpleNamespace(llm=object(), config=None, metrics=Spy())


def outcomes():
    return bench("outcomes")


def test_run_item_returns_file_and_line_of_each_reviewer_finding(patched, monkeypatch):
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([agent_finding(55)]))
    out = patched.run_item(RUN_ITEM, ctx())
    assert [(f["file"], f["line"]) for f in out] == [(FILE, 55)]


def test_run_item_reports_the_reviewer_agent_to_metrics(patched, monkeypatch):
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([]))
    c = ctx()
    patched.run_item(RUN_ITEM, c)
    assert [n for n, _ in c.metrics.calls] == ["reviewer"]


def test_section_without_sql_signal_is_not_scored_and_agent_never_runs(patched, monkeypatch):
    seen = []
    monkeypatch.setattr(patched, "needs_sql_review", lambda section, toolbox: False)
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([agent_finding(55)], seen=seen))
    out = patched.run_item(RUN_ITEM, ctx())
    assert isinstance(out, outcomes().NotScored)
    assert out.reason
    assert seen == []


def test_sql_signal_check_receives_the_gold_section_and_toolbox(patched, monkeypatch):
    section, toolbox, got = SimpleNamespace(section_id="s"), FakeToolbox(), []
    monkeypatch.setattr(patched, "build_section", lambda gold_input: section)
    monkeypatch.setattr(patched, "build_toolbox", lambda item, ctx: toolbox)
    monkeypatch.setattr(patched, "needs_sql_review", lambda s, t: got.append((s, t)) or False)
    patched.run_item(RUN_ITEM, ctx())
    assert got == [(section, toolbox)]


def test_unparsable_kind_is_not_scored_whatever_the_message(patched, monkeypatch):
    errors = [{"source": "sqli:s", "kind": "unparsable", "message": "reworded text"}]
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([], errors))
    out = patched.run_item(RUN_ITEM, ctx())
    assert isinstance(out, outcomes().NotScored)
    assert out.reason


def test_failed_kind_is_an_infra_error_even_with_unparsable_looking_text(patched, monkeypatch):
    errors = [{"source": "sqli:s", "kind": "failed", "message": "could not parse the final answer"}]
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([], errors))
    with pytest.raises(outcomes().InfraError):
        patched.run_item(RUN_ITEM, ctx())


def test_mixed_failed_and_unparsable_errors_are_an_infra_error(patched, monkeypatch):
    errors = [
        {"source": "sqli:s", "kind": "unparsable", "message": "a"},
        {"source": "sqli:s", "kind": "failed", "message": "model unreachable"},
    ]
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([], errors))
    with pytest.raises(outcomes().InfraError):
        patched.run_item(RUN_ITEM, ctx())


def test_findings_pass_through_production_dedup_and_its_result_is_scored(patched, monkeypatch):
    merged, received = agent_finding(60), []

    def fake_dedup(findings):
        received.append(list(findings))
        return [merged]

    monkeypatch.setattr(patched, "dedup_findings", fake_dedup)
    first, second = agent_finding(55), agent_finding(56)
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([first, second]))
    out = patched.run_item(RUN_ITEM, ctx())
    assert received == [[first, second]]
    assert [(f["file"], f["line"]) for f in out] == [(FILE, 60)]


def test_component_uses_the_production_reviewer_dedup_and_signal_check():
    from lgtm.agents.sqli_reviewer import SQLiReviewerAgent, needs_sql_review
    from lgtm.review.dedup import dedup_findings

    mod = bench("sqli_review")
    assert mod.SQLiReviewerAgent is SQLiReviewerAgent
    assert mod.needs_sql_review is needs_sql_review
    assert mod.dedup_findings is dedup_findings


def unit(tp=0, fn=0, fp=0, tn=0, sast_also=0, reviewer_only=0, status="scored"):
    scores = None
    if status == "scored":
        scores = {"tp": tp, "fn": fn, "fp": fp, "tn": tn, "sast_also": sast_also, "reviewer_only": reviewer_only}
    return {"status": status, "scores": scores}


def test_aggregate_reports_hits_false_positives_precision_recall_f1_and_tag_counts(tmp_path):
    units = (
        [unit(tp=1, sast_also=1)] * 2
        + [unit(tp=1, reviewer_only=1)]
        + [unit(fn=1), unit(fp=1), unit(tn=1), unit(status="error"), unit(status="not_scored")]
    )
    agg = bench("sqli_review").aggregate(units, tmp_path)
    assert (agg["hits"], agg["false_positives"]) == (3, 1)
    assert (agg["precision"], agg["recall"], agg["f1"]) == (0.75, 0.75, 0.75)
    assert (agg["sast_also"], agg["reviewer_only"]) == (2, 1)


def test_aggregate_rates_are_none_where_undefined(tmp_path):
    agg = bench("sqli_review").aggregate([unit(fn=1), unit(tn=1)], tmp_path)
    assert agg["precision"] is None
    assert agg["f1"] is None
    assert agg["recall"] == 0.0


def test_finding_in_a_base_side_range_of_a_removed_check_is_a_hit():
    item = vulnerable_item()
    item["gold"]["old_locations"] = [{"file": FILE, "start": 200, "end": 220}]
    s = score(item, [finding(210)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


def test_finding_in_a_second_gold_location_is_a_hit():
    item = vulnerable_item()
    item["gold"]["locations"].append({"file": OTHER_FILE, "start": 5, "end": 9})
    s = score(item, [finding(7, OTHER_FILE)])
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


def semgrep_hit(start=50, end=56, path=FILE):
    from lgtm.sast.semgrep_runner import SemgrepFinding

    return SemgrepFinding(
        rule_id="r.sqli", path=path, start_line=start, end_line=end, message="msg", severity="ERROR", cwe=["CWE-89"]
    )


def real_finding(line, file=FILE):
    from lgtm.agents.base import AgentFinding, EvidenceItem

    return AgentFinding(
        finding_id=f"rev-{file}-{line}", verdict="vulnerable", cwe_id="CWE-89", explanation="x",
        category="sqli", agent="sqli_reviewer", file=file, line=line,
        evidence=[EvidenceItem(type="code", file=file, lines=[line, line], content="q")],
    )


def sast_run(patched, monkeypatch, hits, reviewer, files=(FILE,), notes=None):
    class Agent(make_agent(reviewer)):
        def review_section(self, section, semgrep_notes=""):
            if notes is not None:
                notes.append(semgrep_notes)
            return reviewer

    monkeypatch.setattr(patched, "build_section", lambda gold_input: SimpleNamespace(section_id="s", files=list(files)))
    monkeypatch.setattr(patched, "_kept_sast_hits", lambda: {RUN_ITEM["case_id"]: hits})
    monkeypatch.setattr(patched, "SQLiReviewerAgent", Agent)
    return patched.run_item(RUN_ITEM, ctx())


def test_reviewer_finding_overlapping_a_sast_hit_merges_into_one_sast_also_row_at_the_reviewer_line(patched, monkeypatch):
    out = sast_run(patched, monkeypatch, [semgrep_hit(50, 56)], [real_finding(55)])
    assert out == [{"file": FILE, "line": 55, "sast_also": True}]


def test_sast_only_leftovers_are_dropped_and_reviewer_finding_is_not_sast_also(patched, monkeypatch):
    out = sast_run(patched, monkeypatch, [semgrep_hit(50, 52)], [real_finding(55)])
    assert out == [{"file": FILE, "line": 55, "sast_also": False}]


def test_sast_hit_without_reviewer_finding_yields_no_output(patched, monkeypatch):
    assert sast_run(patched, monkeypatch, [semgrep_hit(50, 56)], []) == []


def test_sast_hit_in_a_file_outside_the_section_is_not_passed_as_notes_or_merged(patched, monkeypatch):
    notes = []
    hit = semgrep_hit(50, 56, path=OTHER_FILE)
    out = sast_run(patched, monkeypatch, [hit], [real_finding(55)], notes=notes)
    assert notes == [""]
    assert out == [{"file": FILE, "line": 55, "sast_also": False}]


def test_sast_hits_in_the_section_are_passed_to_the_reviewer_as_notes(patched, monkeypatch):
    notes = []
    sast_run(patched, monkeypatch, [semgrep_hit(50, 56)], [], notes=notes)
    assert len(notes) == 1
    assert all(part in notes[0] for part in ("r.sqli", f"{FILE}:50", "msg"))


def test_kept_sast_hits_default_to_cwe_89_when_the_label_has_no_cwe(monkeypatch, tmp_path):
    mod = bench("sqli_review")
    label = {
        "case_id": "c",
        "gold": {"keep": True},
        "gold_input": {
            "rule_id": "r", "path": FILE, "start_line": 1, "end_line": 2, "message": "m", "severity": "ERROR",
            "excerpt": "x",
        },
    }
    path = tmp_path / "sast.json"
    path.write_text(json.dumps({"items": [label]}), encoding="utf-8")
    monkeypatch.setattr(mod, "SAST_LABELS", path)
    mod._kept_sast_hits.cache_clear()
    try:
        assert mod._kept_sast_hits()["c"][0].cwe == ["CWE-89"]
    finally:
        mod._kept_sast_hits.cache_clear()


def test_reviewer_error_record_without_kind_is_an_infra_error(patched, monkeypatch):
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent([], [{"source": "sqli:s", "message": "boom"}]))
    with pytest.raises(outcomes().InfraError):
        patched.run_item(RUN_ITEM, ctx())


def test_missing_case_clone_is_an_infra_error(monkeypatch, tmp_path):
    mod = bench("sqli_review")
    monkeypatch.setattr(mod, "CLONE_CACHE", tmp_path)
    item = {"case_id": sorted(sqli_ids())[0]}
    with pytest.raises(outcomes().InfraError):
        mod.build_toolbox(item, SimpleNamespace(llm=object(), config=None, metrics=Spy(), results_dir=tmp_path))


def sast_hit(start: int, end: int):
    from lgtm.sast.semgrep_runner import SemgrepFinding

    return SemgrepFinding(
        rule_id="r", path=FILE, start_line=start, end_line=end, message="m", severity="ERROR", cwe=["CWE-89"]
    )


def with_sast(patched, monkeypatch, hits, reviewed):
    monkeypatch.setattr(patched, "build_section", lambda gold_input: SimpleNamespace(section_id="s", files=[FILE]))
    monkeypatch.setattr(patched, "_kept_sast_hits", lambda: {"c": hits})
    monkeypatch.setattr(patched, "SQLiReviewerAgent", make_agent(reviewed))
    return patched.run_item(RUN_ITEM, ctx())


def test_two_overlapping_sast_hits_without_reviewer_output_score_no_finding(patched, monkeypatch):
    out = with_sast(patched, monkeypatch, [sast_hit(10, 14), sast_hit(12, 16)], [])
    assert out == []


def test_overlapping_sast_hits_do_not_add_a_finding_beside_a_reviewer_finding(patched, monkeypatch):
    out = with_sast(patched, monkeypatch, [sast_hit(10, 14), sast_hit(12, 16)], [real_finding(55)])
    assert [(f["file"], f["line"]) for f in out] == [(FILE, 55)]


def test_sast_hit_overlapping_a_reviewer_finding_stays_the_reviewer_finding_tagged_sast_also(patched, monkeypatch):
    out = with_sast(patched, monkeypatch, [sast_hit(54, 58)], [real_finding(55)])
    assert [(f["file"], f["line"], f["sast_also"]) for f in out] == [(FILE, 55, True)]


def test_sast_only_hit_adds_no_false_positive_on_a_safe_unit(patched, monkeypatch):
    out = with_sast(patched, monkeypatch, [sast_hit(10, 14), sast_hit(12, 16)], [])
    s = score(safe_item(), out)
    assert (s["fp"], s["tn"]) == (0, 1)


def test_sast_hit_in_another_file_than_the_reviewer_finding_adds_no_output_row(patched, monkeypatch):
    hit = semgrep_hit(5, 9, path=OTHER_FILE)
    out = sast_run(patched, monkeypatch, [hit], [real_finding(55)], files=(FILE, OTHER_FILE))
    assert [(f["file"], f["line"], f["sast_also"]) for f in out] == [(FILE, 55, False)]
    s = score(vulnerable_item(), out)
    assert (s["tp"], s["fn"], s["fp"]) == (1, 0, 0)


def test_run_path_passes_the_case_reader_to_score():
    mod, seen, reader = bench("sqli_review"), {}, object()

    def fake_score(item, output, read_source=None):
        seen["read_source"] = read_source
        return {"tp": 1}

    module = SimpleNamespace(
        run_item=lambda item, ctx: [],
        score=fake_score,
        case_reader=lambda item: reader if item["case_id"] == "c" else None,
    )
    unit = bench("run")._run_unit(module, {"case_id": "c", "label_id": "L"}, None, None, None, lambda: 0.0, Path("."))
    assert unit["status"] == "scored"
    assert seen["read_source"] is reader
    assert callable(mod.case_reader)


# AC-S1-2, AC-S4-1: production toolbox and per-unit verdict
def test_scored_unit_carries_the_agent_verdict_and_explanation(bench_env):
    result = bench_env.run("sqli-review", findings=["id is interpolated into the query"])
    unit = result.unit
    assert unit["status"] == "scored"
    assert unit["verdict"] == "vulnerable"
    assert "id is interpolated into the query" in unit["explanation"]


def test_scored_unit_without_findings_carries_the_safe_verdict(bench_env):
    unit = bench_env.run("sqli-review", findings=[]).unit
    assert unit["status"] == "scored"
    assert unit["verdict"] == "safe"
    assert unit["explanation"] == "no finding reported"
