"""Unit tests for the Kev judge component benchmark (labels, verdict and severity scoring)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.component_bench import kev_judge, registry, run, schema  # noqa: E402
from benchmark.real_world.fetch import project_of  # noqa: E402
from benchmark.component_bench.outcomes import InfraError  # noqa: E402

LABELS = ROOT / "benchmark" / "component_bench" / "labels" / "kev-judge.json"
NAME = "kev-judge"
CASE = "pyload_sqli_vulnerable"


def item(label_id="C1", case_id=CASE, verdict="real", severity="high", accept=None):
    gold = {"verdict": verdict}
    if severity is not None:
        gold["severity"] = severity
    if accept is not None:
        gold["acceptable"] = accept
    return {
        "label_id": label_id,
        "case_id": case_id,
        "source": "test",
        "review_state": "draft",
        "gold_input": {
            "finding_id": label_id,
            "cwe_id": "CWE-89",
            "category": "sqli",
            "explanation": "query built from user input",
            "file": "app.py",
            "line": 3,
            "evidence": [
                {
                    "type": "code",
                    "file": "app.py",
                    "lines": [3, 3],
                    "snapshot": "after",
                    "content": "cur.execute('select ' + name)",
                }
            ],
        },
        "gold": gold,
        "distractor": verdict == "not_real",
    }


def reply(verdict="real", severity="high"):
    return {
        "supported": "yes",
        "verdict": verdict,
        "severity": severity,
        "provenance_confidence": 0.9,
        "input_tokens": 7,
    }


def bench(tmp_path, items, judge):
    """Runs kev-judge through the bench-core runner; returns (section, units by label id)."""
    labels = tmp_path / "labels"
    labels.mkdir()
    (labels / f"{NAME}.json").write_text(json.dumps({"component": NAME, "items": items}))
    reg = {NAME: registry.Entry(module="kev_judge")}
    results = tmp_path / "results"
    summary = run.run_benchmark(results, labels, registry=reg, judge=judge)
    units = json.loads((results / f"{NAME}.json").read_text())["units"]
    return summary["components"][NAME], {u["label_id"]: u for u in units}


def answers(replies):
    seq = iter(replies)
    return lambda request: next(seq)


# --- AC-S7-1 / AC-S7-2 ---------------------------------------------------------------


@pytest.mark.parametrize(
    "gold, answered, correct",
    [
        ("real", "real", 1.0),
        ("not_real", "not_real", 1.0),
        ("real", "not_real", 0.0),
        ("not_real", "real", 0.0),
    ],
)
def test_verdict_correct_only_when_it_matches_gold(tmp_path, gold, answered, correct):
    sev = "high" if gold == "real" else None
    _, units = bench(tmp_path, [item(verdict=gold, severity=sev)], answers([reply(answered)]))
    assert units["C1"]["status"] == "scored"
    assert units["C1"]["scores"]["verdict_correct"] == correct


def test_wrong_verdict_unit_records_case_and_label_id(tmp_path):
    _, units = bench(
        tmp_path, [item("W1", verdict="not_real", severity=None)], answers([reply("real")])
    )
    assert units["W1"]["case_id"] == CASE
    assert units["W1"]["label_id"] == "W1"
    assert units["W1"]["scores"]["verdict_correct"] == 0.0


def test_accuracy_has_real_and_not_real_breakdown(tmp_path):
    items = [item("R1"), item("R2"), item("N1", verdict="not_real", severity=None)]
    section, _ = bench(
        tmp_path, items, answers([reply("real"), reply("not_real"), reply("not_real")])
    )
    assert section["scores"]["verdict_correct"] == pytest.approx(2 / 3)
    assert section["scores"]["real_verdict_correct"] == pytest.approx(1 / 2)
    assert section["scores"]["not_real_verdict_correct"] == pytest.approx(1.0)


# --- AC-S7-3 ---------------------------------------------------------------------------


def test_undetermined_candidate_is_not_scored_and_leaves_accuracy_unchanged(tmp_path):
    items = [item("R1"), item("U1", verdict="undetermined", severity=None)]
    section, units = bench(tmp_path, items, answers([reply("real"), reply("real")]))
    assert units["U1"]["status"] == "not_scored"
    assert units["U1"]["scores"] is None
    assert section["units_not_scored"] == 1
    assert section["units_scored"] == 1
    assert section["scores"]["verdict_correct"] == 1.0


def test_undetermined_candidate_is_never_judged(tmp_path):
    calls = []
    items = [item("U1", verdict="undetermined", severity=None)]
    bench(tmp_path, items, lambda request: calls.append(request) or reply())
    assert calls == []


# --- AC-S7-4 ---------------------------------------------------------------------------


def test_unreachable_judge_is_an_error_not_a_wrong_answer(tmp_path):
    def down(request):
        raise ConnectionError("refused")

    section, units = bench(tmp_path, [item("R1"), item("R2")], down)
    assert {u["status"] for u in units.values()} == {"error"}
    assert section["units_errored"] == 2
    assert section["units_scored"] == 0
    assert "verdict_correct" not in section["scores"]


@pytest.mark.parametrize(
    "bad",
    [{}, {"supported": "yes"}, reply(verdict="maybe"), reply(verdict=None), reply(verdict="")],
)
def test_unusable_reply_is_an_error_not_a_wrong_answer(tmp_path, bad):
    section, units = bench(tmp_path, [item("R1")], answers([bad]))
    assert units["R1"]["status"] == "error"
    assert units["R1"]["scores"] is None
    assert section["units_errored"] == 1


def test_judge_failure_in_one_candidate_does_not_stop_the_others(tmp_path):
    state = {"n": 0}

    def flaky(request):
        state["n"] += 1
        if state["n"] == 1:
            raise ConnectionError("down")
        return reply("real")

    _, units = bench(tmp_path, [item("R1"), item("R2")], flaky)
    assert units["R1"]["status"] == "error"
    assert units["R2"]["status"] == "scored"


def test_run_item_raises_infra_error_when_judge_fails():
    mod = run._module(registry.Entry(module="kev_judge"))

    def down(request):
        raise OSError("refused")

    ctx = type("Ctx", (), {"judge": staticmethod(down), "config": None, "metrics": None, "llm": None})()
    with pytest.raises(InfraError):
        mod.run_item(item(), ctx)


def test_unit_detail_records_the_raw_kev_answers(tmp_path):
    _, units = bench(tmp_path, [item()], answers([reply("real", "medium")]))
    assert units["C1"]["detail"]["kev"] == {
        "supported": "yes", "verdict": "real", "severity": "medium", "provenance_confidence": 0.9,
    }


def test_judge_sees_the_enclosing_function_with_its_decorators_from_the_case_clone(tmp_path, monkeypatch):
    case = next(c for c in schema.load_cases() if c["id"] == CASE)
    repo = tmp_path / project_of(case)
    repo.mkdir()
    function = "@login_required\ndef search(name):\n    cur.execute('select ' + name)\n    return cur"
    (repo / "app.py").write_text(function + "\n")
    git = lambda *args: subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: E731
    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "c")
    git("branch", f"rw/{CASE}/pr")
    monkeypatch.setattr(kev_judge, "CLONE_CACHE", tmp_path)
    seen = []
    bench(tmp_path, [item()], lambda request: seen.append(request["state"]) or reply())
    assert function in seen[0]


# --- AC-S7-7 (DEC-21) --------------------------------------------------------------------


@pytest.mark.parametrize(
    "gold_sev, answered_sev, correct",
    [("high", "high", 1.0), ("high", "medium", 0.0), ("low", "critical", 0.0), ("critical", "critical", 1.0)],
)
def test_severity_correct_iff_equal_to_gold_when_judged_real(tmp_path, gold_sev, answered_sev, correct):
    _, units = bench(tmp_path, [item(severity=gold_sev)], answers([reply("real", answered_sev)]))
    assert units["C1"]["scores"]["severity_correct"] == correct


def test_gold_real_judged_not_real_is_a_severity_miss(tmp_path):
    _, units = bench(tmp_path, [item(severity="high")], answers([reply("not_real", "high")]))
    assert units["C1"]["scores"]["severity_correct"] == 0.0


def test_gold_not_real_has_no_severity_score_whatever_the_judge_says(tmp_path):
    items = [item("N1", verdict="not_real", severity=None), item("N2", verdict="not_real", severity=None)]
    section, units = bench(tmp_path, items, answers([reply("real", "critical"), reply("not_real", "low")]))
    for u in units.values():
        assert u["scores"]["severity_correct"] is None
    assert "severity_correct" not in section["scores"]


def test_severity_accuracy_is_over_gold_real_candidates_only(tmp_path):
    items = [
        item("R1", severity="high"),
        item("R2", severity="high"),
        item("N1", verdict="not_real", severity=None),
    ]
    section, _ = bench(
        tmp_path,
        items,
        answers([reply("real", "high"), reply("not_real", "high"), reply("real", "low")]),
    )
    assert section["scores"]["severity_correct"] == pytest.approx(1 / 2)


# --- acceptable answer sets ------------------------------------------------------------------


@pytest.mark.parametrize(
    "answered, verdict_correct, severity_correct",
    [
        (reply("real", "medium"), 1.0, 1.0),
        (reply("real", "low"), 1.0, 0.0),
        (reply("not_real", "high"), 1.0, None),
    ],
)
def test_any_acceptable_answer_is_correct(tmp_path, answered, verdict_correct, severity_correct):
    accept = {"verdict": ["real", "not_real"], "severity": ["medium", "high"]}
    _, units = bench(tmp_path, [item(accept=accept)], answers([answered]))
    assert units["C1"]["scores"]["verdict_correct"] == verdict_correct
    assert units["C1"]["scores"]["severity_correct"] == severity_correct


def test_acceptable_severities_without_acceptable_verdicts_keep_not_real_a_miss(tmp_path):
    accept = {"severity": ["high", "critical"]}
    _, units = bench(
        tmp_path,
        [item("R1", accept=accept), item("R2", accept=accept)],
        answers([reply("real", "critical"), reply("not_real", "high")]),
    )
    assert units["R1"]["scores"] == pytest.approx(
        {"verdict_correct": 1.0, "real_verdict_correct": 1.0, "not_real_verdict_correct": None, "severity_correct": 1.0}
    )
    assert units["R2"]["scores"]["verdict_correct"] == 0.0
    assert units["R2"]["scores"]["severity_correct"] == 0.0


def test_not_real_gold_accepting_real_scores_a_real_answer_correct(tmp_path):
    accept = {"verdict": ["not_real", "real"]}
    _, units = bench(tmp_path, [item(verdict="not_real", severity=None, accept=accept)], answers([reply("real")]))
    assert units["C1"]["scores"]["not_real_verdict_correct"] == 1.0
    assert units["C1"]["scores"]["severity_correct"] is None


# --- registry and shipped labels (AC-S1-6, AC-S1-10, AC-S7-5) ------------------------------


def test_component_is_registered():
    assert NAME in registry.REGISTRY
    assert registry.REGISTRY[NAME].source == "labels"


@pytest.fixture(scope="module")
def shipped():
    return json.loads(LABELS.read_text(encoding="utf-8"))


def test_shipped_labels_pass_core_validation(shipped):
    assert shipped["component"] == NAME
    schema.validate_labels(shipped)


def test_every_case_has_at_least_one_candidate_label(shipped):
    all_cases = {c["id"] for c in schema.load_cases()}
    assert len(all_cases) == 12
    assert {i["case_id"] for i in shipped["items"]} == all_cases


def test_every_real_candidate_carries_a_severity(shipped):
    real = [i for i in shipped["items"] if i["gold"]["verdict"] == "real"]
    assert real
    for i in real:
        assert i["gold"].get("severity") in {"low", "medium", "high", "critical"}, i["label_id"]


def test_every_candidate_has_a_documented_verdict_and_only_real_has_severity(shipped):
    for i in shipped["items"]:
        assert i["gold"]["verdict"] in {"real", "not_real", "undetermined"}, i["label_id"]
        if i["gold"]["verdict"] != "real":
            assert not i["gold"].get("severity"), i["label_id"]


def test_shipped_labels_include_not_real_candidates(shipped):
    assert any(i["gold"]["verdict"] == "not_real" for i in shipped["items"])


def test_shipped_acceptable_sets_contain_the_gold_answer_and_carry_a_rationale(shipped):
    for i in shipped["items"]:
        gold = i["gold"]
        accept = gold.get("acceptable")
        if not accept:
            continue
        assert gold.get("rationale"), i["label_id"]
        assert set(accept.get("verdict", [gold["verdict"]])) <= {"real", "not_real"}, i["label_id"]
        assert gold["verdict"] in accept.get("verdict", [gold["verdict"]]), i["label_id"]
        severities = accept.get("severity", [])
        assert set(severities) <= {"low", "medium", "high", "critical"}, i["label_id"]
        if gold.get("severity"):
            assert gold["severity"] in severities, i["label_id"]
