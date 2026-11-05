"""Unit tests for the component benchmark core: label schema, runner, cost metrics, summary."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "benchmark" / "component_bench"
CASE_A, CASE_B = "pyload_sqli_vulnerable", "aegra_authz_vulnerable"


def bench(name: str):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module(f"benchmark.component_bench.{name}")


def label(label_id="L1", case_id=CASE_A, **over):
    item = {
        "label_id": label_id,
        "case_id": case_id,
        "source": "advisory GHSA-xxxx",
        "review_state": "draft",
        "gold_input": {},
        "gold": {},
    }
    return {**item, **over}


def doc(*items, component="alpha"):
    return {"component": component, "items": list(items)}


def write_labels(labels_dir: Path, component: str, items: list[dict]) -> None:
    labels_dir.mkdir(parents=True, exist_ok=True)
    (labels_dir / f"{component}.json").write_text(json.dumps(doc(*items, component=component)))


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def component(run_item=None, score=None):
    return SimpleNamespace(
        run_item=run_item or (lambda item, ctx: "out"),
        score=score or (lambda item, output: {"hit": 1.0}),
    )


def execute(tmp_path, comps, **kw):
    """Runs the benchmark over fake components; returns (summary, results_dir)."""
    run = bench("run")
    reg = bench("registry")
    labels_dir = tmp_path / "labels"
    registry = {}
    for name, (module, items) in comps.items():
        source = "labels"
        if items is None:
            source = "cases"
        else:
            write_labels(labels_dir, name, items)
        registry[name] = reg.Entry(module=module, source=source)
    results = tmp_path / "results"
    summary = run.run_benchmark(
        results_dir=results, labels_dir=labels_dir, registry=registry, **kw
    )
    return summary, results


def units(results: Path, name: str) -> list[dict]:
    return json.loads((results / f"{name}.json").read_text())["units"]


# AC-S1-2, AC-S1-3, AC-S1-4: label schema


def test_valid_draft_label_is_accepted():
    bench("schema").validate_labels(doc(label("L1"), label("L2", CASE_B)))


@pytest.mark.parametrize(
    "bad",
    [
        doc(label(case_id="no_such_case")),
        doc(label("L1"), label("L1", CASE_B)),
        doc(label(review_state="published")),
        doc(label(), component=None),
    ]
    + [doc({k: v for k, v in label().items() if k != f}) for f in
       ("label_id", "case_id", "source", "review_state", "gold_input", "gold")],
    ids=["unknown-case", "duplicate-label-id", "bad-review-state", "no-component",
         "no-label_id", "no-case_id", "no-source", "no-review_state",
         "no-gold_input", "no-gold"],
)
def test_invalid_label_file_is_rejected(bad):
    schema = bench("schema")
    with pytest.raises(schema.LabelError):
        schema.validate_labels(bad)


def test_label_for_case_outside_applicable_set_is_rejected():
    schema = bench("schema")
    with pytest.raises(schema.LabelError):
        schema.validate_labels(doc(label(case_id=CASE_B)), applicable={CASE_A})


def test_shipped_labels_are_plain_json_and_none_approved():
    schema = bench("schema")
    labels_dir = PKG / "labels"
    assert labels_dir.is_dir()
    for path in labels_dir.glob("*"):
        if path.name.startswith("."):
            continue
        assert path.suffix == ".json"
        data = json.loads(path.read_text())
        schema.validate_labels(data)
        assert {i["review_state"] for i in data["items"]} <= {"draft"}


# AC-S8-1, AC-S8-2: selection


def test_no_selection_runs_every_component_and_selection_runs_only_chosen(tmp_path):
    comps = {
        "alpha": (component(), [label()]),
        "beta": (component(), [label("L1", CASE_B)]),
    }
    summary, results = execute(tmp_path / "all", comps)
    assert set(summary["components"]) == {"alpha", "beta"}

    summary, results = execute(tmp_path / "one", comps, components=["beta"])
    assert set(summary["components"]) == {"beta"}
    assert not (results / "alpha.json").exists()


# AC-S8-3, AC-S1-5, AC-S8-6: errors and summary


def test_infra_error_is_recorded_excluded_from_scores_and_counted(tmp_path):
    run = bench("run")

    def run_item(item, ctx):
        if item["label_id"] == "bad":
            raise run.InfraError("model unreachable")
        return "out"

    scores = {"good": 1.0}
    comp = component(run_item, lambda item, out: {"hit": scores[item["label_id"]]})
    items = [label("good"), label("bad", CASE_B)]
    summary, results = execute(tmp_path, {"alpha": (comp, items)})

    rec = {u["label_id"]: u for u in units(results, "alpha")}
    assert rec["bad"]["status"] == "error"
    assert "model unreachable" in rec["bad"]["reason"]
    assert rec["bad"].get("scores") in (None, {})
    s = summary["components"]["alpha"]
    assert (s["units_scored"], s["units_errored"]) == (1, 1)
    assert s["scores"]["hit"] == 1.0


def test_summary_reports_label_review_counts_and_investigator_na(tmp_path):
    items = [label("L1"), label("L2", CASE_B, review_state="approved"), label("L3")]
    comps = {"alpha": (component(), items), "investigator": (component(), None)}
    summary, results = execute(tmp_path, comps)
    assert summary["components"]["alpha"]["labels"] == {"draft": 2, "approved": 1}
    assert summary["components"]["investigator"]["labels"] == "n/a"
    assert json.loads((results / "alpha.json").read_text())["labels"] == {
        "draft": 2, "approved": 1,
    }


# AC-S8-4: resume


def test_resume_skips_completed_units_and_reruns_errored(tmp_path):
    run = bench("run")
    calls: list[str] = []
    fail = {"flaky"}

    def run_item(item, ctx):
        calls.append(item["label_id"])
        if item["label_id"] in fail:
            raise run.InfraError("down")
        return "out"

    comp = component(run_item)
    items = [label("done"), label("flaky", CASE_B)]
    comps = {"alpha": (comp, items)}
    summary, results = execute(tmp_path, comps)
    assert summary["components"]["alpha"]["units_errored"] == 1

    calls.clear()
    fail.clear()
    summary, _ = execute(tmp_path, comps, resume=True)
    assert calls == ["flaky"]
    s = summary["components"]["alpha"]
    assert (s["units_scored"], s["units_errored"]) == (2, 0)


def test_unit_error_keeps_wall_time_and_tokens_spent_before_failure(tmp_path):
    run = bench("run")
    clock = Clock()

    def run_item(item, ctx):
        ctx.llm.invoke("a")
        clock.t += 5.0
        raise run.InfraError("down")

    usage = {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14}
    summary, results = execute(
        tmp_path, {"alpha": (component(run_item), [label()])}, clock=clock, llm=FakeLLM(usage)
    )
    rec = units(results, "alpha")[0]
    assert rec["wall_time_s"] == 5.0
    assert (rec["input_tokens"], rec["output_tokens"]) == (10, 4)
    assert summary["components"]["alpha"]["wall_time_s"] == 5.0


def test_not_scored_unit_is_counted_separately_with_reason(tmp_path):
    run = bench("run")

    def run_item(item, ctx):
        return run.NotScored("plan invalid") if item["label_id"] == "skip" else "out"

    items = [label("ok"), label("skip", CASE_B)]
    summary, results = execute(tmp_path, {"alpha": (component(run_item), items)})
    rec = {u["label_id"]: u for u in units(results, "alpha")}
    assert rec["skip"]["status"] == "not_scored"
    assert rec["skip"]["reason"] == "plan invalid"
    s = summary["components"]["alpha"]
    assert (s["units_scored"], s["units_errored"], s["units_not_scored"]) == (1, 0, 1)
    assert s["scores"]["hit"] == 1.0


def test_metric_means_span_scored_units_and_skip_none_values(tmp_path):
    table = {
        "L1": {"sev": None, "hit": 1.0},
        "L2": {"sev": 2.0, "hit": 0.0},
        "L3": {"sev": 4.0, "hit": 0.0},
    }
    comp = component(score=lambda item, out: table[item["label_id"]])
    items = [label("L1"), label("L2", CASE_B), label("L3", "pyload_sqli_safe")]
    summary, _ = execute(tmp_path, {"alpha": (comp, items)})
    scores = summary["components"]["alpha"]["scores"]
    assert scores["sev"] == pytest.approx(3.0)
    assert scores["hit"] == pytest.approx(1 / 3)


def test_aggregate_hook_output_appears_in_summary_section_only_when_declared(tmp_path):
    run, reg = bench("run"), bench("registry")
    labels_dir = tmp_path / "labels"
    write_labels(labels_dir, "alpha", [label("L1"), label("L2", CASE_B)])
    write_labels(labels_dir, "beta", [label()])
    seen = {}

    def aggregate(unit_records, results_dir):
        seen["ids"] = sorted(u["label_id"] for u in unit_records)
        seen["dir"] = Path(results_dir)
        return {"custom": 42}

    results = tmp_path / "results"
    registry = {
        "alpha": reg.Entry(module=component(), source="labels", aggregate=aggregate),
        "beta": reg.Entry(module=component(), source="labels"),
    }
    summary = run.run_benchmark(results, labels_dir, registry)
    assert summary["components"]["alpha"]["aggregate"] == {"custom": 42}
    assert "aggregate" not in summary["components"]["beta"]
    assert seen == {"ids": ["L1", "L2"], "dir": results}


# AC-S8-4: interrupted run and model-setting refusal


def test_interrupted_run_keeps_completed_units_and_resume_skips_them(tmp_path):
    calls: list[str] = []
    interrupt = {"on": True}

    def run_item(item, ctx):
        calls.append(item["label_id"])
        if interrupt["on"] and item["label_id"] == "L2":
            raise RuntimeError("tunnel dropped")
        return "out"

    comps = {"alpha": (component(run_item), [label("L1"), label("L2", CASE_B)])}
    with pytest.raises(RuntimeError):
        execute(tmp_path, comps)
    assert [u["label_id"] for u in units(tmp_path / "results", "alpha")] == ["L1"]

    calls.clear()
    interrupt["on"] = False
    summary, _ = execute(tmp_path, comps, resume=True)
    assert calls == ["L2"]
    assert summary["components"]["alpha"]["units_scored"] == 2


def test_run_under_different_model_setting_refuses_and_leaves_results_unchanged(tmp_path):
    run = bench("run")
    comps = {"alpha": (component(), [label()])}
    execute(tmp_path, comps, model_setting="a")
    results = tmp_path / "results"
    before = {p.name: p.read_text() for p in results.iterdir()}

    with pytest.raises(run.ModelSettingMismatch):
        execute(tmp_path, comps, resume=True, model_setting="b")
    assert {p.name: p.read_text() for p in results.iterdir()} == before

    with pytest.raises(run.ModelSettingMismatch):
        execute(tmp_path, comps, resume=False, model_setting="b")
    assert {p.name: p.read_text() for p in results.iterdir()} == before

    execute(tmp_path, comps, resume=True, model_setting="a")


def test_partial_rerun_under_new_model_setting_refuses_instead_of_mixing_results(tmp_path):
    run = bench("run")
    comps = {
        "alpha": (component(), [label()]),
        "beta": (component(), [label("L1", CASE_B)]),
    }
    execute(tmp_path, comps, model_setting="a")
    with pytest.raises(run.ModelSettingMismatch):
        execute(tmp_path, comps, components=["beta"], model_setting="b")


# AC-S8-7: traceability


def test_every_unit_carries_case_id_and_label_id_investigator_case_id_only(tmp_path):
    comps = {
        "alpha": (component(), [label("L1"), label("L2", CASE_B)]),
        "investigator": (component(), None),
    }
    _, results = execute(tmp_path, comps)
    got = {(u["case_id"], u["label_id"]) for u in units(results, "alpha")}
    assert got == {(CASE_A, "L1"), (CASE_B, "L2")}
    inv = units(results, "investigator")
    assert len(inv) == 12
    assert all(u["case_id"] and u.get("label_id") is None for u in inv)


# AC-S8-8: documentation


def test_docs_describe_command_and_options():
    text = (ROOT / "docs" / "component-bench.md").read_text()
    for needle in ("benchmark/component_bench/run.py", "--components", "--resume",
                   "--results-dir"):
        assert needle in text


# AC-S10-1: wall time


def test_unit_wall_time_recorded_and_component_total_summed(tmp_path):
    clock = Clock()

    def run_item(item, ctx):
        clock.t += 3.0
        return "out"

    items = [label("L1"), label("L2", CASE_B)]
    summary, results = execute(
        tmp_path, {"alpha": (component(run_item), items)}, clock=clock
    )
    assert [u["wall_time_s"] for u in units(results, "alpha")] == [3.0, 3.0]
    assert summary["components"]["alpha"]["wall_time_s"] == 6.0


# AC-S10-2, AC-S10-4: tokens


class FakeLLM:
    def __init__(self, usage):
        self.usage = usage

    def invoke(self, messages):
        return SimpleNamespace(content="ok", usage_metadata=self.usage)


def test_llm_and_judge_tokens_recorded_per_unit_and_totaled(tmp_path):
    def llm_item(item, ctx):
        ctx.llm.invoke("a")
        ctx.llm.invoke("b")
        return "out"

    def judge_item(item, ctx):
        ctx.judge({"state": "Claim: x"})
        return "out"

    llm_usage = {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14}
    comps = {
        "alpha": (component(llm_item), [label("L1"), label("L2", CASE_B)]),
        "kev": (component(judge_item), [label("L1")]),
    }
    summary, results = execute(
        tmp_path,
        comps,
        llm=FakeLLM(llm_usage),
        judge=lambda request: {"verdict": "real", "input_tokens": 7},
    )
    first = units(results, "alpha")[0]
    assert (first["input_tokens"], first["output_tokens"]) == (20, 8)
    a = summary["components"]["alpha"]
    assert (a["input_tokens"], a["output_tokens"]) == (40, 16)
    k = summary["components"]["kev"]
    assert k["input_tokens"] == 7
    assert k["output_tokens"] == "not recorded"


def test_tokens_not_returned_are_null_per_unit_and_not_recorded_in_summary(tmp_path):
    def run_item(item, ctx):
        ctx.llm.invoke("a")
        return "out"

    summary, results = execute(
        tmp_path, {"alpha": (component(run_item), [label()])}, llm=FakeLLM(None)
    )
    rec = units(results, "alpha")[0]
    assert rec["input_tokens"] is None and rec["output_tokens"] is None
    a = summary["components"]["alpha"]
    assert a["input_tokens"] == "not recorded"
    assert a["output_tokens"] == "not recorded"


# AC-S10-3: tool calls


def test_summary_lists_calls_invalid_calls_and_never_called_tools_per_agent(tmp_path):
    def call(tool, args):
        return {"tool": tool, "args": args, "result": "r"}

    records = [
        SimpleNamespace(
            section="investigator",
            turns=[
                {
                    "tool_calls": [
                        call("search", {"q": "x"}),
                        call("search", {"q": "y"}),
                        call("read", "not-an-object"),
                        call("delete", {}),
                    ]
                }
            ],
        )
    ]

    def run_item(item, ctx):
        ctx.metrics.add_agent("investigator", records, ["search", "read", "unused"])
        return "out"

    summary, _ = execute(tmp_path, {"alpha": (component(run_item), [label()])})
    tools = summary["components"]["alpha"]["tools"]["investigator"]
    assert tools["search"] == {"calls": 2, "invalid": 0}
    assert tools["read"] == {"calls": 1, "invalid": 1}
    assert tools["unused"] == {"calls": 0, "invalid": 0}
    assert tools["delete"] == {"calls": 1, "invalid": 1}


def _toolbox_style_tools():
    from pydantic import BaseModel

    class ReadArgs(BaseModel):
        path: str
        start_line: int = 0

    class QueryArgs(BaseModel):
        query: str

    return [
        SimpleNamespace(name="read_file", args_schema=ReadArgs),
        SimpleNamespace(name="investigate_pr_code", args_schema=QueryArgs),
    ]


def test_schema_invalid_arguments_to_offered_tool_count_as_invalid(tmp_path):
    def call(tool, args):
        return {"tool": tool, "args": args, "result": "r"}

    records = [
        SimpleNamespace(
            section="investigator",
            turns=[
                {
                    "tool_calls": [
                        call("read_file", {"path": "a.py", "start_line": "abc"}),
                        call("read_file", {"path": "a.py", "start_line": 3}),
                    ]
                }
            ],
        )
    ]

    def run_item(item, ctx):
        ctx.metrics.add_agent("investigator", records, _toolbox_style_tools())
        return "out"

    summary, _ = execute(tmp_path, {"alpha": (component(run_item), [label()])})
    tools = summary["components"]["alpha"]["tools"]["investigator"]
    assert tools["read_file"] == {"calls": 2, "invalid": 1}
    assert tools["investigate_pr_code"] == {"calls": 0, "invalid": 0}


def test_calls_recorded_only_in_turns_are_counted(tmp_path):
    turn_call = {"tool": "investigate_pr_code", "args": {"query": "q"}}
    records = [
        SimpleNamespace(
            section="investigator",
            tool_calls=[],
            turns=[{"tool_calls": [turn_call]}, {"tool_calls": [turn_call]}],
        )
    ]

    def run_item(item, ctx):
        ctx.metrics.add_agent("investigator", records, _toolbox_style_tools())
        return "out"

    summary, _ = execute(tmp_path, {"alpha": (component(run_item), [label()])})
    tools = summary["components"]["alpha"]["tools"]["investigator"]
    assert tools["investigate_pr_code"] == {"calls": 2, "invalid": 0}
    assert tools["read_file"] == {"calls": 0, "invalid": 0}


def test_main_model_setting_differs_when_only_judge_endpoint_differs(tmp_path, monkeypatch):
    import lgtm.agents.base
    import lgtm.config
    import lgtm.validation.judge

    run = bench("run")
    seen = []
    endpoint = {"value": "http://kev-one:8008"}

    class Config(lgtm.config.LGTMConfig):
        def __post_init__(self):
            self.judge_endpoint = endpoint["value"]

    monkeypatch.setattr(lgtm.config, "LGTMConfig", Config)
    monkeypatch.setattr(lgtm.agents.base, "build_llm", lambda config: None)
    monkeypatch.setattr(lgtm.validation.judge, "http_judge", lambda config: None)
    monkeypatch.setattr(run, "run_benchmark", lambda *a, **kw: seen.append(kw["model_setting"]) or {})

    assert run.main(["--results-dir", str(tmp_path / "r"), "--labels-dir", str(tmp_path / "l")]) == 0
    endpoint["value"] = "http://kev-two:8008"
    assert run.main(["--results-dir", str(tmp_path / "r"), "--labels-dir", str(tmp_path / "l")]) == 0
    assert seen[0] != seen[1]
