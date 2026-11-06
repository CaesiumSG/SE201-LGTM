"""Unit tests for the component benchmark core: label schema, runner, cost metrics, summary."""

from __future__ import annotations

import builtins
import importlib
import json
import subprocess
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


@pytest.fixture(autouse=True)
def isolated_clone_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(bench("run"), "CLONE_CACHE", tmp_path / "no-clones", raising=False)


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


def test_summary_json_records_executing_commit_and_dirty_flag(tmp_path, monkeypatch):
    run = bench("run")
    answers = {"rev-parse": "abc123", "status": " M src/x.py"}
    monkeypatch.setattr(run, "_git", lambda *args: answers[args[0]])
    _, results = execute(tmp_path, {"alpha": (component(), [label()])})
    written = json.loads((results / "summary.json").read_text())
    assert written["commit"] == "abc123"
    assert written["dirty"] is True

    monkeypatch.setattr(run, "_git", lambda *args: None)
    _, results = execute(tmp_path / "nogit", {"alpha": (component(), [label()])})
    written = json.loads((results / "summary.json").read_text())
    assert written["commit"] is None and written["dirty"] is None


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


def test_component_detail_is_recorded_on_the_unit_only_when_output_has_it(tmp_path):
    def run_item(item, ctx):
        return {"detail": {"why": "r"}} if item["label_id"] == "with" else {"other": 1}

    items = [label("with"), label("without", CASE_B)]
    _, results = execute(tmp_path, {"alpha": (component(run_item), items)})
    rec = {u["label_id"]: u for u in units(results, "alpha")}
    assert rec["with"]["detail"] == {"why": "r"}
    assert "detail" not in rec["without"]


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
    assert len(inv) == 25
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


# Story 2: real_prs development cases

REAL_WORLD_IDS = [
    "pyload_sqli_vulnerable", "pyload_sqli_safe", "postgraas_sqli_vulnerable", "postgraas_sqli_safe",
    "alerta_sqli_vulnerable", "alerta_sqli_safe", "aegra_authz_vulnerable", "aegra_authz_safe",
    "langflow_authz_vulnerable", "langflow_authz_safe", "litellm_authz_vulnerable", "litellm_authz_safe",
]
BASE_REVISION = "a1b8121"
LABEL_FILES = ("authz", "sast-sqli", "evidence", "kev-judge", "retrieval")


def development_cases() -> list[dict]:
    path = ROOT / "benchmark" / "real_prs" / "cases.json"
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def loaded_development_cases() -> list[dict]:
    return [c for c in bench("schema").load_cases() if c.get("split") == "real_prs"]


def test_load_cases_returns_real_world_cases_then_the_13_development_cases():
    cases = bench("schema").load_cases()
    expected = [c["id"] for c in development_cases()]
    assert len(expected) == 13
    assert [c["id"] for c in cases] == REAL_WORLD_IDS + expected


def test_each_development_case_has_the_fields_components_read():
    by_id = {c["id"]: c for c in loaded_development_cases()}
    for src in development_cases():
        got = by_id[src["id"]]
        assert got["repo_url"] == f"https://github.com/{src['repo']}"
        assert got["base_ref"] == src["introducing"]["base_commit"]
        assert got["pr_ref"] == src["introducing"]["merge_commit"]
        assert got["category"] == src["category"]
        assert got["cwe"] == src["cwe"]
        assert got["description"] == src["title"]
        assert got["split"] == "real_prs"


def test_development_cases_are_four_sqli_and_nine_authz():
    categories = [c["category"] for c in loaded_development_cases()]
    assert (categories.count("sqli"), categories.count("authz")) == (4, 9)


def test_real_world_cases_keep_their_split_and_ids():
    cases = bench("schema").load_cases()[:12]
    assert [c["id"] for c in cases] == REAL_WORLD_IDS
    assert {c["split"] for c in cases} == {"real_world"}


def test_loading_cases_and_validating_shipped_labels_never_opens_heldout(monkeypatch):
    schema = bench("schema")
    real_open, real_read = builtins.open, Path.read_text

    def guard_open(file, *a, **kw):
        assert "heldout" not in str(file).lower(), file
        return real_open(file, *a, **kw)

    def guard_read(self, *a, **kw):
        assert "heldout" not in str(self).lower(), self
        return real_read(self, *a, **kw)

    monkeypatch.setattr(builtins, "open", guard_open)
    monkeypatch.setattr(Path, "read_text", guard_read)
    schema.load_cases()
    for name in LABEL_FILES:
        schema.validate_labels(json.loads(real_read(PKG / "labels" / f"{name}.json", encoding="utf-8")))


def test_loaded_cases_and_label_cases_are_only_real_world_and_development_ids():
    allowed = set(REAL_WORLD_IDS) | {c["id"] for c in development_cases()}
    assert {c["id"] for c in bench("schema").load_cases()} == allowed
    for name in LABEL_FILES:
        items = json.loads((PKG / "labels" / f"{name}.json").read_text(encoding="utf-8"))["items"]
        assert {i["case_id"] for i in items} <= allowed, name


def test_component_bench_sources_and_labels_do_not_reference_the_held_out_file():
    files = [p for p in PKG.rglob("*") if p.is_file() and p.suffix in {".py", ".json", ".md"}]
    assert files
    offenders = [p.name for p in files if "heldout" in p.read_text(encoding="utf-8").lower()]
    assert offenders == []


def test_label_for_a_development_case_is_accepted_and_still_policed():
    schema = bench("schema")
    dev = loaded_development_cases()
    dev_id, other = dev[0]["id"], dev[1]["id"]
    schema.validate_labels(doc(label("L1", dev_id)))
    with pytest.raises(schema.LabelError):
        schema.validate_labels(doc(label("L1", dev_id), label("L1", other)))
    with pytest.raises(schema.LabelError):
        schema.validate_labels(doc(label("L1", dev_id)), applicable={other})
    with pytest.raises(schema.LabelError):
        schema.validate_labels(doc(label("L1", "no_such_development_case")))


@pytest.mark.parametrize("name", LABEL_FILES)
def test_real_world_labels_are_unchanged_from_the_base_revision(name):
    rel = f"benchmark/component_bench/labels/{name}.json"
    shown = subprocess.run(
        ["git", "show", f"{BASE_REVISION}:{rel}"], cwd=ROOT, capture_output=True, encoding="utf-8"
    )
    if shown.returncode != 0:
        pytest.skip(f"base revision {BASE_REVISION} not available")
    before = json.loads(shown.stdout)["items"]
    now = {i["label_id"]: i for i in json.loads((ROOT / rel).read_text(encoding="utf-8"))["items"]}
    assert [now.get(i["label_id"]) for i in before] == before


def test_fetch_command_is_a_module_with_a_main():
    fetch = bench("fetch_real_prs")
    assert callable(fetch.main)


# AC-2-3, AC-2-7: the runner verifies a development case's clone and revisions before any component runs

DEV_CASE = "superset-where-in-sqli"
FETCH = "python -m benchmark.component_bench.fetch_real_prs"


def _git(repo: Path, *args: str) -> str:
    cmd = ["git", "-c", "user.name=t", "-c", "user.email=t@localhost", "-c", "commit.gpgsign=false"]
    return subprocess.run([*cmd, *args], cwd=repo, check=True, capture_output=True, encoding="utf-8").stdout.strip()


def _clone_with_branches(cache: Path, roles: tuple[str, ...]) -> None:
    repo = cache / "superset"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.py").write_text("x = 1")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "c")
    for role in roles:
        _git(repo, "branch", f"rw/{DEV_CASE}/{role}")


def _run_guarded(tmp_path, monkeypatch, cache: Path):
    run, reg = bench("run"), bench("registry")
    monkeypatch.setattr(run, "CLONE_CACHE", cache, raising=False)
    called: list[str] = []

    def run_item(item, ctx):
        called.append(item["case_id"])
        return "out"

    entry = reg.Entry(module=component(run_item), source="cases")
    run.run_benchmark(results_dir=tmp_path / "r", registry={"fake": entry})
    rows = {u["case_id"]: u for u in units(tmp_path / "r", "fake")}
    return rows, called


def test_runner_errors_a_development_case_without_a_clone_and_does_not_call_the_component(
    tmp_path, monkeypatch
):
    rows, called = _run_guarded(tmp_path, monkeypatch, tmp_path / "empty")
    assert set(called) == set(REAL_WORLD_IDS)
    row = rows[DEV_CASE]
    assert row["status"] == "error" and row["scores"] is None
    assert "superset" in row["reason"] and FETCH in row["reason"]


@pytest.mark.parametrize("roles", [("base",), ("pr",), ()], ids=["no-pr", "no-base", "neither"])
def test_runner_errors_a_development_case_with_a_missing_branch(tmp_path, monkeypatch, roles):
    _clone_with_branches(tmp_path / "cache", roles)
    rows, called = _run_guarded(tmp_path, monkeypatch, tmp_path / "cache")
    assert DEV_CASE not in called
    row = rows[DEV_CASE]
    assert row["status"] == "error"
    missing = {"base", "pr"} - set(roles)
    assert all(f"rw/{DEV_CASE}/{role}" in row["reason"] for role in missing)
    assert FETCH in row["reason"]


def test_runner_errors_a_development_case_whose_branches_are_not_at_the_pinned_revisions(
    tmp_path, monkeypatch
):
    _clone_with_branches(tmp_path / "cache", ("base", "pr"))
    rows, called = _run_guarded(tmp_path, monkeypatch, tmp_path / "cache")
    assert DEV_CASE not in called
    row = rows[DEV_CASE]
    assert row["status"] == "error" and row["scores"] is None
    assert FETCH in row["reason"]


# ---------------------------------------------------------------------------
# Production toolbox runs: AC-S1-3, AC-S1-4, AC-S1-7, AC-S4-2, AC-S5-1..3
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402

from tests.conftest import BENCH_TOOLBOX_COMPONENTS  # noqa: E402

GRAPH_TOOLS = ("investigate_base_code", "investigate_pr_code")
TOOLBOX_COMPONENTS = pytest.mark.parametrize("component", BENCH_TOOLBOX_COMPONENTS)
PREVIOUS_RUN = ROOT / "benchmark" / "runs" / "component-bench-2026-11-06"


@TOOLBOX_COMPONENTS
@pytest.mark.parametrize("missing", ["clone", "ref"])
def test_missing_case_clone_or_pinned_ref_is_an_error_with_reason_and_fetch_command(
    bench_env, component, missing
):
    if missing == "clone":
        bench_env.repo.rename(bench_env.cache / "elsewhere")
    else:
        bench_env.base = "1" * 40
    result = bench_env.run(component)
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None
    assert "fetch" in result.unit["reason"].lower()
    assert result.agents.toolboxes == []


@TOOLBOX_COMPONENTS
def test_unavailable_codegraph_binary_is_an_error_not_a_score(bench_env, component, tmp_path):
    result = bench_env.run(component, binary=str(tmp_path / "no-such-codegraph"))
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None
    assert "unavailable" in result.unit["reason"]


@TOOLBOX_COMPONENTS
def test_missing_rag_index_is_an_error_naming_the_failing_step(bench_env, component):
    result = bench_env.run(component, rag=False)
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None
    assert any(word in result.unit["reason"].lower() for word in ("rag", "index"))


@TOOLBOX_COMPONENTS
def test_degraded_graph_state_after_the_run_is_an_error_not_a_score(bench_env, component):
    def degrade(toolbox):
        toolbox.session._latched["pr"] = "export_failed"

    result = bench_env.run(component, effect=degrade, findings=["x"])
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None
    assert "degraded:pr:export_failed" in result.unit["reason"]
    assert result.unit["graph_state"].startswith("degraded:pr")


@TOOLBOX_COMPONENTS
def test_healthy_run_records_graph_state_ok(bench_env, component):
    assert bench_env.run(component).unit["graph_state"] == "ok"


@TOOLBOX_COMPONENTS
@pytest.mark.parametrize("fails", [False, True], ids=["succeeds", "fails"])
def test_graph_sessions_opened_for_a_unit_are_closed_after_it(bench_env, monkeypatch, component, fails):
    from benchmark.component_bench.outcomes import InfraError
    from lgtm.graph.session import GraphSession

    closed: list[int] = []
    original = GraphSession.close

    def spy_close(self):
        closed.append(id(self))
        original(self)

    monkeypatch.setattr(GraphSession, "close", spy_close)

    def boom(toolbox):
        raise InfraError("model down")

    bench_env.run(component, effect=boom if fails else None)
    sessions = [id(t.session) for t in bench_env.agents.toolboxes]
    assert sessions and set(sessions) <= set(closed)


@TOOLBOX_COMPONENTS
def test_unit_records_calls_and_invalid_calls_for_every_offered_tool_and_summary_totals_them(
    bench_env, component
):
    if component == "sast-sqli":
        calls = [{"tool": "grep_repo", "args": {"pattern": "q", "file_glob": "", "snapshot": "pr"}, "result": "r"}]
        result = bench_env.run(component, tool_calls=calls)
        (stats,) = result.unit["tools"].values()
        assert set(stats) == {"read_file", "grep_repo", "search_policy"}
        assert stats["grep_repo"] == {"calls": 1, "invalid": 0}
        assert stats["search_policy"] == {"calls": 0, "invalid": 0}
        return
    calls = [{"tool": "investigate_pr_code", "args": {"query": "q"}, "result": "r"}]
    result = bench_env.run(component, tool_calls=calls)
    (stats,) = result.unit["tools"].values()
    assert {*GRAPH_TOOLS, "search_policy"} <= set(stats)
    assert stats["investigate_pr_code"] == {"calls": 1, "invalid": 0}
    for tool in ("investigate_base_code", "search_policy"):
        assert stats[tool] == {"calls": 0, "invalid": 0}
    assert result.summary["codegraph_calls"] == 1
    assert result.summary["search_policy_calls"] == 0


def test_invalid_search_policy_call_counts_as_invalid_in_unit_and_summary_total(bench_env):
    calls = [{"tool": "search_policy", "args": {}, "result": ""}]
    result = bench_env.run("authz", tool_calls=calls)
    (stats,) = result.unit["tools"].values()
    assert stats["search_policy"] == {"calls": 1, "invalid": 1}
    assert result.summary["search_policy_calls"] == 1
    assert result.summary["codegraph_calls"] == 0


def test_summary_keeps_codegraph_and_search_policy_totals_separate(bench_env):
    calls = [
        {"tool": "investigate_pr_code", "args": {"query": "q"}, "result": "r"},
        {"tool": "investigate_base_code", "args": {"query": "q"}, "result": "r"},
        {"tool": "search_policy", "args": {"query": "who may delete"}, "result": "r"},
    ]
    result = bench_env.run("authz", tool_calls=calls)
    (stats,) = result.unit["tools"].values()
    assert stats["search_policy"] == {"calls": 1, "invalid": 0}
    assert result.summary["codegraph_calls"] == 2
    assert result.summary["search_policy_calls"] == 1


@TOOLBOX_COMPONENTS
def test_error_unit_records_no_verdict_and_keeps_its_reason(bench_env, component):
    result = bench_env.run(component, rag=False)
    assert result.unit["status"] == "error"
    assert not result.unit.get("verdict")
    assert not result.unit.get("explanation")
    assert result.unit["reason"]


def test_not_scored_unit_records_no_verdict_and_keeps_its_reason(bench_env):
    result = bench_env.run("sast-sqli")
    assert result.unit["status"] == "not_scored"
    assert not result.unit.get("verdict")
    assert not result.unit.get("explanation")
    assert "no scripted answer" in result.unit["reason"]


def test_running_the_benchmark_leaves_the_2026_11_06_results_untouched(bench_env):
    def digest():
        return {
            str(p.relative_to(PREVIOUS_RUN)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in PREVIOUS_RUN.rglob("*")
            if p.is_file()
        }

    before = digest()
    bench_env.run("authz")
    assert before and digest() == before
