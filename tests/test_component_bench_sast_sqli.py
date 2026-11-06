"""Unit tests for the SAST SQLi triage benchmark: labels, keep/drop scoring, infra errors."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmark.component_bench import metrics, registry, run, schema  # noqa: E402
from benchmark.component_bench import sast_sqli  # noqa: E402
from benchmark.component_bench.outcomes import InfraError, NotScored  # noqa: E402
from lgtm.agents import registry as prompts  # noqa: E402
from lgtm.config import LGTMConfig  # noqa: E402
from lgtm.validation import judge as judge_mod  # noqa: E402

LABELS = ROOT / "benchmark" / "component_bench" / "labels" / "sast-sqli.json"


def sqli_case_ids() -> set[str]:
    return {c["id"] for c in schema.load_cases() if c["category"] == "sqli"}


def shipped_labels() -> dict:
    return json.loads(LABELS.read_text(encoding="utf-8"))


def item(distractor: bool, label_id="L1", case_id="pyload_sqli_vulnerable") -> dict:
    return {
        "label_id": label_id,
        "case_id": case_id,
        "source": "fix commit",
        "review_state": "draft",
        "gold_input": {
            "rule_id": "python.sqli",
            "path": "app.py",
            "start_line": 3,
            "end_line": 3,
            "message": "tainted query",
            "severity": "ERROR",
            "matched_code": "cur.execute(q)",
        },
        "gold": {"keep": not distractor},
        **({"distractor": True} if distractor else {}),
    }


class UnreachableLLM:
    def bind_tools(self, *args, **kwargs):
        return self

    def model_copy(self, *args, **kwargs):
        return self

    def invoke(self, *args, **kwargs):
        raise ConnectionError("model endpoint unreachable")


def judge_answer(supported="yes"):
    return {
        judge_mod.QUESTION_SUPPORT: supported,
        judge_mod.QUESTION_CONFIDENCE: 0.9,
        judge_mod.QUESTION_VERDICT: "vulnerable",
        judge_mod.QUESTION_SEVERITY: "high",
    }


class FakeJudge:
    def __init__(self, answer=None, error=None):
        self.answer, self.error, self.requests = answer, error, []

    def __call__(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.answer


def ctx(llm, judge=None):
    return SimpleNamespace(
        config=LGTMConfig(), metrics=metrics.Metrics(), llm=llm, judge=judge or FakeJudge(judge_answer())
    )


# AC-S1-8
def test_four_development_sqli_cases_carry_draft_labels_and_are_registered():
    dev = {c["id"] for c in schema.load_cases() if c["split"] == "real_prs" and c["category"] == "sqli"}
    assert len(dev) == 4
    items = shipped_labels()["items"]
    assert dev <= {i["case_id"] for i in items}
    assert {i["review_state"] for i in items if i["case_id"] in dev} == {"draft"}
    assert dev <= set(registry.REGISTRY["sast-sqli"].applicable)


def test_shipped_labels_cover_each_sqli_case_with_a_gold_hit_and_no_authz_case():
    doc = shipped_labels()
    sqli = sqli_case_ids()
    schema.validate_labels(doc, sqli)
    keep_cases = {i["case_id"] for i in doc["items"] if i["gold"]["keep"]}
    assert len(sqli) == 10
    assert {i["case_id"] for i in doc["items"]} == sqli
    assert keep_cases == {
        "pyload_sqli_vulnerable",
        "postgraas_sqli_vulnerable",
        "alerta_sqli_vulnerable",
        "alerta_sqli_safe",
        "superset-where-in-sqli",
        "litellm-global-spend-logs-sqli",
        "redash-query-results-param-sqli",
        "django-explain-options-sqli",
    }
    authz = {c["id"] for c in schema.load_cases() if c["category"] == "authz"}
    assert not authz & {i["case_id"] for i in doc["items"]}


def stage_output(triage, judge="not_run"):
    return {"stages": {"triage": {"decision": triage, "explanation": "e"}, "judge": {"decision": judge, "explanation": "e"}}}


def stage_unit(distractor, triage, judge="not_run"):
    return {
        "status": "scored",
        **stage_output(triage, judge),
        "detail": {"gold_keep": not distractor},
        "scores": sast_sqli.score(item(distractor), stage_output(triage, judge)),
    }


# AC-S3-3
@pytest.mark.parametrize(
    "distractor, triage, judge, triage_correct, judge_correct",
    [
        (False, "keep", "keep", 1.0, 1.0),
        (True, "drop", "drop", 1.0, 1.0),
        (True, "keep", "keep", 0.0, 0.0),
        (False, "keep", "drop", 1.0, 0.0),
        (True, "keep", "drop", 0.0, 1.0),
        (False, "drop", "not_run", 0.0, None),
        (True, "drop", "not_run", 1.0, None),
    ],
)
def test_keep_drop_outcome_per_hit(distractor, triage, judge, triage_correct, judge_correct):
    scores = sast_sqli.score(item(distractor), stage_output(triage, judge))
    assert scores == {"triage_correct": triage_correct, "judge_correct": judge_correct}


def test_precision_recall_f1_from_unit_scores():
    # judge stage: 1 tp, 0 fp, 2 fn -> precision 1, recall 1/3, F1 1/2 (the arithmetic mean would be 2/3)
    units = [
        stage_unit(False, "keep", "keep"),
        stage_unit(False, "keep", "drop"),
        stage_unit(False, "keep", "drop"),
        stage_unit(True, "keep", "drop"),
        {"status": "not_scored", "reason": "unparsable"},
    ]
    out = sast_sqli.aggregate(units, None)
    assert out["judge"]["precision"] == pytest.approx(1.0)
    assert out["judge"]["recall"] == pytest.approx(1 / 3)
    assert out["judge"]["f1"] == pytest.approx(0.5)
    # triage stage keeps every hit: 3 tp, 1 fp, 0 fn, unaffected by the judge decisions
    assert out["triage"]["precision"] == pytest.approx(0.75)
    assert out["triage"]["recall"] == pytest.approx(1.0)


@pytest.mark.parametrize("units", [[], [(True, "keep", "drop")], [(True, "keep", "keep")]])
def test_aggregate_without_true_positives_is_zero(units):
    scored = [stage_unit(*u) for u in units]
    assert sast_sqli.aggregate(scored, None)["judge"] == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


class ReplyLLM:
    """Fake chat model returning the same reply for every call."""

    def __init__(self, content):
        self.content = content

    def bind_tools(self, *args, **kwargs):
        return self

    def model_copy(self, *args, **kwargs):
        return self

    def invoke(self, *args, **kwargs):
        return SimpleNamespace(content=self.content, tool_calls=[])


HIT_LINE = "    cur.execute(f\"select * from t where id={x}\")"


def excerpt_item():
    it = item(False)
    it["gold_input"].update(start_line=4, end_line=4, matched_code=HIT_LINE.strip())
    it["gold_input"]["excerpt"] = {"start_line": 3, "lines": ["def q(cur, x):", HIT_LINE]}
    return it


def agent_reply(evidence):
    return json.dumps(
        {"finding_id": "x", "cwe_id": "CWE-89", "explanation": "tainted", "evidence": evidence}
    )


CITED_HIT = [{"type": "code", "file": "app.py", "lines": [4, 4], "content": HIT_LINE}]


# AC-S3-2, AC-S1-2: the judge answer on the case clone decides the judge stage
@pytest.mark.parametrize("answer, decision", [("yes", "keep"), ("no", "drop")])
def test_judge_answer_on_a_cited_resolving_reply_decides_the_judge_stage(bench_env, answer, decision):
    result, judge = two_stage(bench_env, KEEP_REPLY, answer)
    assert result.unit["stages"]["judge"]["decision"] == decision
    assert len(judge.requests) == 1
    assert "sast_triage" in result.unit["tools"]


def test_agent_reply_citing_code_absent_from_the_clone_still_reaches_the_judge(bench_env):
    cited = [{"type": "code", "file": "app.py", "lines": [2, 2], "content": "    os.system(cmd)"}]
    result, judge = two_stage(bench_env, agent_reply(cited), "no")
    assert result.unit["stages"]["judge"]["decision"] == "drop"
    assert "cur.execute" in json.dumps(judge.requests)


@pytest.mark.parametrize(
    "judge",
    [
        FakeJudge(error=ConnectionError("judge unreachable")),
        FakeJudge({**judge_answer(), judge_mod.QUESTION_CONFIDENCE: 7}),
        FakeJudge({judge_mod.QUESTION_SUPPORT: "yes"}),
    ],
    ids=["raises", "bad-confidence", "missing-keys"],
)
def test_judge_that_cannot_answer_is_an_infra_error_not_a_score(bench_env, judge):
    result = bench_env.run("sast-sqli", llm=PromptLLM(KEEP_REPLY), judge=judge)
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None


# AC-S1-4
def test_unparsable_agent_reply_is_not_scored(bench_env):
    result = bench_env.run("sast-sqli", llm=ReplyLLM("I cannot answer in JSON."), judge=FakeJudge(judge_answer()))
    assert result.unit["status"] == "not_scored"


# AC-S1-5
def test_unreachable_model_endpoint_is_an_infra_error_not_a_score(bench_env):
    result = bench_env.run("sast-sqli", llm=UnreachableLLM(), judge=FakeJudge(judge_answer()))
    assert result.unit["status"] == "error"
    assert result.unit["scores"] is None

# AC-S5-6
def test_only_sqli_cases_run_and_each_unit_names_case_and_label(tmp_path, monkeypatch):
    for mod in (run, sast_sqli):
        monkeypatch.setattr(mod, "CLONE_CACHE", tmp_path / "no-clones")
    entry = registry.REGISTRY["sast-sqli"]
    run.run_benchmark(
        tmp_path / "results", registry={"sast-sqli": entry}, llm=UnreachableLLM(), config=LGTMConfig()
    )
    units = json.loads((tmp_path / "results" / "sast-sqli.json").read_text())["units"]
    labels = shipped_labels()["items"]
    assert [(u["case_id"], u["label_id"]) for u in units] == [
        (i["case_id"], i["label_id"]) for i in labels
    ]
    assert {u["case_id"] for u in units} <= sqli_case_ids()


# AC-3-3, AC-3-4: unparsable is read from the error kind, never from the message wording


def run_with_error(bench_env, monkeypatch, kind, message):
    class FakeAgent:
        def __init__(self, toolbox, config=None, llm=None):
            self.toolbox = toolbox
            self.run_records = []
            self.errors = [{"source": "f", "kind": kind, "message": message}]

        def triage(self, finding, file_diff, facts=""):
            return None

    monkeypatch.setattr(sast_sqli, "SASTTriageAgent", FakeAgent)
    return bench_env.run("sast-sqli", llm=object(), judge=FakeJudge(judge_answer())).unit


@pytest.mark.parametrize(
    "message",
    ["Triage answer could not be parsed.", "", prompts.entry("shared.unparsable_explanation")],
    ids=["reworded", "empty", "current-prompt-text"],
)
def test_unparsable_kind_is_not_scored_whatever_the_message(bench_env, monkeypatch, message):
    assert run_with_error(bench_env, monkeypatch, "unparsable", message)["status"] == "not_scored"


@pytest.mark.parametrize(
    "message",
    ["model endpoint unreachable", prompts.entry("shared.unparsable_explanation")],
    ids=["unreachable", "unparsable-wording"],
)
def test_failed_kind_is_an_infra_error_even_when_the_message_reads_as_unparsable(bench_env, monkeypatch, message):
    assert run_with_error(bench_env, monkeypatch, "failed", message)["status"] == "error"


# AC-S1-1 (decision): triage is offered the production triage toolbox, without CodeGraph tools
def test_sast_sqli_offers_the_production_triage_tools_and_no_codegraph_tools(bench_env):
    from lgtm.graph.session import GraphSession
    from lgtm.rag.retriever import PolicyRetriever

    result = bench_env.run("sast-sqli")
    toolbox = result.agents.toolboxes[0]
    assert isinstance(toolbox.session, GraphSession)
    assert type(toolbox.retriever) is PolicyRetriever
    (stats,) = result.unit["tools"].values()
    assert set(stats) == {"read_file", "grep_repo", "search_policy"}



# ---------------------------------------------------------------------------
# Real clone, PR diff, two stages: AC-S3-1..4, AC-S4-1
# ---------------------------------------------------------------------------


class PromptLLM(ReplyLLM):
    def __init__(self, content):
        super().__init__(content)
        self.prompts = []

    def invoke(self, *args, **kwargs):
        self.prompts.append(str(args))
        return super().invoke(*args, **kwargs)


KEEP_REPLY = agent_reply([{"type": "code", "file": "app.py", "lines": [2, 2], "content": HIT_LINE}])
DROP_REPLY = agent_reply([])


def two_stage(bench_env, triage_reply, judge_supported, gold_keep=False, llm=None):
    judge = FakeJudge(judge_answer(judge_supported))
    result = bench_env.run("sast-sqli", llm=llm or PromptLLM(triage_reply), judge=judge, gold_keep=gold_keep)
    return result, judge


def test_triage_receives_the_sanitized_pr_diff_of_the_finding_file(bench_env):
    llm = PromptLLM(KEEP_REPLY)
    two_stage(bench_env, None, "yes", llm=llm)
    prompt = "\n".join(llm.prompts)
    assert "PR_ONLY = 1" in prompt
    assert "NOTE-STRIPPED" not in prompt
    assert "tainted query" in prompt


def test_unit_records_triage_and_judge_stages_each_with_decision_and_explanation(bench_env):
    result, _ = two_stage(bench_env, KEEP_REPLY, "no")
    stages = result.unit["stages"]
    assert stages["triage"]["decision"] == "keep"
    assert "tainted" in stages["triage"]["explanation"]
    assert stages["judge"]["decision"] == "drop"
    assert "explanation" in stages["judge"]
    assert result.unit["verdict"] and "tainted" in result.unit["explanation"]


@pytest.mark.parametrize(
    "gold_keep, judge_supported, triage_correct, judge_correct",
    [(False, "no", 0.0, 1.0), (True, "no", 1.0, 0.0), (True, "yes", 1.0, 1.0), (False, "yes", 0.0, 0.0)],
)
def test_each_stage_is_scored_against_the_label_independently(
    bench_env, gold_keep, judge_supported, triage_correct, judge_correct
):
    result, _ = two_stage(bench_env, KEEP_REPLY, judge_supported, gold_keep=gold_keep)
    scores = result.unit["scores"]
    assert (scores["triage_correct"], scores["judge_correct"]) == (triage_correct, judge_correct)


@pytest.mark.parametrize("gold_keep", [True, False])
def test_triage_drop_records_judge_as_not_run_and_scores_triage_alone(bench_env, gold_keep):
    result, judge = two_stage(bench_env, DROP_REPLY, "yes", gold_keep=gold_keep)
    unit = result.unit
    assert unit["status"] == "scored"
    assert unit["stages"]["triage"]["decision"] == "drop"
    assert unit["stages"]["judge"]["decision"] == "not_run"
    assert judge.requests == []
    assert unit["scores"]["triage_correct"] == float(not gold_keep)
    assert unit["scores"].get("judge_correct") is None
