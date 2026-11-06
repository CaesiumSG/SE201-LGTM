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


# AC-S5-3, AC-S5-4
@pytest.mark.parametrize(
    "distractor, kept, outcome",
    [
        (False, True, "tp"),
        (True, False, "tn"),
        (True, True, "fp"),
        (False, False, "fn"),
    ],
)
def test_keep_drop_outcome_per_hit(distractor, kept, outcome):
    scores = sast_sqli.score(item(distractor), {"kept": kept})
    assert {k: scores[k] for k in ("tp", "tn", "fp", "fn")} == {
        k: float(k == outcome) for k in ("tp", "tn", "fp", "fn")
    }
    assert scores["correct"] == float(outcome in ("tp", "tn"))


def test_precision_recall_f1_from_unit_scores():
    def unit(distractor, kept):
        return {"status": "scored", "scores": sast_sqli.score(item(distractor), {"kept": kept})}

    # 1 tp, 0 fp, 2 fn -> precision 1, recall 1/3, F1 1/2 (the arithmetic mean would be 2/3)
    units = [unit(False, True), unit(False, False), unit(False, False), unit(True, False)]
    units.append({"status": "not_scored", "reason": "unparsable"})
    out = sast_sqli.aggregate(units, None)
    assert out["precision"] == pytest.approx(1.0)
    assert out["recall"] == pytest.approx(1 / 3)
    assert out["f1"] == pytest.approx(0.5)


@pytest.mark.parametrize("units", [[], [("tn", True, False)], [("fp", True, True)]])
def test_aggregate_without_true_positives_is_zero(units):
    scored = [
        {"status": "scored", "scores": sast_sqli.score(item(d), {"kept": k})} for _, d, k in units
    ]
    assert sast_sqli.aggregate(scored, None) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


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


# AC-S5-3, AC-S5-4
@pytest.mark.parametrize("answer, kept", [("yes", True), ("no", False)])
def test_judge_answer_on_a_cited_resolving_reply_decides_keep(answer, kept):
    judge = FakeJudge(judge_answer(answer))
    c = ctx(ReplyLLM(agent_reply(CITED_HIT)), judge)
    assert sast_sqli.run_item(excerpt_item(), c) == {"kept": kept}
    assert len(judge.requests) == 1
    assert "sast_triage" in c.metrics.tools


def test_agent_reply_citing_code_absent_from_the_excerpt_is_dropped():
    cited = [{"type": "code", "file": "app.py", "lines": [4, 4], "content": "    os.system(cmd)"}]
    judge = FakeJudge(judge_answer("no"))
    assert sast_sqli.run_item(excerpt_item(), ctx(ReplyLLM(agent_reply(cited)), judge)) == {"kept": False}
    assert "cur.execute" in json.dumps(judge.requests)


def test_agent_reply_without_evidence_is_dropped_without_asking_the_judge():
    reply = json.loads(agent_reply([]))
    reply["verdict"] = "vulnerable"
    judge = FakeJudge(judge_answer("yes"))
    assert sast_sqli.run_item(excerpt_item(), ctx(ReplyLLM(json.dumps(reply)), judge)) == {"kept": False}
    assert judge.requests == []


@pytest.mark.parametrize(
    "judge",
    [
        FakeJudge(error=ConnectionError("judge unreachable")),
        FakeJudge({**judge_answer(), judge_mod.QUESTION_CONFIDENCE: 7}),
        FakeJudge({judge_mod.QUESTION_SUPPORT: "yes"}),
    ],
    ids=["raises", "bad-confidence", "missing-keys"],
)
def test_judge_that_cannot_answer_is_an_infra_error_not_a_score(judge):
    with pytest.raises(InfraError):
        sast_sqli.run_item(excerpt_item(), ctx(ReplyLLM(agent_reply(CITED_HIT)), judge))


@pytest.mark.parametrize("helper", ["_commit_excerpt", "resolve_refs"])
def test_git_failure_in_temp_repo_setup_is_an_infra_error(monkeypatch, helper):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(128, ["git"])

    monkeypatch.setattr(sast_sqli, helper, fail)
    with pytest.raises(InfraError):
        sast_sqli.run_item(excerpt_item(), ctx(ReplyLLM(agent_reply(CITED_HIT))))


# AC-S5-5
def test_unparsable_agent_reply_is_not_scored():
    out = sast_sqli.run_item(excerpt_item(), ctx(ReplyLLM("I cannot answer in JSON.")))
    assert isinstance(out, NotScored)


# AC-S5-5
def test_unreachable_model_endpoint_is_an_infra_error_not_a_score():
    with pytest.raises(InfraError):
        sast_sqli.run_item(item(False), ctx(UnreachableLLM()))


# AC-S5-6
def test_only_sqli_cases_run_and_each_unit_names_case_and_label(tmp_path):
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


def run_with_error(monkeypatch, kind, message):
    class FakeAgent:
        def __init__(self, toolbox, config=None, llm=None):
            self.toolbox = SimpleNamespace(build_tools=lambda graph=False: [])
            self.run_records = []
            self.errors = [{"source": "f", "kind": kind, "message": message}]

        def triage(self, finding, semgrep_notes):
            return None

    monkeypatch.setattr(sast_sqli, "SASTTriageAgent", FakeAgent)
    return sast_sqli.run_item(item(False), ctx(object()))


@pytest.mark.parametrize(
    "message",
    ["Triage answer could not be parsed.", "", prompts.entry("shared.unparsable_explanation")],
    ids=["reworded", "empty", "current-prompt-text"],
)
def test_unparsable_kind_is_not_scored_whatever_the_message(monkeypatch, message):
    assert isinstance(run_with_error(monkeypatch, "unparsable", message), NotScored)


@pytest.mark.parametrize(
    "message",
    ["model endpoint unreachable", prompts.entry("shared.unparsable_explanation")],
    ids=["unreachable", "unparsable-wording"],
)
def test_failed_kind_is_an_infra_error_even_when_the_message_reads_as_unparsable(monkeypatch, message):
    with pytest.raises(InfraError):
        run_with_error(monkeypatch, "failed", message)
