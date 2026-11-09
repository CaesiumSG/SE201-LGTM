"""Token usage per review: the meter, its call sites, the report and the benchmark fields."""

import json
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from lgtm import usage
from lgtm.agents import base
from lgtm.agents.base import CHARS_PER_TOKEN, invoke_with_retry
from lgtm.agents.bedrock_llm import BedrockClaude, _Shared
from lgtm.config import LGTMConfig
from lgtm.pipeline import ReviewPipeline
from lgtm.reporting.report_builder import ReportBuilder, ReviewMetadata

ASSESSMENTS = json.dumps({"assessments": [
    {"category": "sqli", "verdict": "safe", "confidence": 0.6, "cwe_id": "CWE-89"},
    {"category": "authz", "verdict": "safe", "confidence": 0.6, "cwe_id": "CWE-862"},
]})


class _UsageLLM:
    """Replies with fixed usage; fails the first ``fail`` calls."""

    def __init__(self, content="ok", usage_metadata=None, fail=0):
        self.content, self.usage_metadata, self.fail, self.calls = content, usage_metadata, fail, 0

    def bind_tools(self, tools):  # pragma: no cover - llm-only never binds tools
        raise AssertionError("no tools expected")

    def invoke(self, messages):
        self.calls += 1
        if self.calls <= self.fail:
            raise RuntimeError("transient")
        return AIMessage(content=self.content, usage_metadata=self.usage_metadata)


def _usage(i, o):
    return {"input_tokens": i, "output_tokens": o, "total_tokens": i + o}


def test_recording_outside_a_meter_is_a_no_op():
    usage.record_llm_response(AIMessage(content="x", usage_metadata=_usage(5, 1)))
    usage.record_judge_reply({"input_tokens": 9})
    assert usage.current_summary() is None


def test_meter_sums_per_stage_and_counts_replies_without_usage():
    with usage.metering() as meter:
        with usage.stage("investigator"):
            usage.record_llm_response(AIMessage(content="", usage_metadata=_usage(100, 10)), 120)
            usage.record_llm_response(AIMessage(content="", usage_metadata=_usage(50, 5)), 60)
        with usage.stage("authz_reviewer"):
            usage.record_llm_response(SimpleNamespace(usage_metadata=None), 40)
        usage.record_llm_response(AIMessage(content="", usage_metadata=_usage(1, 1)))
        usage.record_judge_reply({"input_tokens": 700})
        usage.record_judge_reply({"input_tokens": None})
        summary = usage.current_summary()
    assert summary == meter.summary()
    reviewer = summary["reviewer"]
    assert (reviewer["calls"], reviewer["input_tokens"], reviewer["output_tokens"]) == (4, 151, 16)
    assert reviewer["total_tokens"] == 167
    assert reviewer["unreported_calls"] == 1
    assert reviewer["estimated_input_tokens"] == 220
    assert reviewer["by_stage"]["investigator"]["calls"] == 2
    assert reviewer["by_stage"]["authz_reviewer"]["unreported_calls"] == 1
    assert reviewer["by_stage"][usage.UNLABELLED]["input_tokens"] == 1
    assert summary["judge"] == {"calls": 2, "input_tokens": 700, "unreported_calls": 1}
    assert usage.current_summary() is None  # the meter closes with the block


@pytest.mark.parametrize("bad", [{"input_tokens": -1}, {"input_tokens": True}, {"input_tokens": "9"}, "junk"])
def test_malformed_usage_counts_as_unreported(bad):
    with usage.metering() as meter:
        usage.record_llm_response(SimpleNamespace(usage_metadata=bad))
    assert meter.summary()["reviewer"]["unreported_calls"] == 1
    assert meter.summary()["reviewer"]["input_tokens"] == 0


def test_invoke_with_retry_records_only_the_successful_attempt(monkeypatch):
    monkeypatch.setattr(base, "_sleep", lambda s: None)
    llm = _UsageLLM(usage_metadata=_usage(300, 20), fail=1)
    config = LGTMConfig(llm_retries=2, llm_backoff_seconds=[0])
    messages = [HumanMessage(content="x" * 400)]
    with usage.metering() as meter:
        with usage.stage("sast_triage"):
            invoke_with_retry(llm, messages, config)
    stage = meter.summary()["reviewer"]["by_stage"]["sast_triage"]
    assert llm.calls == 2
    assert stage == {"calls": 1, "input_tokens": 300, "output_tokens": 20,
                     "estimated_input_tokens": 400 // CHARS_PER_TOKEN, "unreported_calls": 0}


def test_judge_replies_are_counted(git_repo):
    from lgtm.agents.base import AgentFinding, EvidenceItem
    from lgtm.validation.judge import judge_candidates

    finding = AgentFinding(
        finding_id="f1", agent="authz", category="authz", verdict="vulnerable", cwe_id="CWE-862",
        file="app.py", line=2, explanation="x",
        evidence=[EvidenceItem(type="code", file="app.py", lines=[1, 2], content="def get_user")],
    )
    reply = {"supported": "yes", "provenance_confidence": 0.9, "verdict": "real",
             "severity": "high", "input_tokens": 1234}
    with usage.metering() as meter:
        judge_candidates([finding], lambda item: "def get_user(cursor, user_id):", LGTMConfig(),
                         judge=lambda request: reply)
    assert finding.judged
    assert meter.summary()["judge"] == {"calls": 1, "input_tokens": 1234, "unreported_calls": 0}


def test_bedrock_usage_includes_cached_prompt_tokens(tmp_path):
    from tests.test_bedrock_llm import MODEL, FakeClient, _reply, _usage as bedrock_usage

    fake = FakeClient([_reply(SimpleNamespace(type="text", text="hi"), usage=bedrock_usage(i=100, o=7, w=40, r=900))])
    config = LGTMConfig(llm_backend="bedrock", bedrock_model=MODEL, bedrock_ledger=str(tmp_path / "s.jsonl"))
    out = BedrockClaude(config, shared=_Shared(client=fake)).invoke([SystemMessage(content="s"), HumanMessage(content="u")])
    assert out.usage_metadata["input_tokens"] == 1040
    assert out.usage_metadata["output_tokens"] == 7
    assert out.usage_metadata["total_tokens"] == 1047
    assert out.usage_metadata["input_token_details"] == {"cache_creation": 40, "cache_read": 900}
    row = json.loads((tmp_path / "s.jsonl").read_text())
    assert (row["input"], row["cache_write"], row["cache_read"]) == (100, 40, 900)  # ledger unchanged


def test_pipeline_reports_reviewer_tokens(git_repo, tmp_path):
    llm = _UsageLLM(ASSESSMENTS, usage_metadata=_usage(2000, 150))
    result = ReviewPipeline(git_repo, LGTMConfig(mode="llm-only"), llm=llm).run(
        "main", "pr", output_dir=tmp_path / "out")
    reviewer = result.meta.token_usage["reviewer"]
    assert reviewer["calls"] == llm.calls >= 1
    assert reviewer["input_tokens"] == 2000 * llm.calls
    assert set(reviewer["by_stage"]) == {"plain_reviewer"}
    report = json.loads(result.json_path.read_text())
    assert report["review"]["token_usage"] == result.meta.token_usage
    assert "**Tokens (reviewer model):** " in result.md_path.read_text()
    assert usage.current_summary() is None


def test_sast_only_makes_no_model_calls(git_repo):
    result = ReviewPipeline(git_repo, LGTMConfig(mode="sast-only")).run("main", "pr")
    assert result.meta.token_usage["reviewer"]["calls"] == 0
    assert "Tokens" not in ReportBuilder(result.findings, result.meta).build_markdown()


def test_report_without_usage_omits_the_tokens_line():
    md = ReportBuilder([], ReviewMetadata()).build_markdown()
    assert "Tokens" not in md


def test_record_fields_and_medians():
    summaries = [
        {"reviewer": {"calls": 3, "input_tokens": 1000, "output_tokens": 100, "total_tokens": 1100,
                      "estimated_input_tokens": 900, "unreported_calls": 0, "by_stage": {}},
         "judge": {"calls": 1, "input_tokens": 500, "unreported_calls": 0}},
        {"reviewer": {"calls": 5, "input_tokens": 3000, "output_tokens": 300, "total_tokens": 3300,
                      "estimated_input_tokens": 2800, "unreported_calls": 1, "by_stage": {}},
         "judge": {"calls": 0, "input_tokens": 0, "unreported_calls": 0}},
        None,  # sast-only or a crash: no model calls, left out of the medians
    ]
    records = [usage.record_fields(s) for s in summaries]
    assert records[0]["total_tokens"] == 1100 and records[0]["judge_input_tokens"] == 500
    assert records[2]["llm_calls"] == 0
    out = usage.summarize_records(records)
    assert out["cases_with_tokens"] == 2
    assert out["cases_with_unreported_calls"] == 1
    assert out["median_total_tokens_per_pr"] == 2200.0
    assert out["median_input_tokens_per_pr"] == 2000.0
    assert out["median_llm_calls_per_pr"] == 4.0
    assert usage.summarize_records([])["median_total_tokens_per_pr"] is None
