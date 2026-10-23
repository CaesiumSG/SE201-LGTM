"""Unit tests: the review pipeline names the judge request format explicitly."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import lgtm.pipeline as pipeline
from lgtm.config import LGTMConfig
from lgtm.validation.judge import REQUEST_FORMATS

PRODUCTION_ELIGIBLE = {"current", "short_claim", "code_first"}


class _Validator:
    def __init__(self, *args, **kwargs):
        pass

    def validate_all(self, findings):
        return findings

    def read_cited_code(self, item):
        return ""


class _Retriever:
    def __init__(self, *args, **kwargs):
        pass

    def is_available(self):
        return True


class _Toolbox:
    def __init__(self, *args, **kwargs):
        pass

    def graph_state(self):
        return "ok"


class _Triage:
    errors: list = []

    def __init__(self, *args, **kwargs):
        pass


def _run_review(monkeypatch, mode, judge_spy):
    monkeypatch.setattr(pipeline, "get_pr_diff", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "PolicyRetriever", _Retriever)
    monkeypatch.setattr(pipeline, "AgentToolbox", _Toolbox)
    monkeypatch.setattr(pipeline, "SASTTriageAgent", _Triage)
    monkeypatch.setattr(pipeline, "EvidenceValidator", _Validator)
    monkeypatch.setattr(pipeline, "judge_candidates", judge_spy)
    monkeypatch.setattr(
        pipeline.ReviewPipeline,
        "_review_sections",
        lambda self, *a, **k: pipeline._SectionStage(
            findings=[],
            plan=None,
            results={},
            investigator_status="skipped",
            investigator_error=None,
            investigator_input="none",
            investigator_tool_calls=0,
            errors=[],
        ),
    )
    monkeypatch.setattr(pipeline, "build_coverage", lambda *a, **k: None)

    fake_judge = object()
    config = LGTMConfig(mode=mode, detect_prompt_injection=False)
    review = pipeline.ReviewPipeline(".", config, llm=object(), judge=fake_judge)
    review._review(
        "base", "pr", "base", "pr", None, session=SimpleNamespace(init_seconds=0.0)
    )
    return fake_judge


@pytest.mark.parametrize("mode", ["lgtm", "lgtm-no-sast"])
def test_production_pipeline_passes_an_explicit_eligible_request_format_to_the_judge(
    monkeypatch, mode
):
    calls = []

    def judge_spy(findings, read_code, config, judge=None, **kwargs):
        calls.append((judge, kwargs))
        return findings

    fake_judge = _run_review(monkeypatch, mode, judge_spy)

    assert len(calls) == 1
    judge, kwargs = calls[0]
    assert judge is fake_judge
    assert "request_format" in kwargs
    assert kwargs["request_format"] in PRODUCTION_ELIGIBLE
    assert kwargs["request_format"] in REQUEST_FORMATS
