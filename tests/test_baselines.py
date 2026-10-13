"""Tests for the plain LLM-only baseline and the benchmark scoring rules."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock

from lgtm.agents.plain_reviewer import PlainLLMReviewer
from lgtm.config import LGTMConfig
from lgtm.pipeline import ReviewPipeline

_spec = importlib.util.spec_from_file_location(
    "bench_evaluate",
    Path(__file__).resolve().parent.parent / "benchmark" / "evaluate.py",
)
evaluate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(evaluate)


class _NoToolsLLM:
    """Records calls and fails loudly if anyone tries to bind tools."""

    def __init__(self, content: str):
        self.content = content
        self.calls = 0

    def bind_tools(self, tools):  # pragma: no cover - must never be called
        raise AssertionError("llm-only baseline must not use tools")

    def invoke(self, messages):
        self.calls += 1
        self.messages = messages
        msg = MagicMock()
        msg.content = self.content
        msg.tool_calls = []
        return msg


ASSESSMENTS = json.dumps({
    "assessments": [
        {
            "category": "sqli", "verdict": "vulnerable", "confidence": 0.9,
            "cwe_id": "CWE-89", "file": "app.py", "line": 6,
            "explanation": "f-string into execute",
            "evidence": [{"type": "code", "file": "app.py", "lines": [6, 6],
                          "content": "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"}],
        },
        {"category": "authz", "verdict": "safe", "confidence": 0.6, "cwe_id": "CWE-862"},
    ]
})


class TestPlainReviewer:
    def test_parses_one_finding_per_category(self):
        findings = PlainLLMReviewer._parse(ASSESSMENTS)
        assert [(f.category, f.verdict) for f in findings] == [
            ("sqli", "vulnerable"), ("authz", "safe"),
        ]
        assert findings[0].line == 6 and findings[0].agent == "plain_llm"

    def test_category_inferred_from_cwe(self):
        raw = json.dumps({"assessments": [{"verdict": "vulnerable", "cwe_id": "CWE-89"}]})
        assert PlainLLMReviewer._parse(raw)[0].category == "sqli"

    def test_unparsable_output_degrades(self):
        findings = PlainLLMReviewer._parse("I think it is fine.")
        assert len(findings) == 1
        assert findings[0].verdict == "insufficient_evidence"

    def test_llm_only_pipeline_uses_no_sast_rag_or_tools(self, git_repo):
        llm = _NoToolsLLM(ASSESSMENTS)
        config = LGTMConfig(mode="llm-only")
        result = ReviewPipeline(git_repo, config, llm=llm).run("main", "pr")
        assert llm.calls == 1
        assert result.meta.semgrep_findings_in_diff == 0
        prompt = llm.messages[1].content
        assert "find_user" in prompt  # the diff is the only context
        sqli = [f for f in result.findings if f.category == "sqli"][0]
        assert sqli.verdict == "vulnerable"
        assert sqli.evidence_valid is True  # snippet is in the PR's added lines


def _f(category, verdict, valid=True):
    return {"category": category, "verdict": verdict, "evidence_valid": valid}


class TestCaseScoring:
    def test_other_category_findings_do_not_leak(self):
        # Regression: an authz case whose only finding is a SQLi "vulnerable"
        # used to fall back to all findings and be scored as flagged.
        assert evaluate.predict_case_verdict([_f("sqli", "vulnerable")], "authz") == "safe"

    def test_uncategorized_findings_count_for_any_category(self):
        assert evaluate.predict_case_verdict([_f("sast", "vulnerable")], "sqli") == "vulnerable"

    def test_grounded_scoring_discounts_unvalidated_detections(self):
        findings = [_f("authz", "vulnerable", valid=False)]
        assert evaluate.predict_case_verdict(findings, "authz") == "vulnerable"
        assert (
            evaluate.predict_case_verdict(findings, "authz", require_grounded=True)
            == "possible"
        )

    def test_score_case_and_summary_splits(self):
        rows = [
            evaluate.score_case({"id": "a", "category": "authz", "split": "dev",
                                 "expected": "vulnerable",
                                 "findings": [_f("authz", "vulnerable", valid=False)],
                                 "latency_seconds": 1.0, "est_tokens": 10}),
            evaluate.score_case({"id": "b", "category": "authz", "split": "eval",
                                 "expected": "safe", "findings": [_f("authz", "safe")],
                                 "latency_seconds": 1.0, "est_tokens": 10}),
        ]
        assert rows[0]["outcome"] == "TP" and rows[0]["outcome_grounded"] == "FN"
        summary = evaluate.summarize(rows)
        assert set(summary["per_split"]) == {"dev", "eval"}
        assert summary["overall"]["recall"] == 1.0
        assert summary["grounded_only"]["overall"]["recall"] == 0.0


class TestRescore:
    def _run_dir(self, tmp_path):
        out = tmp_path / "run"
        out.mkdir()
        cases = [
            {"id": "a", "category": "authz", "split": "dev", "expected_verdict": "vulnerable"},
            {"id": "b", "category": "authz", "split": "eval", "expected_verdict": "safe"},
        ]
        (out / "a.json").write_text(json.dumps({
            "id": "a", "category": "authz", "expected": "vulnerable",
            "findings": [_f("authz", "vulnerable")], "latency_seconds": 1, "est_tokens": 1,
        }))
        # An error result in the pre-grounding format (no outcome_grounded)
        (out / "b.json").write_text(json.dumps({
            "id": "b", "category": "authz", "expected": "safe", "predicted": "error",
            "outcome": "TN", "correct": True, "findings": [], "latency_seconds": 0,
            "est_tokens": 0,
        }))
        (out / "summary.json").write_text(json.dumps({
            "mode": "lgtm", "model": "m", "generated_at": "then", "git_commit": "abc",
            "split": "all", "experiments": {"static_facts": True},
            "outcomes": {"a": "TP", "b": "TN"}, "summary": {},
        }))
        return out, cases

    def test_keeps_provenance_and_handles_old_errors(self, tmp_path):
        out, cases = self._run_dir(tmp_path)
        evaluate.rescore(out, cases, "lgtm")
        saved = json.loads((out / "summary.json").read_text())
        assert saved["generated_at"] == "then" and saved["git_commit"] == "abc"
        assert saved["experiments"] == {"static_facts": True}
        assert "rescored_at_commit" in saved
        assert saved["outcomes"] == {"a": "TP", "b": "TN"}

    def test_refuses_partial_rescore(self, tmp_path):
        import pytest

        out, cases = self._run_dir(tmp_path)
        with pytest.raises(SystemExit):
            evaluate.rescore(out, cases[:1], "lgtm")
