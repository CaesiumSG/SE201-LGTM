"""Unit tests for the judge request builder and the application of a judge answer."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.config import LGTMConfig
from lgtm.validation.judge import apply_judge_answer, build_judge_request, judge_candidates

VERDICTS = {"vulnerable", "possible", "safe", "insufficient_evidence"}
SEVERITIES = {"critical", "high", "medium", "low"}
MAX_CHARS = 200_000


def _item(file="app.py", lines=(10, 12), content="AGENT_SNIPPET", snapshot="pr", grounded=None):
    return EvidenceItem(
        type="code", file=file, lines=list(lines), content=content,
        snapshot=snapshot, grounded_in_pr=grounded,
    )


def _candidate(**kwargs) -> AgentFinding:
    fields = {
        "finding_id": "f1",
        "cwe_id": "CWE-89",
        "explanation": "RATIONALE_SENTINEL query is built from user input",
        "evidence": [_item(grounded=True)],
        "evidence_valid": True,
        "evidence_issues": [],
        "pr_graph_ok": True,
        "category": "sqli",
        "agent": "authz",
        "file": "app.py",
        "line": 10,
    }
    fields.update(kwargs)
    return AgentFinding(**fields)


def _build(finding, read_code=lambda item: "CODE_AT_LOCATION", max_chars=MAX_CHARS, model="kev-test"):
    return build_judge_request(finding, read_code, model=model, max_chars=max_chars)


def _state(finding, **kwargs) -> str:
    return _build(finding, **kwargs)["state"]


def _labels(criteria) -> set[str]:
    return set(criteria)


class TestJudgeRequestContent:
    def test_request_names_the_model_and_asks_three_independent_questions(self):
        request = _build(_candidate())

        assert request["model"] == "kev-test"
        questions = request["questions"]
        assert len(questions) == 3
        verdict = [q for q in questions.values() if q["type"] == "choice" and _labels(q["criteria"]) == VERDICTS]
        severity = [q for q in questions.values() if _labels(q.get("criteria") or []) == SEVERITIES]
        confidence = [q for q in questions.values() if q["type"] == "noul"]
        assert (len(verdict), len(severity), len(confidence)) == (1, 1, 1)

    def test_state_carries_claim_cwe_and_rationale(self):
        state = _state(_candidate(cwe_id="CWE-639"))

        assert "RATIONALE_SENTINEL" in state
        assert "CWE-639" in state

    def test_state_carries_code_read_at_the_cited_location_not_the_agent_snippet(self):
        finding = _candidate(evidence=[_item(content="AGENT_SNIPPET_SENTINEL", grounded=True)])
        seen = []

        def read_code(item):
            seen.append(item)
            return "REAL_CODE_SENTINEL"

        state = _state(finding, read_code=read_code)

        assert "REAL_CODE_SENTINEL" in state
        assert "AGENT_SNIPPET_SENTINEL" not in state
        assert [(i.file, i.lines, i.snapshot) for i in seen] == [("app.py", [10, 12], "pr")]

    def test_state_carries_the_code_of_every_cited_item(self):
        finding = _candidate(evidence=[
            _item(file="a.py", lines=(1, 2), grounded=True),
            _item(file="b.py", lines=(5, 6), snapshot="base", grounded=False),
        ])

        state = _state(finding, read_code=lambda item: f"CODE_OF_{item.file}")

        assert "CODE_OF_a.py" in state
        assert "CODE_OF_b.py" in state

    def test_state_carries_each_cited_location(self):
        finding = _candidate(evidence=[_item(file="routes/orders.py", lines=(41, 47), grounded=True)])

        state = _state(finding)

        assert "routes/orders.py" in state
        assert "41" in state and "47" in state

    def test_state_carries_grounding_issues(self):
        finding = _candidate(
            evidence_valid=False, evidence_issues=["ISSUE_SENTINEL cited file does not exist"],
        )

        assert "ISSUE_SENTINEL" in _state(finding)

    def test_grounding_valid_flag_is_part_of_the_request(self):
        valid = _state(_candidate(evidence_valid=True))
        invalid = _state(_candidate(evidence_valid=False))

        assert valid != invalid

    def test_per_item_pr_grounding_is_part_of_the_request(self):
        grounded = _state(_candidate(evidence=[_item(grounded=True)]))
        ungrounded = _state(_candidate(evidence=[_item(grounded=False)]))

        assert grounded != ungrounded

    def test_semgrep_metadata_is_included_when_present(self):
        finding = _candidate(
            semgrep_rule_id="RULE_SENTINEL", semgrep_severity="SEV_SENTINEL",
            semgrep_message="MSG_SENTINEL",
        )

        state = _state(finding)

        assert all(s in state for s in ("RULE_SENTINEL", "SEV_SENTINEL", "MSG_SENTINEL"))

    def test_no_agent_verdict_or_confidence_reaches_the_request(self):
        finding = _candidate(verdict="AGENT_VERDICT_SENTINEL", provenance_confidence=0.8123)

        state = _state(finding)

        assert "AGENT_VERDICT_SENTINEL" not in state
        assert "0.8123" not in state

    def test_policy_item_is_included_without_reading_code(self):
        policy = EvidenceItem(type="policy", source="policy_sentinel.md", content="POLICY_TEXT")
        finding = _candidate(evidence=[policy])

        def read_code(item):
            raise AssertionError("policy items have no code location")

        assert "policy_sentinel.md" in _state(finding, read_code=read_code)


class TestJudgeRequestBound:
    def test_oversized_code_keeps_the_request_within_the_bound(self):
        finding = _candidate()

        state = _state(finding, read_code=lambda item: "X" * 100_000, max_chars=4_000)

        assert len(state) <= 4_000

    def test_claim_rationale_and_grounding_survive_oversized_code(self):
        finding = _candidate(
            cwe_id="CWE-ORACLE", evidence_valid=False, evidence_issues=["ISSUE_SENTINEL"],
            evidence=[_item(file=f"f{i}.py", grounded=False) for i in range(8)],
        )

        state = _state(finding, read_code=lambda item: "X" * 100_000, max_chars=4_000)

        assert "RATIONALE_SENTINEL" in state
        assert "CWE-ORACLE" in state
        assert "ISSUE_SENTINEL" in state

    def test_code_within_the_bound_is_not_dropped(self):
        assert "SMALL_CODE_SENTINEL" in _state(_candidate(), read_code=lambda item: "SMALL_CODE_SENTINEL")


class TestApplyJudgeAnswer:
    @pytest.mark.parametrize("verdict", sorted(VERDICTS))
    def test_valid_answer_is_recorded_as_the_candidate_verdict(self, verdict):
        finding = _candidate()

        apply_judge_answer(finding, {"verdict": verdict, "severity": "high", "provenance_confidence": 0.5})

        assert finding.verdict == verdict
        assert finding.judged is True

    @pytest.mark.parametrize("confidence", [0, 0.0, 0.37, 1, 1.0])
    def test_provenance_confidence_in_range_is_recorded_as_given(self, confidence):
        finding = _candidate()

        apply_judge_answer(finding, {"verdict": "possible", "severity": "low", "provenance_confidence": confidence})

        assert finding.provenance_confidence == confidence

    @pytest.mark.parametrize("severity", sorted(SEVERITIES))
    @pytest.mark.parametrize("verdict", ["vulnerable", "possible"])
    def test_severity_is_recorded_for_vulnerable_and_possible(self, verdict, severity):
        finding = _candidate()

        apply_judge_answer(finding, {"verdict": verdict, "severity": severity, "provenance_confidence": 0.5})

        assert finding.severity == severity

    def test_grounding_result_is_still_recorded_after_judging(self):
        finding = _candidate(
            evidence_valid=False, evidence_issues=["ISSUE_SENTINEL"],
            evidence=[_item(grounded=True), _item(file="b.py", grounded=False)],
        )

        apply_judge_answer(finding, {"verdict": "safe", "severity": "low", "provenance_confidence": 0.2})

        assert finding.evidence_valid is False
        assert finding.evidence_issues == ["ISSUE_SENTINEL"]
        assert [i.grounded_in_pr for i in finding.evidence] == [True, False]

    @pytest.mark.parametrize("verdict", ["safe", "insufficient_evidence"])
    @pytest.mark.parametrize("severity", sorted(SEVERITIES))
    def test_no_severity_is_recorded_for_safe_or_insufficient_evidence(self, verdict, severity):
        finding = _candidate()

        apply_judge_answer(finding, {"verdict": verdict, "severity": severity, "provenance_confidence": 0.6})

        assert finding.verdict == verdict
        assert not finding.severity
        assert finding.provenance_confidence == 0.6
        assert finding.judged is True


class TestPrGroundingCap:
    ANSWER = {"verdict": "vulnerable", "severity": "critical", "provenance_confidence": 0.9}

    def test_vulnerable_is_capped_to_possible_when_graph_was_down_and_nothing_is_grounded(self):
        finding = _candidate(
            pr_graph_ok=False, evidence=[_item(grounded=False), _item(file="b.py", grounded=False)],
        )

        apply_judge_answer(finding, self.ANSWER)

        assert finding.verdict == "possible"
        assert finding.judge_verdict == "vulnerable"
        assert finding.judged is True

    def test_capped_candidate_keeps_the_judge_severity_and_confidence(self):
        finding = _candidate(pr_graph_ok=False, evidence=[_item(grounded=False)])

        apply_judge_answer(finding, self.ANSWER)

        assert finding.severity == "critical"
        assert finding.provenance_confidence == 0.9

    def test_candidate_without_code_items_is_capped_when_graph_was_down(self):
        policy = EvidenceItem(type="policy", source="policy.md", content="rule")
        finding = _candidate(pr_graph_ok=False, evidence=[policy])

        apply_judge_answer(finding, self.ANSWER)

        assert finding.verdict == "possible"

    def test_one_pr_grounded_item_exempts_the_candidate_from_the_cap(self):
        finding = _candidate(
            pr_graph_ok=False, evidence=[_item(grounded=False), _item(file="b.py", grounded=True)],
        )

        apply_judge_answer(finding, self.ANSWER)

        assert finding.verdict == "vulnerable"
        assert finding.judge_verdict == "vulnerable"

    def test_healthy_graph_never_caps(self):
        finding = _candidate(pr_graph_ok=True, evidence=[_item(grounded=False)])

        apply_judge_answer(finding, self.ANSWER)

        assert finding.verdict == "vulnerable"
        assert finding.judge_verdict == "vulnerable"

    @pytest.mark.parametrize("verdict", sorted(VERDICTS))
    def test_judge_verdict_keeps_the_judge_answer_for_every_verdict(self, verdict):
        finding = _candidate(pr_graph_ok=False, evidence=[_item(grounded=False)])

        apply_judge_answer(finding, {**self.ANSWER, "verdict": verdict})

        assert finding.judge_verdict == verdict

    def test_invalid_answer_leaves_judge_verdict_empty(self):
        finding = _candidate()

        with pytest.raises(ValueError):
            apply_judge_answer(finding, {**self.ANSWER, "provenance_confidence": 1.5})

        assert not finding.judge_verdict

    @pytest.mark.parametrize("verdict", ["possible", "safe", "insufficient_evidence"])
    def test_cap_never_changes_a_verdict_other_than_vulnerable(self, verdict):
        finding = _candidate(pr_graph_ok=False, evidence=[_item(grounded=False)])

        apply_judge_answer(finding, {**self.ANSWER, "verdict": verdict})

        assert finding.verdict == verdict


KEV_REPLY = {
    "answers": {
        "verdict": {"choice": "vulnerable"},
        "severity": {"score": 2.0},
        "provenance_confidence": {"noul": 0.9},
    }
}
OVER_BOUND_PADDING = "x" * 20_000_000


class _Endpoint:
    """Loopback server on an ephemeral port that replies with a fixed status, headers and body."""

    def __init__(self, status=200, body=b"", headers=None):
        outer = self
        self.requests = 0

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.requests += 1
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(status)
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def endpoints():
    opened = []

    def make(**kwargs):
        endpoint = _Endpoint(**kwargs)
        opened.append(endpoint)
        return endpoint

    yield make
    for endpoint in opened:
        endpoint.close()


def _judge_via_config(endpoint_url) -> AgentFinding:
    finding = _candidate()
    judge_candidates([finding], lambda item: "CODE", LGTMConfig(judge_endpoint=endpoint_url, judge_timeout=5.0))
    return finding


def _assert_not_judged(finding):
    assert finding.judged is False
    assert not finding.verdict
    assert not finding.judge_verdict
    assert not finding.severity
    assert not finding.provenance_confidence


class TestJudgeEndpointIsLoopbackHttpOnly:
    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://127.0.0.1:8008",
            "http://example.com",
            "http://10.0.0.5:8008",
            "http://0.0.0.0:8008",
            "http://127.0.0.1.example.com:8008",
            "http://localhost.example.com:8008",
            "http://127.0.0.1@example.com:8008",
            "ftp://127.0.0.1:8008",
            "file:///etc/passwd",
            "127.0.0.1:8008",
            "",
        ],
    )
    def test_endpoint_that_is_not_http_to_loopback_opens_no_connection_and_leaves_candidate_not_judged(
        self, endpoint, monkeypatch
    ):
        attempts = []

        def refuse(*args, **kwargs):
            attempts.append(args)
            raise OSError("network blocked by test")

        monkeypatch.setattr(socket, "create_connection", refuse)
        monkeypatch.setattr(socket.socket, "connect", refuse)

        finding = _judge_via_config(endpoint)

        assert attempts == []
        _assert_not_judged(finding)

    def test_refused_endpoint_does_not_stop_the_other_candidates_from_completing(self):
        findings = [_candidate(finding_id="a"), _candidate(finding_id="b")]

        result = judge_candidates(
            findings, lambda item: "CODE", LGTMConfig(judge_endpoint="http://example.com", judge_timeout=5.0)
        )

        assert [f.finding_id for f in result] == ["a", "b"]
        assert all(not f.judged for f in result)

    def test_loopback_http_endpoint_is_judged(self, endpoints):
        endpoint = endpoints(body=json.dumps(KEV_REPLY).encode())

        finding = _judge_via_config(endpoint.url)

        assert finding.judged is True
        assert finding.verdict == "vulnerable"
        assert endpoint.requests == 1

    def test_redirect_is_not_followed_and_candidate_is_not_judged(self, endpoints):
        target = endpoints(body=json.dumps(KEV_REPLY).encode())
        redirector = endpoints(status=307, headers={"Location": target.url + "/v1/systemone"})

        finding = _judge_via_config(redirector.url)

        assert redirector.requests == 1
        assert target.requests == 0
        _assert_not_judged(finding)


class TestJudgeReplySizeBound:
    def test_reply_over_the_maximum_size_leaves_candidate_not_judged(self, endpoints):
        oversized = json.dumps({**KEV_REPLY, "padding": OVER_BOUND_PADDING}).encode()
        endpoint = endpoints(body=oversized)

        finding = _judge_via_config(endpoint.url)

        assert endpoint.requests == 1
        _assert_not_judged(finding)

    def test_normal_sized_reply_is_still_judged(self, endpoints):
        endpoint = endpoints(body=json.dumps(KEV_REPLY).encode())

        finding = _judge_via_config(endpoint.url)

        assert finding.judged is True


class _StubValidator:
    def __init__(self, *args, **kwargs):
        pass

    def validate_all(self, candidates):
        return candidates

    def read_cited_code(self, item):
        return "CODE_AT_LOCATION"


@pytest.fixture
def stub_validator(monkeypatch):
    import lgtm.validation as validation

    monkeypatch.setattr(validation, "EvidenceValidator", _StubValidator)


def _run_validation(candidates, judge):
    from lgtm.validation import validate_candidates

    return validate_candidates("repo", candidates, "main", "pr", [], LGTMConfig(), judge=judge)


def _failing_judge(request):
    raise ConnectionError("judge unreachable")


@pytest.mark.usefixtures("stub_validator")
class TestValidateCandidatesEntry:
    def test_successful_judge_returns_the_same_candidates_with_result_fields_filled(self):
        candidates = [_candidate(finding_id="a"), _candidate(finding_id="b")]
        answer = {"verdict": "vulnerable", "severity": "high", "provenance_confidence": 0.8}

        result = _run_validation(candidates, lambda request: answer)

        assert [c.finding_id for c in result] == ["a", "b"]
        for finding in result:
            assert finding.judged is True
            assert finding.verdict == "vulnerable"
            assert finding.severity == "high"
            assert finding.provenance_confidence == 0.8

    def test_failed_rejudge_clears_the_earlier_judge_result(self):
        candidate = _candidate()
        _run_validation(
            [candidate],
            lambda request: {"verdict": "vulnerable", "severity": "high", "provenance_confidence": 0.9},
        )
        assert candidate.judged is True

        result = _run_validation([candidate], _failing_judge)

        _assert_not_judged(result[0])

    def test_candidate_the_judge_failed_on_is_not_judged_and_others_still_are(self):
        good, bad = _candidate(finding_id="good"), _candidate(finding_id="bad")

        calls = iter([None, ConnectionError("down")])

        def judge_once_then_fail(request):
            outcome = next(calls)
            if outcome:
                raise outcome
            return {"verdict": "possible", "severity": "low", "provenance_confidence": 0.5}

        result = _run_validation([good, bad], judge_once_then_fail)

        assert result[0].judged is True
        _assert_not_judged(result[1])
