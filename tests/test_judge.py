"""Unit tests for the judge request builder and the application of a judge answer."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import lgtm.validation.judge as judge_module
from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.config import LGTMConfig
from lgtm.validation.judge import (
    RequestTooLarge,
    apply_judge_answer,
    build_judge_request,
    judge_candidates,
)

MAX_CHARS = 200_000
BOUND_CHARS = 28_000
REMOVED_FIELDS = ("evidence_valid", "evidence_issues", "judge_verdict")


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


QUESTION_IDS = {"supported", "verdict", "severity", "provenance_confidence"}
INPUT_TOKENS = 4321


def _severity_levels() -> tuple:
    return tuple(getattr(judge_module, "SEVERITY_LEVELS", ("medium", "high")))


def _choice_labels(qid: str) -> list:
    """Option labels the production request offers for a question; empty when it has none."""
    try:
        criteria = build_judge_request(
            _candidate(), lambda item: "", model="m", max_chars=MAX_CHARS
        )["questions"][qid].get("criteria") or []
    except Exception:  # noqa: BLE001 - request without the question; callers fall back to defaults
        return []
    return list(criteria)


def _answer(supported="yes", confidence=0.5, verdict=None, severity=None) -> dict:
    labels = _choice_labels("verdict")
    return {
        "supported": supported,
        "verdict": verdict if verdict is not None else (labels[0] if labels else "yes"),
        "severity": severity if severity is not None else _severity_levels()[0],
        "provenance_confidence": confidence,
        "input_tokens": INPUT_TOKENS,
    }


class TestRemovedFields:
    @pytest.mark.parametrize("name", REMOVED_FIELDS)
    def test_validator_flags_and_judge_verdict_no_longer_exist_on_a_finding(self, name):
        assert name not in AgentFinding.model_fields
        assert not hasattr(_candidate(), name)


class TestJudgeRequestContent:
    def test_request_names_the_model_and_keeps_the_yes_no_support_question_and_the_noul_confidence_question(self):
        request = _build(_candidate())

        assert request["model"] == "kev-test"
        questions = request["questions"]
        assert questions["supported"]["type"] == "choice"
        assert sorted(label.lower()[0] for label in questions["supported"]["criteria"]) == ["n", "y"]
        assert questions["provenance_confidence"]["type"] == "noul"

    def test_state_carries_claim_cwe_and_rationale(self):
        state = _state(_candidate(cwe_id="CWE-639"))

        assert "RATIONALE_SENTINEL" in state
        assert "CWE-639" in state

    def test_state_carries_category_and_location_of_the_finding(self):
        state = _state(_candidate(category="CATEGORY_SENTINEL", file="svc/orders.py", line=77))

        assert "CATEGORY_SENTINEL" in state
        assert "svc/orders.py" in state

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

    def test_pr_grounding_never_reaches_the_request(self):
        grounded = _state(_candidate(evidence=[_item(grounded=True)]))
        ungrounded = _state(_candidate(evidence=[_item(grounded=False)]))
        unknown = _state(_candidate(evidence=[_item(grounded=None)]))

        assert grounded == ungrounded == unknown

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

        state = _state(finding, read_code=read_code)

        assert "policy_sentinel.md" in state
        assert "POLICY_TEXT" in state


class TestApplyJudgeAnswer:
    @pytest.mark.parametrize("answer,expected", [("yes", True), ("no", False)])
    def test_valid_answer_is_recorded_as_supported_yes_or_no(self, answer, expected):
        finding = _candidate()

        apply_judge_answer(finding, _answer(answer, 0.5))

        assert finding.supported is expected
        assert finding.judged is True
        assert not finding.not_judged_reason

    @pytest.mark.parametrize("confidence", [0, 0.0, 0.37, 1, 1.0])
    def test_provenance_confidence_in_range_is_recorded_as_given(self, confidence):
        finding = _candidate()

        apply_judge_answer(finding, _answer("yes", confidence))

        assert finding.provenance_confidence == confidence

    @pytest.mark.parametrize("answer", ["yes", "no"])
    @pytest.mark.parametrize("severity", ["", "low", "high", "WARNING"])
    def test_candidate_severity_is_unchanged_by_the_answer(self, answer, severity):
        finding = _candidate(severity=severity)

        apply_judge_answer(finding, {**_answer(answer, 0.9), "severity": _severity_levels()[-1]})

        assert finding.severity == severity

    @pytest.mark.parametrize("graph_ok", [True, False, None])
    def test_unsupported_or_supported_is_never_capped_by_pr_grounding(self, graph_ok):
        finding = _candidate(pr_graph_ok=graph_ok, evidence=[_item(grounded=False)])

        apply_judge_answer(finding, _answer("yes", 0.9))

        assert finding.supported is True

    def test_grounded_in_pr_annotation_is_unchanged_after_judging(self):
        finding = _candidate(evidence=[_item(grounded=True), _item(file="b.py", grounded=False)])

        apply_judge_answer(finding, _answer("no", 0.2))

        assert [i.grounded_in_pr for i in finding.evidence] == [True, False]

    @pytest.mark.parametrize(
        "answer",
        [
            _answer("maybe", 0.5),
            _answer(None, 0.5),
            _answer(True, 0.5),
            _answer("yes", 1.5),
            _answer("yes", -0.1),
            _answer("yes", "0.5"),
            _answer("yes", True),
            _answer("yes", None),
            {"supported": "yes"},
            {"provenance_confidence": 0.5},
            {},
        ],
    )
    def test_invalid_answer_raises_and_changes_nothing(self, answer):
        finding = _candidate(severity="medium")

        with pytest.raises(ValueError):
            apply_judge_answer(finding, answer)

        assert finding.judged is False
        assert finding.supported is None
        assert finding.provenance_confidence is None
        assert finding.severity == "medium"


def _kev_answers(request: dict, supported=True, confidence=0.9, variant=0) -> dict:
    """Kev answers for every question of ``request``, shaped by each question's type.

    ``variant`` 0 picks the first option or lowest level, 1 the last option or highest level."""
    answers = {}
    for qid, question in request["questions"].items():
        kind = question["type"]
        if kind == "noul":
            value = confidence if qid == "provenance_confidence" else 0.2 + 0.6 * variant
            answers[qid] = {"type": "noul", "noul": value}
        elif kind == "score":
            answers[qid] = {"type": "score", "score": 0.5 + variant, "legend": list(question["criteria"]),
                            "probabilities": {}, "confidence": 0.5}
        else:
            labels = list(question["criteria"])
            if qid == "supported":
                label = next((n for n in labels if n.lower().startswith("y" if supported else "n")), labels[0])
            else:
                label = labels[-1 if variant else 0]
            answers[qid] = {"type": "choice", "choice": label, "confidence": 0.8,
                            "probabilities": {n: (0.9 if n == label else 0.1) for n in labels}}
    return answers


def _kev_payload(request: dict, *, input_tokens=INPUT_TOKENS, **kwargs) -> dict:
    return {
        "model": request["model"],
        "answers": _kev_answers(request, **kwargs),
        "usage": {"input_tokens": input_tokens, "output_tokens": 0},
        "latency_ms": 1,
    }


def _reply_for(request: dict, choice="yes", noul=0.9) -> bytes:
    return json.dumps(_kev_payload(request, supported=choice.startswith("y"), confidence=noul)).encode()


KEV_REPLY = _reply_for
OVER_BOUND_PADDING = "x" * 20_000_000


class _Endpoint:
    """Loopback server on an ephemeral port that replies with a fixed status, headers and body."""

    def __init__(self, status=200, body=b"", headers=None):
        outer = self
        self.requests = 0

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                outer.requests += 1
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                payload = body(json.loads(raw)) if callable(body) else body
                self.send_response(status)
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

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
    assert finding.supported is None
    assert finding.provenance_confidence is None
    assert finding.not_judged_reason


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
        endpoint = endpoints(body=KEV_REPLY)

        finding = _judge_via_config(endpoint.url)

        assert finding.judged is True
        assert finding.supported is True
        assert finding.provenance_confidence == 0.9
        assert endpoint.requests == 1

    def test_redirect_is_not_followed_and_candidate_is_not_judged(self, endpoints):
        target = endpoints(body=KEV_REPLY)
        redirector = endpoints(status=307, headers={"Location": target.url + "/v1/systemone"})

        finding = _judge_via_config(redirector.url)

        assert redirector.requests == 1
        assert target.requests == 0
        _assert_not_judged(finding)


class TestJudgeReplySizeBound:
    def test_reply_over_the_maximum_size_leaves_candidate_not_judged(self, endpoints):
        endpoint = endpoints(
            body=lambda request: json.dumps({**json.loads(_reply_for(request)), "padding": OVER_BOUND_PADDING}).encode()
        )

        finding = _judge_via_config(endpoint.url)

        assert endpoint.requests == 1
        _assert_not_judged(finding)

    def test_normal_sized_reply_is_still_judged(self, endpoints):
        endpoint = endpoints(body=KEV_REPLY)

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


def _recording_judge(answer=None):
    requests = []

    def judge(request):
        requests.append(request)
        return answer or _answer("yes", 0.8)

    judge.requests = requests
    return judge


def _judge(findings, read_code=lambda item: "CODE", judge=None):
    return judge_candidates(findings, read_code, LGTMConfig(), judge or _recording_judge())


@pytest.mark.usefixtures("stub_validator")
class TestValidateCandidatesEntry:
    def test_successful_judge_returns_the_same_candidates_with_result_fields_filled(self):
        candidates = [_candidate(finding_id="a"), _candidate(finding_id="b")]

        result = _run_validation(candidates, lambda request: _answer("yes", 0.8))

        assert [c.finding_id for c in result] == ["a", "b"]
        for finding in result:
            assert finding.judged is True
            assert finding.supported is True
            assert finding.provenance_confidence == 0.8
            assert not finding.not_judged_reason
            assert not finding.unsupported_reason

    def test_failed_rejudge_clears_the_earlier_judge_result(self):
        candidate = _candidate()
        _run_validation([candidate], lambda request: _answer("yes", 0.9))
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
            return _answer("no", 0.5)

        result = _run_validation([good, bad], judge_once_then_fail)

        assert result[0].judged is True and result[0].supported is False
        _assert_not_judged(result[1])


class TestJudgeFailureFallback:
    @pytest.mark.parametrize(
        "bad_answer",
        [_answer("maybe", 0.5), _answer("yes", 2), {"supported": "yes"}, {}],
    )
    def test_invalid_answer_leaves_candidate_not_judged_with_a_reason_and_keeps_its_severity(self, bad_answer):
        candidate = _candidate(severity="high")

        _judge([candidate], judge=lambda request: bad_answer)

        _assert_not_judged(candidate)
        assert candidate.severity == "high"
        assert candidate.not_judged_reason != "request-too-large"
        assert not candidate.unsupported_reason

    def test_judge_exception_leaves_candidate_not_judged_with_a_reason_distinct_from_request_too_large(self):
        candidate = _candidate()

        _judge([candidate], judge=_failing_judge)

        _assert_not_judged(candidate)
        assert candidate.not_judged_reason != "request-too-large"

    def test_judged_candidate_has_no_not_judged_reason(self):
        candidate = _candidate()

        _judge([candidate])

        assert candidate.judged is True
        assert not candidate.not_judged_reason


class TestRequestBound:
    def test_over_bound_request_is_never_sent_and_the_candidate_is_not_judged_with_request_too_large(self):
        candidate = _candidate()
        judge = _recording_judge()

        _judge([candidate], read_code=lambda item: "X" * (BOUND_CHARS * 2), judge=judge)

        assert judge.requests == []
        assert candidate.judged is False
        assert candidate.not_judged_reason == "request-too-large"
        assert candidate.supported is None
        assert candidate.provenance_confidence is None

    def test_over_bound_candidate_keeps_its_severity(self):
        candidate = _candidate(severity="medium")

        _judge([candidate], read_code=lambda item: "X" * (BOUND_CHARS * 2))

        assert candidate.severity == "medium"

    def test_other_candidates_are_still_judged_when_one_is_over_the_bound(self):
        big = _candidate(finding_id="big", evidence=[_item(file="big.py")])
        small = _candidate(finding_id="small", evidence=[_item(file="small.py")])
        judge = _recording_judge()

        def read_code(item):
            return "X" * (BOUND_CHARS * 2) if item.file == "big.py" else "ok"

        _judge([big, small], read_code=read_code, judge=judge)

        assert len(judge.requests) == 1
        assert big.not_judged_reason == "request-too-large"
        assert small.judged is True and small.supported is True

    def test_request_within_the_bound_is_sent_whole_without_truncation(self):
        candidate = _candidate()
        judge = _recording_judge()
        code = "HEAD_SENTINEL " + "y" * 12_000 + " TAIL_SENTINEL"

        _judge([candidate], read_code=lambda item: code, judge=judge)

        assert len(judge.requests) == 1
        assert code in judge.requests[0]["state"]
        assert candidate.judged is True

    def test_many_items_that_together_exceed_the_bound_are_not_judged_rather_than_trimmed(self):
        candidate = _candidate(evidence=[_item(file=f"f{i}.py") for i in range(6)])
        judge = _recording_judge()

        _judge([candidate], read_code=lambda item: "Z" * 10_000, judge=judge)

        assert judge.requests == []
        assert candidate.not_judged_reason == "request-too-large"


class TestNoCitedSource:
    def test_candidate_without_evidence_is_recorded_unsupported_without_a_judge_call(self):
        candidate = _candidate(evidence=[], severity="high")
        judge = _recording_judge()

        _judge([candidate], judge=judge)

        assert judge.requests == []
        assert candidate.unsupported_reason == "no-cited-source"
        assert candidate.supported is False
        assert candidate.judged is True
        assert candidate.provenance_confidence is None
        assert not candidate.not_judged_reason
        assert candidate.severity == "high"

    def test_stale_result_is_cleared_for_a_candidate_without_evidence(self):
        candidate = _candidate(evidence=[], supported=True, provenance_confidence=0.9)

        _judge([candidate])

        assert candidate.supported is False
        assert candidate.provenance_confidence is None

    def test_candidate_with_evidence_never_gets_an_unsupported_reason(self):
        candidate = _candidate()

        _judge([candidate], judge=_recording_judge(_answer("no", 0.7)))

        assert candidate.supported is False
        assert not candidate.unsupported_reason

    def test_candidate_without_evidence_does_not_stop_the_others_from_being_judged(self):
        empty, cited = _candidate(finding_id="empty", evidence=[]), _candidate(finding_id="cited")
        judge = _recording_judge()

        _judge([empty, cited], judge=judge)

        assert len(judge.requests) == 1
        assert cited.supported is True


class TestPolicyOnlyCandidate:
    def test_policy_only_candidate_is_judged_with_the_cited_policy_text_as_its_source(self):
        policy = EvidenceItem(type="policy", source="auth_policy.md", content="POLICY_TEXT_SENTINEL")
        candidate = _candidate(evidence=[policy])
        judge = _recording_judge(_answer("yes", 0.6))

        def read_code(item):
            raise AssertionError("policy items have no code location")

        _judge([candidate], read_code=read_code, judge=judge)

        assert len(judge.requests) == 1
        assert "POLICY_TEXT_SENTINEL" in judge.requests[0]["state"]
        assert candidate.judged is True
        assert candidate.supported is True
        assert not candidate.unsupported_reason


class TestUnreadableCitedItem:
    def test_unreadable_item_does_not_stop_other_candidates_from_being_judged(self):
        broken = _candidate(finding_id="broken", evidence=[_item(file="gone.py")])
        fine = _candidate(finding_id="fine")

        def read_code(item):
            if item.file == "gone.py":
                raise FileNotFoundError(item.file)
            return "CODE"

        _judge([broken, fine], read_code=read_code)

        assert fine.judged is True and fine.supported is True
        assert broken.judged != bool(broken.not_judged_reason)

    def test_readable_items_of_the_same_candidate_still_reach_the_judge(self):
        candidate = _candidate(evidence=[_item(file="gone.py"), _item(file="ok.py")])
        judge = _recording_judge()

        def read_code(item):
            if item.file == "gone.py":
                raise FileNotFoundError(item.file)
            return "READABLE_SENTINEL"

        _judge([candidate], read_code=read_code, judge=judge)

        assert len(judge.requests) == 1
        assert "READABLE_SENTINEL" in judge.requests[0]["state"]


class TestSeverityComesFromTheCandidate:
    @pytest.mark.parametrize("answer", ["yes", "no"])
    def test_semgrep_candidate_keeps_its_semgrep_severity_when_judged(self, answer):
        candidate = _candidate(
            agent="semgrep", semgrep_rule_id="rule.x", semgrep_severity="ERROR", severity="high",
        )

        _judge([candidate], judge=_recording_judge(_answer(answer, 0.7)))

        assert candidate.judged is True
        assert candidate.severity == "high"

    def test_authz_candidate_without_severity_gets_none_from_the_judge(self):
        candidate = _candidate(severity="")

        _judge([candidate], judge=lambda request: {**_answer("yes", 0.9), "severity": _severity_levels()[-1]})

        assert not candidate.severity


FORMATS = ("current", "short_claim", "code_first", "code_only")
NON_CURRENT = ("short_claim", "code_first", "code_only")
CLAIM_FORMATS = ("short_claim", "code_first")
UNAUTHORED_CWE = "CWE-99999"
CLAIM = "CLAIMSENT the query is built from user input"


def _request(finding, request_format, read_code=lambda item: "CODE_AT_LOCATION"):
    return build_judge_request(
        finding, read_code, model="kev-test", max_chars=MAX_CHARS, request_format=request_format
    )


def _without(text: str, *fragments: str) -> str:
    for fragment in fragments:
        text = text.replace(fragment, "")
    return text


def _questions_text(request) -> str:
    return json.dumps(request["questions"])


class TestRequestFormatSelection:
    def test_omitting_the_format_builds_the_base_commit_state_and_support_question(self):
        request = _build(_candidate())

        assert request["model"] == "kev-test"
        assert request["state"] == (
            "Claim: RATIONALE_SENTINEL query is built from user input\n"
            "CWE: CWE-89\n"
            "Category: sqli\n"
            "Location: app.py:10\n"
            "Cited item: app.py:10-12 at pr snapshot\n"
            "CODE_AT_LOCATION"
        )
        supported = request["questions"]["supported"]
        assert supported["type"] == "choice"
        assert supported["criteria"] == {
            "yes": "The cited code supports the claimed security flaw.",
            "no": "The cited code does not support the claimed security flaw.",
        }
        assert "Does the cited code support the claimed security flaw?" in supported["instructions"]
        assert request["questions"]["provenance_confidence"]["type"] == "noul"

    def test_current_format_by_name_equals_the_default_request(self):
        assert _request(_candidate(), "current") == _build(_candidate())

    def test_unknown_format_name_is_refused_naming_the_valid_formats(self):
        with pytest.raises(Exception) as excinfo:
            _request(_candidate(), "no_such_format")

        assert all(name in str(excinfo.value) for name in FORMATS)

    @pytest.mark.parametrize("request_format", NON_CURRENT)
    def test_every_format_keeps_the_question_ids_and_answer_labels_read_from_replies(self, request_format):
        other = _request(_candidate(), request_format)["questions"]

        assert {"supported", "provenance_confidence"} <= set(other)
        assert other["supported"]["type"] == "choice"
        assert set(other["supported"]["criteria"]) == {"yes", "no"}
        assert other["provenance_confidence"]["type"] == "noul"


class TestCodeBeforeClaim:
    @pytest.mark.parametrize("request_format", CLAIM_FORMATS)
    def test_cited_code_appears_before_the_claim_text(self, request_format):
        state = _request(_candidate(explanation=CLAIM), request_format)["state"]

        assert "CODE_AT_LOCATION" in state
        assert "CLAIMSENT" in state
        assert state.index("CODE_AT_LOCATION") < state.index("CLAIMSENT")

    def test_code_only_state_carries_the_cited_code(self):
        state = _request(_candidate(explanation=CLAIM), "code_only")["state"]

        assert "CODE_AT_LOCATION" in state


class TestCodeFirstAndShortClaim:
    @pytest.mark.parametrize("request_format", CLAIM_FORMATS)
    def test_question_and_options_do_not_state_the_flaw_exists(self, request_format):
        text = _questions_text(_request(_candidate(explanation=CLAIM), request_format))

        assert "CLAIMSENT" not in text
        assert "CWE-89" not in text
        assert "claimed" not in text.lower()

    @pytest.mark.parametrize("request_format", CLAIM_FORMATS)
    def test_state_carries_criteria_for_the_finding_cwe(self, request_format):
        authored = _request(_candidate(cwe_id="CWE-89"), request_format)["state"]
        unauthored = _request(_candidate(cwe_id=UNAUTHORED_CWE), request_format)["state"]

        authored_body = _without(authored, "CWE-89")
        unauthored_body = _without(unauthored, UNAUTHORED_CWE)
        assert len(authored_body) > len(unauthored_body)

    def test_short_claim_claim_fits_on_one_line(self):
        finding = _candidate(explanation="CLAIM_PART_A first\nCLAIM_PART_B second\nCLAIM_PART_C third")

        state = _request(finding, "short_claim")["state"]

        claim_lines = [ln for ln in state.splitlines() if "CLAIM_PART_" in ln]
        assert len(claim_lines) <= 1

    @pytest.mark.parametrize("request_format", CLAIM_FORMATS)
    def test_cwe_without_authored_criteria_builds_a_request_without_criteria_text(self, request_format):
        first = _request(_candidate(cwe_id=UNAUTHORED_CWE), request_format)
        second = _request(_candidate(cwe_id="CWE-88888"), request_format)

        assert _without(first["state"], UNAUTHORED_CWE) == _without(second["state"], "CWE-88888")
        assert "CODE_AT_LOCATION" in first["state"]
        assert first["model"] == "kev-test"


class TestCodeOnly:
    def test_request_carries_no_claim_cwe_category_or_criteria(self):
        finding = _candidate(
            explanation="CLAIMSENT injection flaw", cwe_id="CWE-89", category="CATEGORY_SENTINEL"
        )

        request = _request(finding, "code_only")
        text = (request["state"] + _questions_text(request)).lower()

        for forbidden in ("claimsent", "cwe-89", "category_sentinel", "injection"):
            assert forbidden not in text

    def test_request_does_not_vary_with_the_claim_cwe_or_category(self):
        authored = _candidate(explanation="CLAIM ONE", cwe_id="CWE-89", category="sqli")
        other = _candidate(explanation="CLAIM TWO", cwe_id=UNAUTHORED_CWE, category="other")

        assert _request(authored, "code_only") == _request(other, "code_only")


class TestEvidenceAcrossFormats:
    @pytest.mark.parametrize("request_format", ("current", "short_claim", "code_first"))
    def test_policy_text_is_passed_verbatim(self, request_format):
        policy = EvidenceItem(type="policy", source="docs/POLICY.md", content="POLICY_TEXT\n  indented  line\n")
        finding = _candidate(evidence=[_item(grounded=True), policy])

        state = _request(finding, request_format)["state"]

        assert "POLICY_TEXT\n  indented  line\n" in state
        assert "docs/POLICY.md" in state

    @pytest.mark.parametrize("request_format", FORMATS)
    def test_code_is_reread_from_the_repository_not_taken_from_the_agent_snippet(self, request_format):
        finding = _candidate(evidence=[_item(content="AGENT_SNIPPET_SENTINEL", grounded=True)])
        seen = []

        def read_code(item):
            seen.append((item.file, item.lines, item.snapshot))
            return "REAL_CODE_SENTINEL"

        state = _request(finding, request_format, read_code=read_code)["state"]

        assert "REAL_CODE_SENTINEL" in state
        assert "AGENT_SNIPPET_SENTINEL" not in state
        assert seen == [("app.py", [10, 12], "pr")]


class TestJudgingInEachFormat:
    @pytest.mark.parametrize("request_format", FORMATS)
    def test_rejecting_answer_yields_a_rejected_result(self, request_format):
        candidate = _candidate()

        judge_candidates(
            [candidate], lambda item: "CODE", LGTMConfig(), _recording_judge(_answer("no", 0.7)),
            request_format=request_format,
        )

        assert (candidate.judged, candidate.supported, candidate.provenance_confidence) == (True, False, 0.7)

    @pytest.mark.parametrize("request_format", FORMATS)
    def test_accepting_answer_yields_an_accepted_result(self, request_format):
        candidate = _candidate()

        judge_candidates(
            [candidate], lambda item: "CODE", LGTMConfig(), _recording_judge(_answer("yes", 0.9)),
            request_format=request_format,
        )

        assert (candidate.judged, candidate.supported, candidate.provenance_confidence) == (True, True, 0.9)

    @pytest.mark.parametrize("request_format", FORMATS)
    def test_judge_receives_the_request_built_in_that_format(self, request_format):
        judge = _recording_judge()

        judge_candidates(
            [_candidate()], lambda item: "CODE_AT_LOCATION", LGTMConfig(), judge, request_format=request_format
        )

        expected = _request(_candidate(), request_format)
        assert [r["state"] for r in judge.requests] == [expected["state"]]
        assert judge.requests[0]["questions"] == expected["questions"]

    def test_omitting_the_format_sends_the_current_request(self):
        judge = _recording_judge()

        judge_candidates([_candidate()], lambda item: "CODE_AT_LOCATION", LGTMConfig(), judge)

        assert [r["state"] for r in judge.requests] == [_request(_candidate(), "current")["state"]]

    def test_unknown_format_is_refused_naming_the_valid_formats_and_the_judge_is_not_called(self):
        candidate = _candidate()
        judge = _recording_judge()

        with pytest.raises(Exception) as excinfo:
            judge_candidates(
                [candidate], lambda item: "CODE", LGTMConfig(), judge, request_format="no_such_format"
            )

        assert all(name in str(excinfo.value) for name in FORMATS)
        assert judge.requests == []
        assert candidate.judged is False


def _instructions(request) -> dict:
    return {qid: q.get("instructions", "") for qid, q in request["questions"].items()}


def _size(request) -> int:
    return len(request["state"]) + sum(len(text) for text in _instructions(request).values())


def _arms(finding=None, read_code=lambda item: "CODE_AT_LOCATION"):
    finding = finding or _candidate()
    return tuple(
        build_judge_request(finding, read_code, model="kev-test", max_chars=MAX_CHARS, few_shot=few_shot)
        for few_shot in (True, False)
    )


def _examples_text(few: dict, zero: dict, qid: str) -> str:
    zero_text = zero["questions"][qid]["instructions"].strip()
    return few["questions"][qid]["instructions"].replace(zero_text, "", 1)


def _live_shaped(citations: int) -> tuple[AgentFinding, dict]:
    code = {
        f"f{i}.py": "\n".join(f"    value_{i}_{n} = lookup(request.args['k{n}'])  # line" for n in range(30))
        for i in range(citations)
    }
    finding = _candidate(
        explanation="The handler concatenates request input into a query:\n" + code["f0.py"][:600],
        evidence=[_item(file=name, lines=(1, 30), grounded=True) for name in code],
    )
    return finding, code


class TestProductionRequestAsksAllQuestions:
    def test_request_asks_supported_verdict_severity_and_provenance_confidence(self):
        request = _build(_candidate())

        assert set(request["questions"]) == QUESTION_IDS

    def test_request_is_json_and_every_question_has_instructions_and_a_kev_accepted_shape(self):
        request = json.loads(json.dumps(_build(_candidate())))

        assert isinstance(request["state"], str) and request["state"]
        for qid, question in request["questions"].items():
            assert question["type"] in {"choice", "noul", "score"}, qid
            assert question["instructions"].strip(), qid
            if question["type"] == "choice":
                assert 2 <= len(question["criteria"]) <= 255, qid
                assert all(isinstance(d, str) and d for d in question["criteria"].values()), qid
            if question["type"] == "score":
                assert 1 <= len(question["criteria"]) <= 255, qid

    def test_severity_question_offers_the_severity_levels_lowest_to_highest(self):
        levels = judge_module.SEVERITY_LEVELS
        severity = _build(_candidate())["questions"]["severity"]

        assert len(levels) >= 2 and all(isinstance(level, str) for level in levels)
        assert list(severity["criteria"]) == list(levels)

    def test_verdict_question_offers_at_least_two_answers_or_is_a_noul(self):
        verdict = _build(_candidate())["questions"]["verdict"]

        assert verdict["type"] == "noul" or len(verdict["criteria"]) >= 2

    def test_state_is_the_same_whatever_the_questions(self):
        few, zero = _arms()

        assert few["state"] == zero["state"] == _build(_candidate())["state"]


class TestFewShotExamples:
    @pytest.mark.parametrize("qid", sorted(QUESTION_IDS))
    def test_each_question_carries_examples_beyond_its_zero_shot_instructions(self, qid):
        few, zero = _arms()

        assert zero["questions"][qid]["instructions"].strip() in few["questions"][qid]["instructions"]
        assert _examples_text(few, zero, qid).strip()

    @pytest.mark.parametrize("qid", sorted(QUESTION_IDS))
    def test_each_question_holds_only_its_own_examples(self, qid):
        few, zero = _arms()
        own = {ln.strip() for ln in _examples_text(few, zero, qid).splitlines() if ln.strip()}
        others = {
            ln.strip()
            for other in QUESTION_IDS - {qid}
            for ln in _examples_text(few, zero, other).splitlines()
            if ln.strip()
        }

        assert own and not (own & others)

    @pytest.mark.parametrize("qid", ["supported", "verdict"])
    def test_choice_question_examples_show_a_correct_and_an_incorrect_answer(self, qid):
        few, zero = _arms()
        question = few["questions"][qid]
        if question["type"] != "choice":
            pytest.skip("question is not a choice question")
        shown = _examples_text(few, zero, qid).lower()

        assert sum(label.lower() in shown for label in question["criteria"]) >= 2

    def test_severity_examples_show_more_than_one_level(self):
        few, zero = _arms()
        shown = _examples_text(few, zero, "severity").lower()

        assert sum(level.lower() in shown for level in judge_module.SEVERITY_LEVELS) >= 2

    def test_provenance_examples_show_at_least_a_supporting_and_an_unsupporting_case(self):
        few, zero = _arms()
        lines = [ln for ln in _examples_text(few, zero, "provenance_confidence").splitlines() if ln.strip()]

        assert len(lines) >= 2

    def test_few_shot_is_the_default(self):
        assert _build(_candidate()) == _arms()[0]


class TestZeroShotDiffersOnlyByExamples:
    def test_both_arms_ask_the_same_questions_with_the_same_types_and_options(self):
        few, zero = _arms()

        assert few["model"] == zero["model"]
        assert set(few["questions"]) == set(zero["questions"]) == QUESTION_IDS
        for qid in QUESTION_IDS:
            assert {k: v for k, v in few["questions"][qid].items() if k != "instructions"} == {
                k: v for k, v in zero["questions"][qid].items() if k != "instructions"
            }

    def test_every_zero_shot_instruction_is_contained_in_the_few_shot_one_and_the_few_shot_request_is_larger(self):
        few, zero = _arms()

        assert _size(few) > _size(zero)
        for qid in QUESTION_IDS:
            zero_text = zero["questions"][qid]["instructions"].strip()
            assert zero_text
            assert zero_text in few["questions"][qid]["instructions"]

    def test_zero_shot_request_is_deterministic(self):
        assert _arms()[1] == _arms()[1]


class TestRequestSizeBound:
    @staticmethod
    def _base(few_shot):
        return _size(build_judge_request(
            _candidate(), lambda item: "x", model="m", max_chars=MAX_CHARS, few_shot=few_shot
        ))

    def test_production_request_totalling_exactly_the_bound_is_sent_and_one_character_more_is_not(self):
        base = self._base(True)
        assert base < BOUND_CHARS

        def run(total):
            candidate, judge = _candidate(), _recording_judge(_answer("yes", 0.5))
            _judge([candidate], read_code=lambda item: "x" * (1 + total - base), judge=judge)
            return candidate, judge

        at_bound, judge = run(BOUND_CHARS)
        assert [_size(r) for r in judge.requests] == [BOUND_CHARS]
        assert at_bound.judged is True and not at_bound.not_judged_reason

        over, judge = run(BOUND_CHARS + 1)
        assert judge.requests == []
        assert over.judged is False and over.not_judged_reason == "request-too-large"

    @pytest.mark.parametrize("few_shot", [True, False])
    def test_build_succeeds_at_the_bound_and_raises_request_too_large_one_character_over(self, few_shot):
        base = self._base(few_shot)

        def build(total):
            return build_judge_request(
                _candidate(), lambda item: "x" * (1 + total - base), model="m", max_chars=BOUND_CHARS,
                few_shot=few_shot,
            )

        assert _size(build(BOUND_CHARS)) == BOUND_CHARS
        with pytest.raises(RequestTooLarge):
            build(BOUND_CHARS + 1)

    def test_state_within_the_bound_is_refused_when_state_plus_instructions_exceed_it(self):
        state_len = len(_state(_candidate(), read_code=lambda item: "x"))
        pad = BOUND_CHARS - state_len
        candidate, judge = _candidate(), _recording_judge()

        _judge([candidate], read_code=lambda item: "x" * pad, judge=judge)

        assert state_len + pad <= BOUND_CHARS
        assert judge.requests == []
        assert candidate.judged is False and candidate.not_judged_reason == "request-too-large"

    def test_over_bound_request_is_not_sent_truncated(self):
        candidate, judge = _candidate(), _recording_judge()

        _judge([candidate], read_code=lambda item: "TAIL_SENTINEL".rjust(BOUND_CHARS + 500, "z"), judge=judge)

        assert judge.requests == []
        assert candidate.not_judged_reason == "request-too-large"

    @pytest.mark.parametrize("citations", [3, 4, 5])
    def test_live_shaped_finding_with_a_quoted_claim_fits_the_bound_with_examples(self, citations):
        finding, code = _live_shaped(citations)

        request = build_judge_request(
            finding, lambda item: code[item.file], model="kev-test", max_chars=BOUND_CHARS, few_shot=True
        )

        assert _size(request) <= BOUND_CHARS


class TestParseKevReply:
    @staticmethod
    def _reply(**kwargs) -> dict:
        return _kev_payload(_build(_candidate()), **kwargs)

    def test_reply_yields_supported_verdict_severity_and_provenance_confidence(self):
        request = _build(_candidate())
        reply = _kev_payload(request, supported=False, confidence=0.37, variant=1)

        parsed = judge_module.parse_kev_reply(reply)

        assert parsed["supported"] == "no"
        assert parsed["provenance_confidence"] == 0.37
        questions = request["questions"]
        if questions["verdict"]["type"] == "choice":
            assert parsed["verdict"] == list(questions["verdict"]["criteria"])[-1]
        else:
            assert parsed["verdict"] is not None
        if questions["severity"]["type"] == "choice":
            assert parsed["severity"] == judge_module.SEVERITY_LEVELS[-1]
        else:
            assert parsed["severity"] is not None

    def test_reply_yields_the_input_tokens_kev_reported(self):
        parsed = judge_module.parse_kev_reply(self._reply(input_tokens=7777))

        assert parsed["input_tokens"] == 7777

    @pytest.mark.parametrize("missing", sorted(QUESTION_IDS))
    def test_reply_missing_an_answer_is_refused_not_guessed(self, missing):
        reply = self._reply()
        del reply["answers"][missing]

        with pytest.raises(ValueError):
            judge_module.parse_kev_reply(reply)

    def test_reply_without_answers_is_refused(self):
        with pytest.raises(ValueError):
            judge_module.parse_kev_reply({"usage": {"input_tokens": 1}})

    @pytest.mark.parametrize("missing", ["verdict", "severity"])
    def test_candidate_whose_answer_lacks_verdict_or_severity_is_not_judged_as_judge_failed(self, missing):
        candidate = _candidate()
        reply = {k: v for k, v in _answer("yes", 0.8).items() if k != missing}

        _judge([candidate], judge=lambda request: reply)

        _assert_not_judged(candidate)
        assert candidate.not_judged_reason == "judge-failed"
        assert candidate.kev_verdict is None and candidate.kev_severity is None

    @pytest.mark.parametrize("missing", sorted(QUESTION_IDS))
    def test_http_reply_missing_an_answer_leaves_the_candidate_not_judged_as_judge_failed(
        self, endpoints, missing
    ):
        def body(request):
            payload = _kev_payload(request)
            del payload["answers"][missing]
            return json.dumps(payload).encode()

        finding = _judge_via_config(endpoints(body=body).url)

        _assert_not_judged(finding)
        assert finding.not_judged_reason == "judge-failed"
        assert finding.kev_verdict is None and finding.kev_severity is None


class TestHttpJudgeResult:
    def test_flat_mapping_carries_the_four_answers_and_kev_reported_input_tokens(self, endpoints):
        endpoint = endpoints(body=lambda request: json.dumps(_kev_payload(request, input_tokens=9100)).encode())
        config = LGTMConfig(judge_endpoint=endpoint.url, judge_timeout=5.0)

        result = judge_module.http_judge(config)(_build(_candidate()))

        assert QUESTION_IDS <= set(result)
        assert result["input_tokens"] == 9100
        assert result["supported"] == "yes"

    def test_judged_candidate_records_the_verdict_and_severity_kev_answered(self, endpoints):
        endpoint = endpoints(body=lambda request: json.dumps(_kev_payload(request, variant=1)).encode())

        finding = _judge_via_config(endpoint.url)

        assert finding.judged is True
        assert finding.kev_verdict is not None
        assert finding.kev_severity is not None


class TestKevFieldsOnTheFinding:
    def test_new_finding_has_no_kev_verdict_or_severity(self):
        finding = _candidate()

        assert finding.kev_verdict is None and finding.kev_severity is None

    def test_judged_answer_is_recorded_with_supported_and_provenance_confidence(self):
        finding = _candidate()
        severity = _severity_levels()[-1]
        answer = _answer("yes", 0.6, severity=severity)

        apply_judge_answer(finding, answer)

        assert (finding.supported, finding.provenance_confidence, finding.judged) == (True, 0.6, True)
        assert finding.kev_severity == severity
        assert finding.kev_verdict == answer["verdict"]

    @pytest.mark.parametrize("missing", ["verdict", "severity"])
    def test_answer_without_verdict_or_severity_raises_and_changes_nothing(self, missing):
        finding = _candidate()
        answer = {k: v for k, v in _answer("yes", 0.6).items() if k != missing}

        with pytest.raises(ValueError):
            apply_judge_answer(finding, answer)

        assert (finding.judged, finding.supported, finding.provenance_confidence) == (False, None, None)
        assert finding.kev_verdict is None and finding.kev_severity is None

    def test_failed_rejudge_clears_the_earlier_verdict_and_severity(self):
        finding = _candidate()
        _judge([finding])
        assert finding.kev_verdict is not None

        _judge([finding], judge=_failing_judge)

        assert finding.kev_verdict is None and finding.kev_severity is None

    def test_candidate_too_large_to_judge_has_no_verdict_or_severity(self):
        finding = _candidate(kev_verdict="stale", kev_severity="stale")

        _judge([finding], read_code=lambda item: "X" * (BOUND_CHARS * 2))

        assert finding.kev_verdict is None and finding.kev_severity is None

    def test_candidate_without_evidence_has_no_verdict_or_severity(self):
        finding = _candidate(evidence=[], kev_verdict="stale", kev_severity="stale")

        _judge([finding])

        assert finding.kev_verdict is None and finding.kev_severity is None
