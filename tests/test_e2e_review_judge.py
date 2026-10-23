"""E2E: `lgtm review` end to end with the System One judge on a loopback fake, fake agent LLM, fake Semgrep and fake graph."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from lgtm.cli import main
from lgtm.sast.semgrep_runner import SemgrepFinding
from tests.test_graph_pipeline import (  # noqa: F401 - fixtures and scripted-agent helpers
    CLAIM_AUTHZ_A,
    CLAIM_AUTHZ_B,
    CLAIM_OVERSIZE_PAD,
    CLAIM_TRIAGE,
    KEV_ANSWERS,
    KEV_MODEL,
    REQUEST_BOUND,
    Reply,
    ScriptedLLM,
    _closed_loopback_port,
    _final,
    _findings,
    _base_evidence,
    _msg,
    _no_sections,
    _pr_evidence,
    _section_finding,
    _two_agent_llm,
    install_graph,
    isolated_git_config,
    repo,
    start_kev,
)
from tests.test_judge import QUESTION_IDS, _kev_payload

UNPARSABLE = "The change looks fine to me."
CLAIM_DROPPED = "DROPPED_CLAIM_SENTINEL"
ATTEMPTS = 4  # first attempt plus the three retries
BENCHMARK = Path(__file__).resolve().parent.parent / "benchmark"


@pytest.fixture(scope="module")
def judge_eval():
    spec = importlib.util.spec_from_file_location("e2e_judge_eval", BENCHMARK / "judge_eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["e2e_judge_eval"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def one_semgrep_hit(install_graph, monkeypatch):
    install_graph()

    def run(root, files, *args, **kwargs):
        if "a.py" not in files:
            return []
        return [SemgrepFinding(
            rule_id="fake.sqli", path="a.py", start_line=5, end_line=5,
            message="SQL built from user input", severity="ERROR", cwe=["CWE-89"],
            matched_code='cursor.execute(f"SELECT")',
        )]

    monkeypatch.setattr("lgtm.pipeline.run_semgrep", run)


def _review_cli(repo, tmp_path, monkeypatch, llm, endpoint, **config):
    config_file = tmp_path / "lgtm.json"
    config_file.write_text(json.dumps(config), encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr("lgtm.pipeline.build_llm", lambda cfg: llm)
    done = CliRunner().invoke(main, [
        "review", "--repo", str(repo), "--base", "main", "--pr", "pr",
        "--judge-endpoint", endpoint, "--judge-model", KEV_MODEL, "--judge-timeout", "2",
        "--config-file", str(config_file), "--output", str(out),
    ])
    report = json.loads(next(out.glob("*.json")).read_text(encoding="utf-8"))
    markdown = next(out.glob("*.md")).read_text(encoding="utf-8")
    return done, report, markdown


def _kev_reply(request: dict, supported: bool, confidence: float, variant: int = 0) -> Reply:
    return Reply(200, json.dumps(_kev_payload(
        request, supported=supported, confidence=confidence, variant=variant
    )).encode())


def _answer_by_claim(variant: int = 0):
    def respond(request: dict) -> Reply:
        claim = next(c for c in KEV_ANSWERS if c in request["state"])
        return _kev_reply(request, *KEV_ANSWERS[claim], variant=variant)

    return respond


def _by_claim(report: dict, claims) -> dict:
    return {c: f for f in report["findings"] for c in claims if c in f["explanation"]}


@pytest.mark.usefixtures("one_semgrep_hit")
def test_review_reports_candidates_from_both_agents_with_the_support_answer_and_their_own_severity(
    repo, tmp_path, monkeypatch, start_kev
):
    kev = start_kev(_answer_by_claim())

    done, report, markdown = _review_cli(repo, tmp_path, monkeypatch, _two_agent_llm(), kev.url)

    assert done.exit_code == 1, done.output  # a supported candidate signals CI
    assert len(kev.requests) == 3
    found = _by_claim(report, KEV_ANSWERS)
    assert set(found) == set(KEV_ANSWERS)
    assert {f["agent"] for f in found.values()} == {"authz_reviewer", "sast_triage"}
    for claim, (supported, confidence) in KEV_ANSWERS.items():
        f = found[claim]
        assert (f["supported"], f["judged"]) == (supported, True)
        assert not f.get("not_judged_reason")
        assert f["provenance_confidence"] == confidence
        assert not {"evidence_valid", "evidence_issues", "judge_verdict"} & set(f)
    assert report["review"]["agent_errors"] == []

    assert "NOT JUDGED" not in markdown.upper()
    assert "evidence_valid" not in markdown and "evidence_issues" not in markdown
    assert {"40", "90"} <= set(re.findall(r"\*\*Provenance confidence:\*\* (\d+)%", markdown))


@pytest.mark.usefixtures("one_semgrep_hit")
def test_review_completes_with_candidates_not_judged_and_the_unparsable_agent_error_listed_when_the_judge_is_unreachable(
    repo, tmp_path, monkeypatch
):
    llm = ScriptedLLM([
        *[_msg(UNPARSABLE) for _ in range(4)], _msg(_no_sections()),
        _msg(_findings(_section_finding(file="a.py", explanation=CLAIM_AUTHZ_A, evidence=[_pr_evidence()]))),
        _msg(_findings()),
        _msg(_findings(_section_finding(file="b.py", explanation=CLAIM_AUTHZ_B, evidence=[_base_evidence("b")]))),
    ])

    done, report, markdown = _review_cli(
        repo, tmp_path, monkeypatch, llm, f"http://127.0.0.1:{_closed_loopback_port()}",
        llm_retries=0, max_answer_reasks=0,
    )

    assert done.exit_code == 2, done.output  # nothing supported; candidates not judged and an agent errored
    found = _by_claim(report, (CLAIM_AUTHZ_A, CLAIM_AUTHZ_B))
    assert set(found) == {CLAIM_AUTHZ_A, CLAIM_AUTHZ_B}
    for f in found.values():
        assert (f["judged"], f.get("supported"), f.get("provenance_confidence")) == (False, None, None)
        assert f["not_judged_reason"]
        assert f["not_judged_reason"] in markdown
    assert [i["file"] for i in found[CLAIM_AUTHZ_A]["evidence"]] == ["a.py"]
    [error] = report["review"]["agent_errors"]
    assert error["source"] == "fake.sqli:a.py:5" and error["message"]

    assert "**Provenance confidence:**" not in markdown
    errors_section = markdown.partition("## Agent Errors")[2].partition("##")[0]
    assert "fake.sqli:a.py:5" in errors_section
    assert CLAIM_TRIAGE not in markdown


@pytest.mark.usefixtures("one_semgrep_hit")
def test_review_drops_unresolvable_references_without_an_agent_error_or_exit_code_change_and_never_sends_them_to_the_judge(
    repo, tmp_path, monkeypatch, start_kev
):
    kev = start_kev(lambda request: _kev_reply(request, False, 0.5))
    ghost_file = {**_pr_evidence(), "file": "ghost.py"}
    out_of_range = {**_pr_evidence(), "lines": [900, 901]}
    mixed = _msg(_findings(_section_finding(
        file="a.py", explanation=CLAIM_AUTHZ_A, evidence=[_pr_evidence(), out_of_range],
    )))
    unresolvable = _msg(_findings(_section_finding(
        file="a.py", explanation=CLAIM_DROPPED, evidence=[ghost_file],
    )))
    llm = ScriptedLLM([
        _msg(_final(explanation=CLAIM_TRIAGE, evidence=[_pr_evidence()])), _msg(_no_sections()),
        *[mixed] * ATTEMPTS,
        *[unresolvable] * ATTEMPTS,
        _msg(_findings(_section_finding(file="b.py", explanation=CLAIM_AUTHZ_B, evidence=[_base_evidence("b")]))),
    ])

    done, report, markdown = _review_cli(repo, tmp_path, monkeypatch, llm, kev.url)

    assert done.exit_code == 0, done.output  # nothing supported; the dropped candidate is not an anomaly
    assert report["review"]["agent_errors"] == []
    found = _by_claim(report, (CLAIM_TRIAGE, CLAIM_AUTHZ_A, CLAIM_AUTHZ_B, CLAIM_DROPPED))
    assert set(found) == {CLAIM_TRIAGE, CLAIM_AUTHZ_A, CLAIM_AUTHZ_B}
    assert len(report["findings"]) == 3
    assert all((f["judged"], f["supported"]) == (True, False) for f in found.values())
    assert [(i["file"], i["lines"]) for i in found[CLAIM_AUTHZ_A]["evidence"]] == [("a.py", [4, 4])]
    assert CLAIM_DROPPED not in markdown and "Agent Errors" not in markdown

    assert len(kev.requests) == 3
    sent = json.dumps([r.body for r in kev.requests])
    assert CLAIM_DROPPED not in sent and "ghost.py" not in sent


@pytest.mark.usefixtures("one_semgrep_hit")
def test_review_reports_the_oversize_candidate_as_request_too_large_and_the_benchmark_counts_it_per_reason(
    repo, tmp_path, monkeypatch, start_kev, judge_eval
):
    kev = start_kev(_answer_by_claim())
    oversize_claim = CLAIM_AUTHZ_A + CLAIM_OVERSIZE_PAD * (REQUEST_BOUND // len(CLAIM_OVERSIZE_PAD) + 100)

    done, report, markdown = _review_cli(
        repo, tmp_path, monkeypatch, _two_agent_llm(oversize_claim), kev.url
    )

    assert done.exit_code == 1, done.output  # the normal triage candidate is supported
    found = _by_claim(report, KEV_ANSWERS)
    assert set(found) == set(KEV_ANSWERS)
    large = found[CLAIM_AUTHZ_A]
    assert (large["judged"], large.get("supported")) == (False, None)
    assert large["not_judged_reason"] == "request-too-large"
    assert "request-too-large" in markdown
    for claim in (CLAIM_TRIAGE, CLAIM_AUTHZ_B):
        assert found[claim]["judged"] is True
        assert found[claim]["supported"] is KEV_ANSWERS[claim][0]
    assert len(kev.requests) == 2
    assert not any(CLAIM_OVERSIZE_PAD in json.dumps(r.body) for r in kev.requests)

    assert judge_eval.not_judged_by_reason(report["findings"]) == {"request-too-large": 1}


@pytest.mark.usefixtures("one_semgrep_hit")
def test_review_report_and_exit_code_do_not_change_with_kev_verdict_and_severity(
    repo, tmp_path, monkeypatch, start_kev
):
    outcomes = []
    for variant in (0, 1):
        kev = start_kev(_answer_by_claim(variant))
        workdir = tmp_path / f"variant{variant}"
        workdir.mkdir()

        done, report, markdown = _review_cli(repo, workdir, monkeypatch, _two_agent_llm(), kev.url)

        assert len(kev.requests) == 3
        assert all(set(r.body["questions"]) == QUESTION_IDS for r in kev.requests)
        found = _by_claim(report, KEV_ANSWERS)
        assert set(found) == set(KEV_ANSWERS)
        for f in found.values():
            assert not {"kev_verdict", "kev_severity", "input_tokens"} & set(f)
        outcomes.append((
            done.exit_code,
            {c: (f["supported"], f["judged"], f["provenance_confidence"], f.get("severity")) for c, f in found.items()},
            {c: set(f) for c, f in found.items()},
            sorted(re.findall(r"\*\*Provenance confidence:\*\* (\d+)%", markdown)),
        ))

    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == 1
    assert {c: v[:2] for c, v in outcomes[0][1].items()} == {
        c: (supported, True) for c, (supported, _) in KEV_ANSWERS.items()
    }
