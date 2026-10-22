"""E2E: `lgtm review` end to end with the System One judge on a loopback fake, fake agent LLM, fake Semgrep and fake graph."""

from __future__ import annotations

import json
import re

import pytest
from click.testing import CliRunner

from lgtm.cli import main
from lgtm.sast.semgrep_runner import SemgrepFinding
from tests.test_graph_pipeline import (  # noqa: F401 - fixtures and scripted-agent helpers
    CLAIM_AUTHZ_A,
    CLAIM_AUTHZ_B,
    CLAIM_TRIAGE,
    KEV_ANSWERS,
    KEV_MODEL,
    ScriptedLLM,
    _closed_loopback_port,
    _findings,
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

UNPARSABLE = "The change looks fine to me."


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


def _by_claim(report: dict, claims) -> dict:
    return {c: f for f in report["findings"] for c in claims if c in f["explanation"]}


@pytest.mark.usefixtures("one_semgrep_hit")
def test_review_reports_candidates_from_both_agents_judged_with_severity_only_on_vulnerable_or_possible(
    repo, tmp_path, monkeypatch, start_kev
):
    kev = start_kev()

    done, report, markdown = _review_cli(repo, tmp_path, monkeypatch, _two_agent_llm(), kev.url)

    assert done.exit_code == 1, done.output  # a vulnerable finding signals CI
    assert len(kev.requests) == 3
    found = _by_claim(report, KEV_ANSWERS)
    assert set(found) == set(KEV_ANSWERS)
    assert {f["agent"] for f in found.values()} == {"authz_reviewer", "sast_triage"}
    for claim, (verdict, severity, confidence) in KEV_ANSWERS.items():
        f = found[claim]
        assert (f["verdict"], f["provenance_confidence"], f["judged"]) == (verdict, confidence, True)
        assert f["severity"] == (severity if verdict in ("vulnerable", "possible") else "")
    assert report["stats"]["by_verdict"] == {"vulnerable": 1, "possible": 1, "safe": 1}
    assert report["stats"]["not_judged"] == 0
    assert report["review"]["agent_errors"] == []

    assert "[VULNERABLE]" in markdown and "[POSSIBLE]" in markdown and "[SAFE]" in markdown
    assert "NOT JUDGED" not in markdown
    assert re.findall(r"\*\*Severity:\*\* (\w+)", markdown) == ["high", "medium"]
    assert sorted(re.findall(r"\*\*Provenance confidence:\*\* (\d+)%", markdown)) == ["20", "40", "90"]


@pytest.mark.usefixtures("one_semgrep_hit")
def test_review_completes_with_candidates_not_judged_and_the_unparsable_agent_error_listed_when_the_judge_is_unreachable(
    repo, tmp_path, monkeypatch
):
    llm = ScriptedLLM([
        *[_msg(UNPARSABLE) for _ in range(4)], _msg(_no_sections()),
        _msg(_findings(_section_finding(file="a.py", explanation=CLAIM_AUTHZ_A, evidence=[_pr_evidence()]))),
        _msg(_findings()),
        _msg(_findings(_section_finding(file="b.py", explanation=CLAIM_AUTHZ_B))),
    ])

    done, report, markdown = _review_cli(
        repo, tmp_path, monkeypatch, llm, f"http://127.0.0.1:{_closed_loopback_port()}",
        llm_retries=0, max_answer_reasks=0,
    )

    assert done.exit_code == 0, done.output
    found = _by_claim(report, (CLAIM_AUTHZ_A, CLAIM_AUTHZ_B))
    assert set(found) == {CLAIM_AUTHZ_A, CLAIM_AUTHZ_B}
    for f in found.values():
        assert (f["judged"], f["verdict"], f["severity"], f["provenance_confidence"]) == (False, "", "", None)
    assert found[CLAIM_AUTHZ_A]["evidence_valid"] is True
    assert [i["file"] for i in found[CLAIM_AUTHZ_A]["evidence"]] == ["a.py"]
    assert report["stats"]["total_findings"] == 2 and report["stats"]["not_judged"] == 2
    assert report["stats"]["by_verdict"] == {}
    [error] = report["review"]["agent_errors"]
    assert error["source"] == "fake.sqli:a.py:5" and error["message"]

    assert markdown.count("[NOT JUDGED]") == 2
    assert "| not judged | 2 |" in markdown
    assert "**Severity:**" not in markdown and "**Provenance confidence:**" not in markdown
    errors_section = markdown.partition("## Agent Errors")[2].partition("##")[0]
    assert "fake.sqli:a.py:5" in errors_section
    assert CLAIM_TRIAGE not in markdown
