"""E2E: `lgtm review` with policy citations through the real git snapshots, citation gate, Kev HTTP client and report."""

from __future__ import annotations

import json

import pytest

from tests.test_e2e_review_judge import (  # noqa: F401 - fixtures
    ATTEMPTS,
    _by_claim,
    _kev_reply,
    _review_cli,
    one_semgrep_hit,
)
from tests.test_graph_pipeline import (  # noqa: F401 - fixtures and scripted-agent helpers
    CLAIM_AUTHZ_A,
    CLAIM_AUTHZ_B,
    CLAIM_TRIAGE,
    ScriptedLLM,
    _base_evidence,
    _final,
    _findings,
    _git,
    _msg,
    _no_sections,
    _pr_evidence,
    _section_finding,
    install_graph,
    isolated_git_config,
    repo,
    start_kev,
)

RULE = "Only admins may delete users."
INVENTED = "Users may delete only their own orders."
CLAIM_POLICY_ONLY = "POLICY_ONLY_CLAIM_SENTINEL"
GOOD_POLICY = {"type": "policy", "source": "security-policy.md", "content": RULE}
INVENTED_RULE = {**GOOD_POLICY, "content": INVENTED}
INVENTED_FILE = {**GOOD_POLICY, "source": "security_policy.md"}


@pytest.fixture
def policy_repo(repo):
    (repo / "security-policy.md").write_text(f"# Access\n\n{RULE}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "policy")
    return repo


def _script(*section_a_replies):
    return ScriptedLLM([
        _msg(_final(explanation=CLAIM_TRIAGE, evidence=[_pr_evidence()])), _msg(_no_sections()),
        *section_a_replies,
        _msg(_findings()),
        _msg(_findings(_section_finding(file="b.py", explanation=CLAIM_AUTHZ_B, evidence=[_base_evidence("b")]))),
    ])


def _section_a(explanation, *evidence):
    return _msg(_findings(_section_finding(file="a.py", explanation=explanation, evidence=list(evidence))))


def _sent(kev) -> str:
    return json.dumps([r.body for r in kev.requests])


def _prompts(llm) -> list[str]:
    return [str(messages) for messages in llm.seen]


@pytest.mark.usefixtures("one_semgrep_hit")
def test_invented_rule_is_reasked_and_kev_sees_only_the_corrected_policy(policy_repo, tmp_path, monkeypatch, start_kev):
    kev = start_kev(lambda request: _kev_reply(request, True, 0.9))
    llm = _script(
        _section_a(CLAIM_AUTHZ_A, _pr_evidence(), INVENTED_RULE),
        _section_a(CLAIM_AUTHZ_A, _pr_evidence(), GOOD_POLICY),
    )

    done, report, markdown = _review_cli(policy_repo, tmp_path, monkeypatch, llm, kev.url)

    assert done.exit_code == 1, done.output
    assert report["review"]["agent_errors"] == []
    assert sum("cited policy text not found" in p for p in _prompts(llm)) >= 1
    found = _by_claim(report, (CLAIM_AUTHZ_A,))[CLAIM_AUTHZ_A]
    assert found["judged"] is True and found["supported"] is True
    assert [i["content"] for i in found["evidence"] if i["type"] == "policy"] == [RULE]
    assert RULE in _sent(kev) and INVENTED not in _sent(kev)


@pytest.mark.usefixtures("one_semgrep_hit")
@pytest.mark.parametrize("bad", [INVENTED_RULE, INVENTED_FILE], ids=["invented rule", "invented file"])
def test_policy_never_corrected_does_not_reach_kev_and_code_still_decides(
    policy_repo, tmp_path, monkeypatch, start_kev, bad
):
    kev = start_kev(lambda request: _kev_reply(request, True, 0.9))
    llm = _script(*[_section_a(CLAIM_AUTHZ_A, _pr_evidence(), bad)] * ATTEMPTS)

    done, report, markdown = _review_cli(policy_repo, tmp_path, monkeypatch, llm, kev.url)

    assert report["review"]["agent_errors"] == []
    found = _by_claim(report, (CLAIM_AUTHZ_A,))[CLAIM_AUTHZ_A]
    assert found["judged"] is True
    assert [i["type"] for i in found["evidence"]] == ["code"]
    assert INVENTED not in _sent(kev) and "security_policy.md" not in _sent(kev)


@pytest.mark.usefixtures("one_semgrep_hit")
def test_candidate_citing_only_an_invented_rule_is_unsupported_without_a_kev_call(
    policy_repo, tmp_path, monkeypatch, start_kev
):
    kev = start_kev(lambda request: _kev_reply(request, True, 0.9))
    llm = _script(*[_section_a(CLAIM_POLICY_ONLY, INVENTED_RULE)] * ATTEMPTS)

    done, report, markdown = _review_cli(policy_repo, tmp_path, monkeypatch, llm, kev.url)

    assert report["review"]["agent_errors"] == []
    found = _by_claim(report, (CLAIM_POLICY_ONLY,))[CLAIM_POLICY_ONLY]
    assert (found["judged"], found["supported"]) == (True, False)
    assert CLAIM_POLICY_ONLY not in _sent(kev) and INVENTED not in _sent(kev)


@pytest.mark.usefixtures("one_semgrep_hit")
def test_valid_policy_citation_is_judged_without_a_reask(policy_repo, tmp_path, monkeypatch, start_kev):
    kev = start_kev(lambda request: _kev_reply(request, True, 0.9))
    llm = _script(_section_a(CLAIM_AUTHZ_A, _pr_evidence(), GOOD_POLICY))

    done, report, markdown = _review_cli(policy_repo, tmp_path, monkeypatch, llm, kev.url)

    assert done.exit_code == 1, done.output
    assert not any("cited policy" in p for p in _prompts(llm))
    assert len(kev.requests) == 3 and RULE in _sent(kev)
