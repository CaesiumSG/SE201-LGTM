"""E2E: benchmark replay of a frozen candidate set through a fake Kev judge on a loopback port,
then the export and report commands of benchmark/README.md run as processes."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from lgtm.agents.base import AgentFinding, EvidenceItem
from lgtm.config import LGTMConfig
from lgtm.validation.judge import http_judge, judge_candidates

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
CASE_ID = "case_a"
BASE_APP = "line1\nbase2\nbase3\nline4\nline5\n"
PR_APP = "line1\npr2\npr3\nline4\nline5\n"

# claim -> (supported, confidence); None: HTTP 500
SCRIPT = {
    "claim supported": (True, 0.9),
    "claim unsupported": (False, 0.8),
    "claim also supported": (True, 0.6),
    "claim judge down": None,
}
LABELS = {"claim supported": "yes", "claim unsupported": "no", "claim also supported": "no"}


class _FakeKev(BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        answer = self.answer(request["state"])
        if answer is None:
            self.send_response(500)
            self.end_headers()
            return
        supported, confidence = answer
        answers = {}
        for qid, question in request["questions"].items():
            if question["type"] == "noul":
                answers[qid] = {"noul": confidence if supported else 1 - confidence}
            elif qid == "supported":
                answers[qid] = {"choice": "yes" if supported else "no", "confidence": confidence}
            elif qid == "verdict":
                answers[qid] = {"choice": "real" if supported else "not_real", "confidence": confidence}
            else:
                answers[qid] = {"choice": "high" if supported else "low", "confidence": confidence}
        tokens = 9000 if request["state"].startswith("Claim: claim supported\n") else 500
        body = json.dumps({"answers": answers, "usage": {"input_tokens": tokens}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def answer(self, state: str):
        return SCRIPT[state.splitlines()[0].removeprefix("Claim: ")]

    def log_message(self, *args):
        pass


class _GroundedKev(_FakeKev):
    """Supports only the original claim next to its original cited code."""

    def answer(self, state: str):
        grounded = state.startswith("Claim: claim supported\n") and "pr2\npr3" in state
        return (True, 0.9) if grounded else (False, 0.2)


def _serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def grounded_kev():
    yield from _serve(_GroundedKev)


@pytest.fixture
def fake_kev():
    server = HTTPServer(("127.0.0.1", 0), _FakeKev)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _isolated_git_config(tmp_path, monkeypatch):
    empty = tmp_path / "empty.gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args],
        cwd=repo, capture_output=True, text=True, check=True,
    )
    return done.stdout.strip()


def _case_repo(root: Path) -> dict:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text(BASE_APP, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "pr")
    (repo / "app.py").write_text(PR_APP, encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "pr")
    pr_sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    return {"repo": repo, "base_sha": base_sha, "pr_sha": pr_sha}


def _frozen_finding(claim: str) -> dict:
    return AgentFinding(
        finding_id=claim, explanation=claim, cwe_id="CWE-89", category="sqli", agent="authz",
        file="app.py", line=2, pr_graph_ok=True,
        evidence=[EvidenceItem(type="code", file="app.py", lines=[2, 3], snapshot="pr",
                               content="pr2\npr3", grounded_in_pr=True)],
    ).model_dump(exclude={"raw_response"})


def _write_run(run_dir: Path, case: dict, findings: list[dict]) -> None:
    run_dir.mkdir()
    record = {
        "id": CASE_ID, "base_sha": case["base_sha"], "pr_sha": case["pr_sha"],
        "mode": "lgtm", "category": "sqli", "expected": "vulnerable", "findings": findings,
    }
    (run_dir / f"{CASE_ID}.json").write_text(json.dumps(record), encoding="utf-8")


def _cli(script: str, *args: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BENCH / script), *map(str, args)],
        capture_output=True, text=True, timeout=60,
    )


def _export(run_dir: Path, case: dict, out: Path) -> list[str]:
    done = _cli("citation_export.py", run_dir, out, "--repo", f"{CASE_ID}={case['repo']}")
    assert done.returncode == 0, done.stderr
    return [u["unit_id"] for u in json.loads(out.read_text(encoding="utf-8"))["units"]]


def test_replay_reports_both_populations_over_the_same_unit_ids_from_one_export_and_labels_file(
    tmp_path, fake_kev
):
    case = _case_repo(tmp_path)
    frozen_dir = tmp_path / "frozen"
    _write_run(frozen_dir, case, [_frozen_finding(claim) for claim in SCRIPT])

    candidates = [AgentFinding.model_validate(f) for f in _frozen_findings(frozen_dir)]
    config = LGTMConfig(judge_endpoint=fake_kev, judge_timeout=5)
    judge_candidates(candidates, lambda item: item.content, config, http_judge(config))
    judged_dir = tmp_path / "judged"
    _write_run(judged_dir, case, [c.model_dump(exclude={"raw_response"}) for c in candidates])

    frozen_ids = _export(frozen_dir, case, tmp_path / "export.json")
    assert _export(judged_dir, case, tmp_path / "judged_export.json") == frozen_ids
    by_claim = dict(zip(SCRIPT, frozen_ids))
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"units": {
        by_claim[claim]: {"supports": label} for claim, label in LABELS.items()
    }}), encoding="utf-8")

    before = _cli("judge_eval.py", frozen_dir, tmp_path / "export.json", labels)
    after = _cli("judge_eval.py", judged_dir, tmp_path / "export.json", labels)

    assert before.returncode == 0 and after.returncode == 0, before.stderr + after.stderr
    before_report = json.loads(before.stdout)["citation_support"]
    after_report = json.loads(after.stdout)["citation_support"]
    assert after_report["before_judging"] == before_report["before_judging"]
    assert after_report["before_judging"]["n"] == 3
    assert after_report["before_judging"]["unlabelled"] == 1
    assert after_report["before_judging"]["percent_yes"] == pytest.approx(100 / 3)
    assert after_report["judged"] == {"n": 2, "unlabelled": 0, "percent_yes": 50.0}
    assert before_report["judged"]["n"] == 0


def test_replay_states_a_support_drop_for_each_of_the_three_perturbations(
    tmp_path, monkeypatch, grounded_kev
):
    case = _case_repo(tmp_path)
    repo = case["repo"]
    _git(repo, "branch", "rw/case_a/base", "main")
    _git(repo, "checkout", "-q", "-b", "rw/case_a/pr", "pr")
    (repo / "other.py").write_text("unrelated = 1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "unrelated code")
    _git(repo, "checkout", "-q", "main")

    spec = importlib.util.spec_from_file_location("e2e_judge_eval", BENCH / "judge_eval.py")
    judge_eval = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = judge_eval
    spec.loader.exec_module(judge_eval)
    real_tempdir = tempfile.TemporaryDirectory
    monkeypatch.setattr(
        judge_eval.tempfile, "TemporaryDirectory", lambda **kw: real_tempdir(**{**kw, "dir": tmp_path})
    )

    config = LGTMConfig(judge_endpoint=grounded_kev, judge_timeout=5)
    measured = judge_eval.perturb_case(
        {"id": CASE_ID, "construction": "synthetic-revert"},
        [AgentFinding.model_validate(_frozen_finding("claim supported"))],
        config, http_judge(config), repo=repo,
    )
    report = judge_eval.perturbation_report(measured)

    assert set(report) == {"unrelated_code", "mutated_claim", "safe_twin_code"}
    for name, row in report.items():
        assert (row["n"], row["skipped"], row["support_rate_drop"]) == (1, 0, 1.0), name
        assert row["confidence_drop"] > 0, name
        assert row["verdict_shift"] == {"real->not_real": 1}, name


def _frozen_findings(run_dir: Path) -> list[dict]:
    return json.loads((run_dir / f"{CASE_ID}.json").read_text(encoding="utf-8"))["findings"]


def test_replay_report_gives_kev_answers_over_judged_candidates_and_none_before_judging(
    tmp_path, fake_kev
):
    case = _case_repo(tmp_path)
    frozen_dir = tmp_path / "frozen"
    _write_run(frozen_dir, case, [_frozen_finding(claim) for claim in SCRIPT])

    candidates = [AgentFinding.model_validate(f) for f in _frozen_findings(frozen_dir)]
    config = LGTMConfig(judge_endpoint=fake_kev, judge_timeout=5)
    inner, tokens = http_judge(config), {}

    def judge(request):
        reply = inner(request)
        tokens[request["state"].splitlines()[0]] = reply["input_tokens"]
        return reply

    judge_candidates(candidates, lambda item: item.content, config, judge)
    judged_dir = tmp_path / "judged"
    _write_run(judged_dir, case, [
        {**c.model_dump(exclude={"raw_response"}), "kev_verdict": c.kev_verdict,
         "kev_severity": c.kev_severity, "input_tokens": tokens.get(f"Claim: {c.explanation}")}
        for c in candidates
    ])
    export = tmp_path / "export.json"
    _export(frozen_dir, case, export)
    _export(judged_dir, case, tmp_path / "judged_export.json")
    labels = tmp_path / "labels.json"
    labels.write_text(json.dumps({"units": {}}), encoding="utf-8")

    before = _cli("judge_eval.py", frozen_dir, export, labels)
    after = _cli("judge_eval.py", judged_dir, export, labels)

    assert before.returncode == 0 and after.returncode == 0, before.stderr + after.stderr
    before_report, after_report = json.loads(before.stdout), json.loads(after.stdout)
    kev = after_report["kev"]
    assert kev["judged"] == 3
    assert kev["verdicts"] == {"real": 2, "not_real": 1}
    assert kev["severities"] == {"high": 2, "low": 1}
    assert kev["not_judged"] == {"judge-failed": 1}
    assert kev["requests_over_8192_input_tokens"] == 1
    before_kev = before_report.get("kev", {})
    assert (before_kev.get("judged", 0), before_kev.get("verdicts", {}), before_kev.get("severities", {}),
            before_kev.get("requests_over_8192_input_tokens", 0)) == (0, {}, {}, 0)
    for key in ("citation_support", "confidence_agreement", "supported_agreement", "not_judged_by_reason"):
        assert key in after_report
