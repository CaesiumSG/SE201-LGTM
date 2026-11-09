"""E2E: benchmark replay of a frozen candidate set through a fake Kev judge on a loopback port,
then summarized by evaluate and evaluate_real."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import threading
from types import SimpleNamespace
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


def _frozen_findings(run_dir: Path) -> list[dict]:
    return json.loads((run_dir / f"{CASE_ID}.json").read_text(encoding="utf-8"))["findings"]


def test_replay_of_one_recorded_run_gives_the_same_kev_summary_in_evaluate_and_evaluate_real(
    tmp_path, monkeypatch, fake_kev
):
    case = _case_repo(tmp_path)
    frozen_dir = tmp_path / "frozen"
    _write_run(frozen_dir, case, [_frozen_finding(claim) for claim in SCRIPT])
    spec = importlib.util.spec_from_file_location("e2e_evaluate_real", BENCH / "real_world" / "evaluate_real.py")
    evaluate_real = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = evaluate_real
    spec.loader.exec_module(evaluate_real)
    evaluate = evaluate_real.evaluate

    candidates = [AgentFinding.model_validate(f) for f in _frozen_findings(frozen_dir)]

    class Pipeline:
        def __init__(self, repo, config):
            self.config, self._judge = config, http_judge(config)

        def run(self, base, pr, output_dir=None):
            judge_candidates(candidates, lambda item: item.content, self.config, self._judge)
            meta = SimpleNamespace(
                semgrep_findings_in_diff=0, base_sha=case["base_sha"], pr_sha=case["pr_sha"]
            )
            return SimpleNamespace(findings=candidates, meta=meta)

    monkeypatch.setattr(evaluate_real, "get_pr_diff", lambda *a, **k: [])
    monkeypatch.setattr(evaluate_real, "ensure_index", lambda *a, **k: {"seconds": 0.0, "chunks": 0, "reused": True})
    monkeypatch.setattr(evaluate_real, "ReviewPipeline", Pipeline)
    unit = {"id": CASE_ID, "category": "sqli", "expected_verdict": "vulnerable",
            "repo_url": "https://github.com/o/p", "file": "app.py"}
    config = LGTMConfig(judge_endpoint=fake_kev, judge_timeout=5)

    record = evaluate_real.run_unit(unit, "lgtm", tmp_path, tmp_path, config)

    run_dir, real_dir = tmp_path / "run", tmp_path / "real"
    for directory in (run_dir, real_dir):
        directory.mkdir()
        (directory / f"{CASE_ID}.json").write_text(json.dumps(record, default=str), encoding="utf-8")
    saved_row = json.loads((run_dir / f"{CASE_ID}.json").read_text(encoding="utf-8"))
    saved = {f["explanation"]: f for f in saved_row["findings"]}
    for claim, answer in SCRIPT.items():
        if answer is None:
            assert saved[claim].get("kev_verdict") is None and saved[claim].get("input_tokens") is None
            continue
        assert saved[claim]["kev_verdict"] == ("real" if answer[0] else "not_real")
        assert saved[claim]["kev_severity"] == ("high" if answer[0] else "low")
        assert saved[claim]["input_tokens"] == (9000 if claim == "claim supported" else 500)

    bench_kev = evaluate.summarize([saved_row])["kev"]
    real_kev = evaluate_real.write_dir_summary(real_dir, "lgtm", {CASE_ID}, "m")["summary"]["kev"]

    expected = {
        "judged": 3, "verdicts": {"real": 2, "not_real": 1}, "severities": {"high": 2, "low": 1},
        "not_judged": {"judge-failed": 1}, "requests_over_8192_input_tokens": 1,
    }
    for kev in (bench_kev, real_kev):
        assert {k: kev[k] for k in expected} == expected
        # the fake judge answers 0.9 and 0.6 for the supported claims and 1 - 0.8 for the unsupported one
        assert kev["provenance_confidence_mean"] == pytest.approx((0.9 + 0.2 + 0.6) / 3)
