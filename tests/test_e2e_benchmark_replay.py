"""E2E: benchmark replay of a frozen candidate set through a fake Kev judge on a loopback port,
then the export and report commands of benchmark/README.md run as processes."""

from __future__ import annotations

import json
import subprocess
import sys
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
LABELS = {"claim supported": "correct", "claim unsupported": "incorrect", "claim also supported": "incorrect"}


class _FakeKev(BaseHTTPRequestHandler):
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        claim = request["state"].splitlines()[0].removeprefix("Claim: ")
        answer = SCRIPT[claim]
        if answer is None:
            self.send_response(500)
            self.end_headers()
            return
        supported, confidence = answer
        answers = {}
        for qid, question in request["questions"].items():
            if question["type"] == "noul":
                answers[qid] = {"noul": confidence if supported else 1 - confidence}
            else:
                want = "y" if supported else "n"
                label = next(n for n in question["criteria"] if n.lower().startswith(want))
                answers[qid] = {"choice": label, "confidence": confidence}
        body = json.dumps({"answers": answers}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        by_claim[claim]: {"citation": label} for claim, label in LABELS.items()
    }}), encoding="utf-8")

    before = _cli("judge_eval.py", frozen_dir, tmp_path / "export.json", labels)
    after = _cli("judge_eval.py", judged_dir, tmp_path / "export.json", labels)

    assert before.returncode == 0 and after.returncode == 0, before.stderr + after.stderr
    before_report = json.loads(before.stdout)["citation_correctness"]
    after_report = json.loads(after.stdout)["citation_correctness"]
    assert after_report["before_judging"] == before_report["before_judging"]
    assert after_report["before_judging"]["n"] == 3
    assert after_report["before_judging"]["unlabelled"] == 1
    assert after_report["before_judging"]["percent_correct"] == pytest.approx(100 / 3)
    assert after_report["judged"] == {"n": 2, "unlabelled": 0, "percent_correct": 50.0}
    assert before_report["judged"]["n"] == 0


def _frozen_findings(run_dir: Path) -> list[dict]:
    return json.loads((run_dir / f"{CASE_ID}.json").read_text(encoding="utf-8"))["findings"]
