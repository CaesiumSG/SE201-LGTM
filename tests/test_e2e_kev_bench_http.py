"""E2E: the standalone Kev benchmark against a fake Kev server on a loopback port."""

from __future__ import annotations

import copy
import functools
import importlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from lgtm.config import LGTMConfig
from lgtm.validation.judge import (
    QUESTION_CONFIDENCE,
    QUESTION_SEVERITY,
    QUESTION_SUPPORT,
    QUESTION_VERDICT,
    SYSTEM_ONE_PATH,
)

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

PERMUTE_PATH = SYSTEM_ONE_PATH + "/permute"
CHOICE_QUESTIONS = (QUESTION_SUPPORT, QUESTION_VERDICT, QUESTION_SEVERITY)
ARMS = ("few_shot", "zero_shot")
FAIL_MARK = "FAIL-THIS-CASE-MARK"
OVERSIZE = "x" * 30_000


def _probabilities(options) -> dict:
    return {option: round(0.5 / (i + 1), 4) for i, option in enumerate(options)}


class FakeKev(ThreadingHTTPServer):
    """Answers every choice question with its first option and distinct option scores."""

    def __init__(self, fail=None):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.fail = fail or (lambda path, raw: None)
        self.posts: list[tuple[str, str]] = []
        self.judge_replies: list[dict] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"])).decode()
        body = json.loads(raw)
        server = self.server
        server.posts.append((self.path, raw))
        mode = server.fail(self.path, raw)
        if mode == "http500":
            return self._send(500, b'{"detail": "boom"}')
        if mode == "malformed":
            return self._send(200, b'{"answers": {}}')
        if self.path == PERMUTE_PATH:
            options = list(body["request"]["questions"][body["question"]]["criteria"])
            runs = [
                {"order": options, "probabilities": _probabilities(options), "choice": options[0]}
                for _ in range(body["n_perm"])
            ]
            reply = {"runs": runs, "argmax_stable": True, "spread": {o: 0.0 for o in options}}
        else:
            answers = {
                q: {"type": "choice", "choice": next(iter(c)), "confidence": 0.5, "probabilities": _probabilities(c)}
                for q in CHOICE_QUESTIONS
                for c in [body["questions"][q]["criteria"]]
            }
            answers[QUESTION_CONFIDENCE] = {"type": "noul", "noul": 0.9}
            tokens = 9000 if not server.judge_replies else 1000
            reply = {"answers": answers, "usage": {"input_tokens": tokens, "output_tokens": 0}}
            server.judge_replies.append(reply)
        self._send(200, json.dumps(reply).encode())


@pytest.fixture
def kev_server():
    servers = []

    def start(fail=None) -> FakeKev:
        server = FakeKev(fail)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def run_bench(kev_server, monkeypatch, tmp_path):
    runner = importlib.import_module("kev_support.runner")
    controls = [f for f in importlib.import_module("kev_support.fixtures").load_fixtures() if f.kind == "control"][:3]

    def go(*, fail=None, edit=None):
        subset = [copy.deepcopy(f) for f in controls]
        if edit:
            edit(subset)
        server = kev_server(fail)
        monkeypatch.setattr(runner, "load_fixtures", lambda: subset)
        monkeypatch.setattr(runner, "LGTMConfig", functools.partial(LGTMConfig, judge_endpoint=server.url))
        out = tmp_path / "out"
        code = runner.main(["--out", str(out), "--work-dir", str(tmp_path / "work")])
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        return server, code, subset, {c["case_id"]: c for c in report["cases"]}

    return go


def test_both_arms_are_scored_over_http_with_raw_option_scores_recorded_and_exit_zero(run_bench):
    server, code, subset, cases = run_bench()

    assert code == 0
    judge_bodies = [raw for path, raw in server.posts if path == SYSTEM_ONE_PATH]
    assert len(judge_bodies) == len(subset) * 2
    assert all(len(few) > len(zero) for few, zero in zip(judge_bodies[0::2], judge_bodies[1::2]))
    for k, reply in enumerate(server.judge_replies):
        rec = cases[subset[k // 2].case_id]["arms"][ARMS[k % 2]]
        assert rec["status"] == "answered"
        for q in CHOICE_QUESTIONS:
            assert rec["scores"][q] == reply["answers"][q]["probabilities"]
            assert rec["answers"][q] == reply["answers"][q]["choice"]
        assert rec["noul"] == 0.9
        assert reply["usage"]["input_tokens"] in rec.values()
        assert set(rec["permute"]) == set(CHOICE_QUESTIONS)
        assert all(not rec["permute"][q].get("error") for q in CHOICE_QUESTIONS)


def test_oversized_request_is_recorded_as_too_large_never_sent_and_the_run_still_exits_zero(run_bench):
    def oversize(subset):
        subset[0].finding.explanation = OVERSIZE

    server, code, subset, cases = run_bench(edit=oversize)

    assert code == 0
    assert not any(OVERSIZE[:1000] in raw for _, raw in server.posts)
    for arm in ARMS:
        assert cases[subset[0].case_id]["arms"][arm]["status"] == "too_large"
        assert all(cases[f.case_id]["arms"][arm]["status"] == "answered" for f in subset[1:])


@pytest.mark.parametrize("mode", ["http500", "malformed"])
def test_failing_judge_call_marks_only_that_case_as_error_and_exits_nonzero(run_bench, mode):
    def mark(subset):
        subset[0].finding.explanation += " " + FAIL_MARK

    server, code, subset, cases = run_bench(
        fail=lambda path, raw: mode if path == SYSTEM_ONE_PATH and FAIL_MARK in raw else None, edit=mark
    )

    assert code != 0
    for arm in ARMS:
        bad = cases[subset[0].case_id]["arms"][arm]
        assert bad["status"] == "error" and bad["reason"]
        assert all(cases[f.case_id]["arms"][arm]["status"] == "answered" for f in subset[1:])


def test_failing_permute_call_is_recorded_for_its_question_and_exits_nonzero(run_bench):
    server, code, subset, cases = run_bench(fail=lambda path, raw: "http500" if path == PERMUTE_PATH else None)

    assert code != 0
    rec = cases[subset[0].case_id]["arms"]["few_shot"]
    assert rec["status"] == "answered"
    assert all(rec["permute"][q].get("error") for q in CHOICE_QUESTIONS)
