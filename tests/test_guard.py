"""No-network, no-model guards for benchmark/guard.py: the held-out guard run
over the synthetic eval split and its flip report.

The evaluator subprocess, git and the endpoints are faked; results live under
pytest's tmp_path."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
LABELS = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))["cases"]
EVAL = [c for c in LABELS if c.get("split", "eval") == "eval"]
EVAL_IDS = [c["id"] for c in EVAL]
CATEGORY = {c["id"]: c["category"] for c in EVAL}
DEV_IDS = [c["id"] for c in LABELS if c.get("split", "eval") != "eval"]

# CT-guard-run-1 fixes the content of flips.json, not its key names.
FLIPS_FILE = "flips.json"
FLIPS, UNSCORED, REFERENCE, COMMIT = "flips", "unscored", "reference", "commit"
CASE_ID, CATEGORY_KEY, DIRECTION = "id", "category", "direction"
CORRECT_TO_WRONG = "correct_to_wrong"

LEAK = "SENTINEL-claim-/srv/secret/path.py"
EVAL_LABEL = "SENTINEL-case-label"
EVAL_ERROR = "SENTINEL-scan-error"


def _result(cid: str, behavior: str) -> dict:
    """Per-case JSON of the shape benchmark/evaluate.py score_case writes."""
    row = {"id": cid, "category": CATEGORY[cid], "mode": "lgtm", "pin": {"commit": "x"},
           "expected": "vulnerable", "trace": [],
           "findings": [{"category": CATEGORY[cid], "file": "/srv/secret/path.py",
                         "claim": LEAK, "judged": True, "kev_verdict": "real"}]}
    if behavior == "error":
        row.update(predicted="error", outcome="ERROR", correct=None,
                   error="boom", case_label="scan_failure")
    elif behavior == "wrong":
        row.update(predicted="safe", outcome="FN", correct=False)
    else:
        row.update(predicted="vulnerable", outcome="TP", correct=True)
    return row


class Env:
    def __init__(self, tmp_path, monkeypatch):
        self.monkeypatch = monkeypatch
        self.repo = tmp_path / "repo"
        self.root = tmp_path / "results-root"
        self.repo.mkdir()
        self.root.mkdir()
        self.commit = "c0ffee1"
        self.behavior: dict[str, str] = {}
        self.calls: list[list[str]] = []
        self.rc = 0
        monkeypatch.setattr(subprocess, "run", self._run)
        monkeypatch.setattr(subprocess, "check_output", self._check_output)
        monkeypatch.setattr(urllib.request, "urlopen", self._no_network)
        monkeypatch.setattr(socket, "create_connection", self._no_network)

    @staticmethod
    def _no_network(*a, **kw):
        raise AssertionError("guard reached the network")

    def _check_output(self, args, *a, **kw):
        return self._run(args, *a, **kw).stdout

    def _run(self, args, *a, **kw):
        args = [str(x) for x in args]
        if "evaluate.py" not in " ".join(args):
            return subprocess.CompletedProcess(args, 0, stdout=self.commit + "\n", stderr="")
        self.calls.append(args)
        out = Path(self._opts(args)["--output"][0])
        out.mkdir(parents=True, exist_ok=True)
        outcomes = {}
        for cid in EVAL_IDS:
            behavior = self.behavior.get(cid, "ok")
            if behavior == "missing":
                continue
            row = _result(cid, behavior)
            (out / f"{cid}.json").write_text(json.dumps(row), encoding="utf-8")
            outcomes[cid] = row["outcome"]
        (out / "summary.json").write_text(json.dumps(
            {"mode": "lgtm", "git_commit": self.commit, "outcomes": outcomes,
             "split": "eval", "cases_expected": len(EVAL_IDS)}), encoding="utf-8")
        self._console(kw, outcomes)
        return subprocess.CompletedProcess(args, self.rc, stdout="", stderr="")

    @staticmethod
    def _console(kw, outcomes):
        """Per-case lines evaluate.py prints; they reach the parent's file
        descriptors only when the caller leaves the stream inherited."""
        capture = kw.get("capture_output")
        out_inherited = not capture and kw.get("stdout") is None
        err_inherited = not capture and kw.get("stderr") is None
        if kw.get("stderr") == subprocess.STDOUT:
            err_inherited = out_inherited
        for cid, outcome in outcomes.items():
            line = f"{cid} {outcome} {EVAL_LABEL} (expected vulnerable, predicted safe, 1.2s)\n"
            if out_inherited:
                os.write(1, line.encode())
            if err_inherited:
                os.write(2, f"ERROR: {EVAL_ERROR} {cid}\n".encode())

    @staticmethod
    def _opts(args):
        opts: dict[str, list[str]] = {}
        key = None
        for a in args:
            if a.startswith("--"):
                key = a
                opts[key] = []
            elif key:
                opts[key].append(a)
        return opts

    def load(self):
        path = BENCH / "guard.py"
        if not path.is_file():
            pytest.fail("benchmark/guard.py does not exist")
        spec = importlib.util.spec_from_file_location("bench_guard", path)
        guard = importlib.util.module_from_spec(spec)
        sys.modules["bench_guard"] = guard
        spec.loader.exec_module(guard)
        self.monkeypatch.setattr(guard, "REPO_ROOT", self.repo, raising=False)
        return guard

    def run(self, capsys, root=None, **behavior):
        self.behavior = behavior
        guard = self.load()
        capsys.readouterr()
        rc = guard.main([str(self.root) if root is None else str(root)])
        out = capsys.readouterr()
        return SimpleNamespace(rc=rc, out=out.out, err=out.err)

    def flips_path(self, root=None):
        return (root or self.root) / "guard" / FLIPS_FILE

    def report(self, root=None):
        return json.loads(self.flips_path(root).read_text(encoding="utf-8"))

    def flipped(self, root=None):
        return {f[CASE_ID]: f for f in self.report(root)[FLIPS]}


@pytest.fixture
def env(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestGuardRun:
    def test_eval_split_has_the_expected_26_cases(self):
        assert len(EVAL_IDS) == 26

    # AC-US3-1, DEC-12, CON-4
    def test_guard_runs_evaluator_on_eval_split_in_lgtm_mode_with_the_gpu_model(self, env, capsys):
        env.run(capsys)
        assert len(env.calls) == 1
        opt = env._opts(env.calls[0])
        assert opt["--mode"] == ["lgtm"]
        assert opt["--split"] == ["eval"]
        assert opt["--gpu-model"] == ["qwen3.8-27b"]
        for flag in ("--cases", "--labels", "--rescore", "--model", "--ollama-url", "--gpu-cluster"):
            assert flag not in env.calls[0]

    # AC-US3-1
    def test_guard_results_stay_under_the_roots_guard_directory_and_leave_batches_alone(self, env, capsys):
        batch = env.root / "batch-1" / "lgtm"
        batch.mkdir(parents=True)
        (batch / "case.json").write_text("{}", encoding="utf-8")
        env.run(capsys)
        env.run(capsys)
        for call in env.calls:
            out = Path(env._opts(call)["--output"][0]).resolve()
            assert (env.root / "guard").resolve() in out.parents
        assert sorted(p.name for p in batch.parent.rglob("*") if p.is_file()) == ["case.json"]
        assert (batch / "case.json").read_text(encoding="utf-8") == "{}"
        assert env.flips_path().is_file()

    # AC-US3-1, DEC-14
    def test_reference_survives_across_sessions_on_the_same_root_only(self, env, capsys, tmp_path):
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        assert EVAL_IDS[0] in env.flipped()
        other = tmp_path / "other-root"
        other.mkdir()
        env.run(capsys, root=other, **{EVAL_IDS[0]: "wrong"})
        assert env.report(other)[REFERENCE] is True
        assert env.report(other)[FLIPS] == []

    # AC-US3-7, CON-3
    def test_guard_changes_no_label_case_definition_or_scoring_input(self, env, capsys):
        watched = [BENCH / "labels.json", BENCH / "real_world" / "cases.json", BENCH / "evaluate.py"]
        before = [_sha(p) for p in watched]
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        assert [_sha(p) for p in watched] == before
        assert not any(c in " ".join(env.calls[0]) for c in DEV_IDS[:3])


class TestFlipReport:
    # AC-US3-2
    def test_correct_to_wrong_case_is_listed_with_id_category_and_direction_only(self, env, capsys):
        env.run(capsys)
        flipped = {EVAL_IDS[0], EVAL_IDS[-1]}
        env.run(capsys, **{cid: "wrong" for cid in flipped})
        got = env.flipped()
        assert set(got) == flipped
        for cid, entry in got.items():
            assert set(entry) == {CASE_ID, CATEGORY_KEY, DIRECTION}
            assert entry[CATEGORY_KEY] == CATEGORY[cid]
            assert entry[DIRECTION] == CORRECT_TO_WRONG

    # AC-US3-2, CON-5
    def test_report_and_output_expose_nothing_else_about_the_eval_cases(self, env, capsys):
        env.run(capsys)
        res = env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        text = env.flips_path().read_text(encoding="utf-8")
        for secret in (LEAK, "/srv/secret", "findings", "kev_verdict", "FN", str(env.root)):
            assert secret not in text
            assert secret not in res.out + res.err
        assert not any(c in text for c in EVAL_IDS[1:])

    # AC-US3-2, CON-5: the evaluator's per-case console output is not forwarded
    def test_evaluator_per_case_console_output_does_not_reach_the_guards_output(self, env, capfd):
        env.run(capfd)
        res = env.run(capfd, **{EVAL_IDS[0]: "wrong", EVAL_IDS[1]: "error"})
        assert env.calls
        for text in (res.out, res.err):
            for leaked in (EVAL_LABEL, EVAL_ERROR, "expected vulnerable", "predicted", *EVAL_IDS):
                assert leaked not in text

    # AC-US3-3
    def test_wrong_to_correct_and_unchanged_cases_are_not_flips(self, env, capsys):
        env.run(capsys, **{cid: "wrong" for cid in EVAL_IDS[:3]})
        env.run(capsys, **{EVAL_IDS[0]: "wrong", EVAL_IDS[1]: "wrong"})
        assert env.report()[FLIPS] == []
        env.run(capsys, **{EVAL_IDS[0]: "wrong", EVAL_IDS[1]: "wrong", EVAL_IDS[5]: "wrong"})
        assert set(env.flipped()) == {EVAL_IDS[5]}

    # AC-US3-3
    def test_case_errored_in_the_current_run_is_unscored_and_not_a_flip(self, env, capsys):
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "error", EVAL_IDS[1]: "wrong"})
        report = env.report()
        assert set(env.flipped()) == {EVAL_IDS[1]}
        assert EVAL_IDS[0] in report[UNSCORED]
        assert EVAL_IDS[1] not in report[UNSCORED]

    # AC-US3-3
    def test_case_with_no_result_in_the_current_run_is_unscored(self, env, capsys):
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "missing"})
        assert EVAL_IDS[0] in env.report()[UNSCORED]
        assert EVAL_IDS[0] not in env.flipped()

    # AC-US3-3
    def test_no_case_is_unscored_when_every_case_is_scored(self, env, capsys):
        env.run(capsys)
        env.run(capsys)
        assert env.report()[UNSCORED] == []

    # AC-US3-3, AC-US3-6: result files left by the previous run do not score a missing case
    def test_results_left_by_the_previous_run_do_not_score_a_missing_case(self, env, capsys):
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "missing"})
        assert EVAL_IDS[0] in env.report()[UNSCORED]


class TestFirstRunAndReference:
    # AC-US3-4
    def test_first_run_reports_it_is_the_reference_and_lists_no_flips(self, env, capsys):
        res = env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        report = env.report()
        assert res.rc == 0
        assert report[REFERENCE] is True
        assert report[FLIPS] == []

    # AC-US3-4
    def test_later_run_is_not_a_reference(self, env, capsys):
        env.run(capsys)
        env.run(capsys)
        assert env.report()[REFERENCE] is False

    # AC-US3-6
    def test_each_complete_run_becomes_the_next_reference(self, env, capsys):
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        assert env.report()[FLIPS] == []
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        assert set(env.flipped()) == {EVAL_IDS[0]}

    # AC-US3-6
    def test_incomplete_run_does_not_replace_the_reference(self, env, capsys):
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "error"})
        env.run(capsys, **{EVAL_IDS[1]: "wrong"})
        assert set(env.flipped()) == {EVAL_IDS[1]}
        assert env.report()[REFERENCE] is False

    # AC-US3-6
    def test_incomplete_run_with_wrong_cases_does_not_hide_later_flips(self, env, capsys):
        env.run(capsys)
        env.run(capsys, **{EVAL_IDS[0]: "wrong", EVAL_IDS[1]: "error"})
        env.run(capsys, **{EVAL_IDS[0]: "wrong"})
        assert set(env.flipped()) == {EVAL_IDS[0]}

    # AC-US3-4, AC-US3-6
    def test_incomplete_first_run_is_not_a_reference(self, env, capsys):
        env.run(capsys, **{EVAL_IDS[0]: "error"})
        env.run(capsys, **{EVAL_IDS[1]: "wrong"})
        report = env.report()
        assert report[REFERENCE] is True
        assert report[FLIPS] == []

    # AC-US3-4, AC-US3-6: "reference" is reported only when a reference is stored
    def test_incomplete_run_with_no_stored_reference_is_not_reported_as_the_reference(self, env, capsys):
        for _ in range(2):
            res = env.run(capsys, **{EVAL_IDS[0]: "error"})
            assert env.report()[REFERENCE] is not True
            assert "reference run" not in res.out
            assert env.report()[FLIPS] == []
        env.run(capsys)
        assert env.report()[REFERENCE] is True

    # DEC-18
    def test_run_after_an_incomplete_run_starts_fresh_over_the_whole_split(self, env, capsys):
        env.run(capsys, **{EVAL_IDS[0]: "missing"})
        env.run(capsys)
        assert len(env.calls) == 2
        assert "--resume" not in env.calls[1]
        assert "--cases" not in env.calls[1]


class TestExitAndCommit:
    # AC-US3-5, DEC-5
    def test_zero_flips_is_stated_and_the_run_succeeds(self, env, capsys):
        env.run(capsys)
        res = env.run(capsys)
        assert res.rc == 0
        assert env.report()[FLIPS] == []
        assert env.report()[REFERENCE] is False

    # AC-US3-5, DEC-5
    def test_flips_still_complete_with_exit_zero(self, env, capsys):
        env.run(capsys)
        res = env.run(capsys, **{cid: "wrong" for cid in EVAL_IDS})
        assert res.rc == 0
        assert len(env.report()[FLIPS]) == len(EVAL_IDS)

    # AC-US3-5, DEC-5
    def test_incomplete_run_still_exits_zero(self, env, capsys):
        env.run(capsys)
        env.rc = 3
        res = env.run(capsys, **{EVAL_IDS[0]: "error", EVAL_IDS[1]: "wrong"})
        assert res.rc == 0
        assert env.flips_path().is_file()

    def test_evaluator_failure_is_reported_without_its_output(self, env, capsys):
        env.rc = 3
        res = env.run(capsys)
        assert res.rc == 0
        assert env.report()["evaluator_exit"] == 3
        assert "code 3" in res.err

    # AC-US3-6
    def test_report_names_the_commit_of_that_run(self, env, capsys):
        env.commit = "aaa1111"
        env.run(capsys)
        assert env.report()[COMMIT] == "aaa1111"
        env.commit = "bbb2222"
        env.run(capsys)
        assert env.report()[COMMIT] == "bbb2222"
