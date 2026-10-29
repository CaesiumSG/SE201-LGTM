"""No-network, no-model guards for benchmark/real_world/batch.py: batch
selection, resume, the control run, endpoint preflight and the bundle.

The evaluator subprocess, git and the reviewer endpoint are faked; results
live under pytest's tmp_path."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.config import LGTMConfig

RW = Path(__file__).resolve().parent.parent / "benchmark" / "real_world"
_spec = importlib.util.spec_from_file_location("rw_test_evaluate", RW.parent / "evaluate.py")
evaluate = importlib.util.module_from_spec(_spec)
sys.modules["rw_test_evaluate"] = evaluate
_spec.loader.exec_module(evaluate)
CASE_IDS = [c["id"] for c in json.loads((RW / "cases.json").read_text(encoding="utf-8"))["cases"]]
FIRST, SECOND = CASE_IDS[:6], CASE_IDS[6:]

# Bundle field names beyond batch/pass/commit are not fixed by CT-batch-run-1.
CASES, ID, LGTM_OK, CONTROL_OK, LGTM_PATH = "cases", "id", "lgtm_correct", "control_correct", "lgtm_result"
TOTALS, LGTM_TOTAL, CONTROL_TOTAL = "totals", "lgtm", "control"


def _lgtm_correct(cid: str) -> bool:
    return CASE_IDS.index(cid) % 3 != 0


def _control_correct(cid: str) -> bool:
    return CASE_IDS.index(cid) % 2 == 0


def _result(cid: str, mode: str, behavior: str = "ok") -> dict:
    correct = _lgtm_correct(cid) if mode == "lgtm" else _control_correct(cid)
    row = {"id": cid, "mode": mode, "pin": {"commit": "x"}, "trace": [],
           "findings": [{"judged": True, "kev_verdict": "real"}],
           "correct": correct, "outcome": "TP" if correct else "FN"}
    if behavior == "error":
        row.update(predicted="error", outcome="ERROR", correct=None, error="boom", findings=[])
    if behavior == "unjudged":
        row["findings"] = [{"judged": True, "kev_verdict": None}]
    if behavior == "uncited":
        row["findings"] = [{"judged": True, "kev_verdict": None,
                            "unsupported_reason": "no_cited_source"}]
    return row


class Env:
    def __init__(self, tmp_path, monkeypatch):
        self.monkeypatch = monkeypatch
        self.repo = tmp_path / "repo"
        self.root = self.repo / "results"
        self.repo.mkdir()
        self.commit = "c0ffee1"
        self.reachable = True
        self.behavior: dict[str, str] = {}
        self.control_behavior: dict[str, str] = {}
        self.control_rc = 0
        self.calls: list[list[str]] = []
        self.ran: list[tuple[str, str]] = []
        self.endpoints: list[str] = []
        monkeypatch.setattr(subprocess, "run", self._run)
        monkeypatch.setattr(subprocess, "check_output", self._check_output)
        monkeypatch.setattr(urllib.request, "urlopen", self._urlopen)

    def _urlopen(self, url, *a, **kw):
        self.endpoints.append(str(getattr(url, "full_url", url)))
        if not self.reachable:
            raise OSError("connection refused")
        return SimpleNamespace(read=lambda: b"{}", close=lambda: None,
                               __enter__=lambda s: s, __exit__=lambda *x: None)

    def _check_output(self, args, *a, **kw):
        return self._run(args, *a, **kw).stdout

    def _run(self, args, *a, **kw):
        args = [str(x) for x in args]
        if "evaluate_real" not in " ".join(args):
            return subprocess.CompletedProcess(args, 0, stdout=self.commit + "\n", stderr="")
        self.calls.append(args)
        opt = self._opts(args)
        out, mode = Path(opt["--output"][0]), opt["--modes"][0]
        for cid in opt.get("--cases", CASE_IDS):
            path = out / mode / f"{cid}.json"
            if "--resume" in args and evaluate.is_done(path):
                continue
            self.ran.append((mode, cid))
            behavior = (self.behavior if mode == "lgtm" else self.control_behavior).get(cid, "ok")
            if behavior == "missing":
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(_result(cid, mode, behavior)), encoding="utf-8")
        rc = self.control_rc if mode == "llm-only" else 0
        return subprocess.CompletedProcess(args, rc, stdout="", stderr="")

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

    def lgtm_calls(self):
        return [c for c in self.calls if self._opts(c)["--modes"] == ["lgtm"]]

    def control_calls(self):
        return [c for c in self.calls if self._opts(c)["--modes"] == ["llm-only"]]

    def reset(self):
        self.calls.clear()
        self.ran.clear()
        self.endpoints.clear()

    def ran_ids(self, mode):
        return [cid for m, cid in self.ran if m == mode]

    def load(self):
        path = RW / "batch.py"
        if not path.is_file():
            pytest.fail("benchmark/real_world/batch.py does not exist")
        spec = importlib.util.spec_from_file_location("rw_batch", path)
        batch = importlib.util.module_from_spec(spec)
        sys.modules["rw_batch"] = batch
        spec.loader.exec_module(batch)
        self.monkeypatch.setattr(batch, "REPO_ROOT", self.repo, raising=False)
        return batch

    def run(self, capsys, root=None):
        batch = self.load()
        capsys.readouterr()
        rc = batch.main([str(self.root) if root is None else root])
        out = capsys.readouterr()
        return SimpleNamespace(rc=rc, out=out.out, err=out.err,
                               last=(out.out.strip().splitlines() or [""])[-1])

    def bundle(self, n):
        return json.loads((self.root / f"batch-{n}" / "bundle.json").read_text(encoding="utf-8"))

    def bundles(self):
        return sorted(self.root.glob("**/bundle.json")) if self.root.exists() else []


@pytest.fixture
def env(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch)


def _finish(env, capsys, n):
    for _ in range(n):
        assert env.run(capsys).rc == 0


class TestBatchSelection:
    # AC-US2-1
    @pytest.mark.parametrize("session, ids, pass_no", [
        (1, FIRST, 1), (2, SECOND, 1), (3, FIRST, 2), (4, SECOND, 2)])
    def test_batches_follow_cases_json_order_and_repeat_as_second_pass(
            self, env, capsys, session, ids, pass_no):
        _finish(env, capsys, session - 1)
        env.reset()
        assert env.run(capsys).rc == 0
        assert sorted(env.ran_ids("lgtm")) == sorted(ids)
        assert env.bundle(session)["pass"] == pass_no
        assert env.bundle(session)["batch"] == session

    def test_each_batch_holds_three_vulnerable_safe_pairs(self):
        for ids in (FIRST, SECOND):
            assert sum(i.endswith("_vulnerable") for i in ids) == 3
            assert sum(i.endswith("_safe") for i in ids) == 3

    # AC-US2-2, DEC-12
    def test_batch_invokes_evaluator_in_lgtm_mode_only_into_its_batch_directory(self, env, capsys):
        assert env.run(capsys).rc == 0
        calls = env.lgtm_calls()
        assert len(calls) >= 1
        for call in calls:
            opt = env._opts(call)
            assert opt["--modes"] == ["lgtm"]
            assert Path(opt["--output"][0]) == env.root / "batch-1"
            assert not any(w in a.lower() for a in call for w in ("variant", "policy", "judge"))
        assert not (env.root / "batch-1" / "llm-only").exists()
        assert (env.root / "batch-1" / "lgtm").is_dir()


class TestResume:
    # AC-US2-3
    def test_next_session_starts_at_next_batch_without_rerunning_finished_cases(self, env, capsys):
        _finish(env, capsys, 1)
        env.reset()
        before = {p: p.read_bytes() for p in (env.root / "batch-1").glob("**/*.json")}
        assert env.run(capsys).rc == 0
        assert sorted(env.ran_ids("lgtm")) == sorted(SECOND)
        assert {p: p.read_bytes() for p in before} == before

    def test_third_session_does_not_overwrite_batches_one_and_two(self, env, capsys):
        _finish(env, capsys, 2)
        env.reset()
        before = {p: p.read_bytes() for b in (1, 2) for p in (env.root / f"batch-{b}").glob("**/*.json")}
        assert env.run(capsys).rc == 0
        assert {p: p.read_bytes() for p in before} == before
        assert (env.root / "batch-3" / "bundle.json").is_file()

    # AC-US2-4
    @pytest.mark.parametrize("behavior", ["missing", "error", "unjudged"])
    def test_batch_with_an_unfinished_unit_writes_no_bundle_and_next_session_reruns_only_it(
            self, env, capsys, behavior):
        victim = FIRST[2]
        env.behavior[victim] = behavior
        res = env.run(capsys)
        assert res.rc != 0
        assert victim in res.out + res.err
        assert env.bundles() == []
        env.behavior.clear()
        env.reset()
        res = env.run(capsys)
        assert res.rc == 0
        assert env.ran_ids("lgtm") == [victim]
        assert env.bundle(1)["batch"] == 1
        assert not (env.root / "batch-2").exists()

    def test_finding_without_cited_evidence_counts_as_finished(self, env, capsys):
        env.behavior[FIRST[2]] = "uncited"
        res = env.run(capsys)
        assert res.rc == 0
        assert len(env.bundles()) == 1

    def test_session_stopping_early_leaves_batch_unfinished(self, env, capsys):
        for cid in FIRST[3:]:
            env.behavior[cid] = "missing"
        env.run(capsys)
        assert env.bundles() == []
        env.behavior.clear()
        env.reset()
        env.run(capsys)
        assert sorted(env.ran_ids("lgtm")) == sorted(FIRST[3:])
        assert len(env.bundles()) == 1

    # AC-US2-5
    def test_errored_case_does_not_stop_remaining_cases_and_is_named(self, env, capsys):
        victim = FIRST[1]
        env.behavior[victim] = "error"
        res = env.run(capsys)
        assert sorted(env.ran_ids("lgtm")) == sorted(FIRST)
        assert victim in res.out + res.err
        assert env.bundles() == []
        assert not (env.root / "batch-2").exists()

    def test_errored_batch_is_not_marked_run_and_bundle_appears_after_completion(self, env, capsys):
        env.behavior[FIRST[0]] = "error"
        env.run(capsys)
        env.behavior.clear()
        env.reset()
        res = env.run(capsys)
        assert env.ran_ids("lgtm") == [FIRST[0]]
        assert Path(res.last).resolve() == (env.root / "batch-1" / "bundle.json").resolve()


class TestEndpointPreflight:
    # AC-US2-6
    def test_unreachable_endpoint_stops_before_any_unit_and_names_endpoint(self, env, capsys):
        env.reachable = False
        res = env.run(capsys)
        assert res.rc != 0
        assert env.calls == []
        assert env.endpoints == [LGTMConfig().ollama_base_url]
        assert LGTMConfig().ollama_base_url in res.out + res.err
        assert env.bundles() == []

    def test_batch_is_not_marked_run_after_unreachable_endpoint(self, env, capsys):
        env.reachable = False
        env.run(capsys)
        env.reachable = True
        env.reset()
        assert env.run(capsys).rc == 0
        assert env.endpoints[-1] == LGTMConfig().ollama_base_url
        assert sorted(env.ran_ids("lgtm")) == sorted(FIRST)
        assert (env.root / "batch-1" / "bundle.json").is_file()

    def test_unjudged_findings_never_finish_a_batch(self, env, capsys):
        for cid in FIRST:
            env.behavior[cid] = "unjudged"
        env.run(capsys)
        assert env.bundles() == []
        env.behavior.clear()
        env.reset()
        env.run(capsys)
        assert sorted(env.ran_ids("lgtm")) == sorted(FIRST)


class TestBundle:
    # AC-US2-7
    def test_finished_batch_leaves_exactly_one_bundle_with_ids_and_commit(self, env, capsys):
        env.commit = "abc1234"
        env.run(capsys)
        assert [p.relative_to(env.root) for p in env.bundles()] == [Path("batch-1/bundle.json")]
        bundle = env.bundle(1)
        assert bundle["commit"] == "abc1234"
        assert sorted(c[ID] for c in bundle[CASES]) == sorted(FIRST)

    def test_last_stdout_line_is_the_bundle_path(self, env, capsys):
        res = env.run(capsys)
        assert Path(res.last).resolve() == (env.root / "batch-1" / "bundle.json").resolve()

    # AC-US2-8
    def test_bundle_states_per_case_correctness_and_totals_for_lgtm_and_control(self, env, capsys):
        env.run(capsys)
        bundle = env.bundle(1)
        by_id = {c[ID]: c for c in bundle[CASES]}
        for cid in FIRST:
            assert by_id[cid][LGTM_OK] is _lgtm_correct(cid)
            assert by_id[cid][CONTROL_OK] is _control_correct(cid)
        assert bundle[TOTALS][LGTM_TOTAL] == sum(_lgtm_correct(c) for c in FIRST)
        assert bundle[TOTALS][CONTROL_TOTAL] == sum(_control_correct(c) for c in FIRST)

    # AC-US2-9
    def test_commit_change_between_batches_is_accepted_and_each_bundle_names_its_own(self, env, capsys):
        env.commit = "1111111"
        env.run(capsys)
        env.commit = "2222222"
        env.reset()
        res = env.run(capsys)
        assert res.rc == 0
        assert sorted(env.ran_ids("lgtm")) == sorted(SECOND)
        assert env.bundle(1)["commit"] == "1111111"
        assert env.bundle(2)["commit"] == "2222222"

    # AC-US2-10
    def test_every_cited_case_record_opens_from_the_repository_root(self, env, capsys):
        env.run(capsys)
        cited = [c[LGTM_PATH] for c in env.bundle(1)[CASES]]
        assert len(cited) == 6
        for rel in cited:
            assert not Path(rel).is_absolute()
            record = json.loads((env.repo / rel).read_text(encoding="utf-8"))
            assert record["mode"] == "lgtm"
            assert "trace" in record
        assert sorted(Path(r).stem for r in cited) == sorted(FIRST)
        assert {Path(r).parent.as_posix() for r in cited} == {"results/batch-1/lgtm"}


class TestNoBatchRemaining:
    # AC-US2-11
    def test_after_four_batches_nothing_runs_says_so_and_exits_zero(self, env, capsys):
        _finish(env, capsys, 4)
        env.reset()
        res = env.run(capsys)
        assert res.rc == 0
        assert env.calls == []
        assert env.endpoints == []
        assert res.out.strip()
        assert not (env.root / "batch-5").exists()
        assert len(env.bundles()) == 4


class TestControl:
    # AC-US2-13, AC-US2-2
    def test_control_runs_once_for_cases_lacking_a_stored_result_and_stores_it_under_control(self, env, capsys):
        env.run(capsys)
        assert sorted(env.ran_ids("llm-only")) == sorted(FIRST)
        for cid in FIRST:
            assert (env.root / "control" / "llm-only" / f"{cid}.json").is_file()
        for call in env.control_calls():
            assert Path(env._opts(call)["--output"][0]) == env.root / "control"

    def test_stored_control_results_are_reused_and_left_unmodified(self, env, capsys):
        stored = env.root / "control" / "llm-only"
        stored.mkdir(parents=True)
        sentinel = {}
        for cid in FIRST[:2]:
            sentinel[cid] = json.dumps(_result(cid, "llm-only")).encode() + b"  "
            (stored / f"{cid}.json").write_bytes(sentinel[cid])
        env.run(capsys)
        assert sorted(env.ran_ids("llm-only")) == sorted(FIRST[2:])
        for cid, data in sentinel.items():
            assert (stored / f"{cid}.json").read_bytes() == data

    def test_second_pass_and_reruns_never_start_or_rewrite_a_control(self, env, capsys):
        _finish(env, capsys, 2)
        stored = env.root / "control" / "llm-only"
        before = {p: p.read_bytes() for p in stored.glob("*.json")}
        assert len(before) == 12
        env.reset()
        _finish(env, capsys, 2)
        assert env.control_calls() == []
        assert {p: p.read_bytes() for p in stored.glob("*.json")} == before

    def test_rerun_of_an_unfinished_batch_does_not_rerun_controls(self, env, capsys):
        env.behavior[FIRST[0]] = "error"
        env.run(capsys)
        env.reset()
        env.behavior.clear()
        env.run(capsys)
        assert env.ran_ids("llm-only") == []


class TestResultsRoot:
    # AC-US2-14
    def test_all_output_lives_under_the_passed_root_and_earlier_state_survives(self, env, capsys):
        keep = env.root / "guard" / "reference.json"
        keep.parent.mkdir(parents=True)
        keep.write_text("{}", encoding="utf-8")
        _finish(env, capsys, 2)
        for call in env.calls:
            out = Path(env._opts(call)["--output"][0])
            assert out == env.root or env.root in out.parents
        assert keep.read_text(encoding="utf-8") == "{}"
        assert {p.name for p in env.root.iterdir()} == {"batch-1", "batch-2", "control", "guard"}
        assert not any(p.name == "benchmark" for p in env.repo.iterdir())

    def test_new_session_finds_state_left_by_earlier_session_at_the_same_root(self, env, capsys):
        _finish(env, capsys, 1)
        assert (env.root / "batch-1" / "bundle.json").is_file()
        env.reset()
        env.run(capsys)
        assert sorted(env.ran_ids("lgtm")) == sorted(SECOND)


class TestResultsRootLocation:
    # CT-batch-run-1, AC-US2-7
    def test_relative_root_inside_repository_writes_bundle_with_repository_relative_paths(
            self, env, capsys, monkeypatch):
        monkeypatch.chdir(env.repo)
        res = env.run(capsys, root="results")
        assert res.rc == 0
        cited = [c[LGTM_PATH] for c in env.bundle(1)[CASES]]
        assert sorted(Path(r).stem for r in cited) == sorted(FIRST)
        for rel in cited:
            assert not Path(rel).is_absolute()
            assert (env.repo / rel).is_file()

    def test_relative_root_outside_repository_writes_bundle_with_absolute_paths(
            self, env, capsys, monkeypatch, tmp_path):
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        res = env.run(capsys, root="results")
        assert res.rc == 0
        bundle = json.loads((elsewhere / "results" / "batch-1" / "bundle.json").read_text(encoding="utf-8"))
        for c in bundle[CASES]:
            assert Path(c[LGTM_PATH]).is_absolute()
            assert Path(c[LGTM_PATH]).resolve() == (elsewhere / "results" / "batch-1" / "lgtm" / f"{c[ID]}.json").resolve()

    def test_absolute_root_outside_repository_writes_bundle_with_absolute_paths(
            self, env, capsys, tmp_path):
        outside = tmp_path / "outside" / "results"
        res = env.run(capsys, root=str(outside))
        assert res.rc == 0
        bundle = json.loads((outside / "batch-1" / "bundle.json").read_text(encoding="utf-8"))
        assert sorted(c[ID] for c in bundle[CASES]) == sorted(FIRST)
        for c in bundle[CASES]:
            assert Path(c[LGTM_PATH]).is_absolute()
            assert json.loads(Path(c[LGTM_PATH]).read_text(encoding="utf-8"))["mode"] == "lgtm"
        assert Path(res.last).resolve() == (outside / "batch-1" / "bundle.json").resolve()


class TestControlValidity:
    # AC-US2-13, final-02
    def _store(self, env, cid, behavior="ok"):
        path = env.root / "control" / "llm-only" / f"{cid}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_result(cid, "llm-only", behavior)), encoding="utf-8")
        return path

    def test_errored_stored_control_is_rerun_into_the_control_directory_and_reported(self, env, capsys):
        bad, good = FIRST[1], FIRST[2]
        self._store(env, bad, "error")
        for cid in FIRST:
            if cid != bad:
                self._store(env, cid)
        kept = env.root / "control" / "llm-only" / f"{good}.json"
        before = kept.read_bytes()
        assert env.run(capsys).rc == 0
        assert env.ran_ids("llm-only") == [bad]
        for call in env.control_calls():
            opt = env._opts(call)
            assert opt["--modes"] == ["llm-only"]
            assert Path(opt["--output"][0]) == env.root / "control"
        assert kept.read_bytes() == before
        row = {c[ID]: c for c in env.bundle(1)[CASES]}[bad]
        assert row[CONTROL_OK] is _control_correct(bad)

    def test_missing_control_is_run_and_reported_in_the_first_bundle(self, env, capsys):
        env.run(capsys)
        row = {c[ID]: c for c in env.bundle(1)[CASES]}
        assert all(row[c][CONTROL_OK] is not None for c in FIRST)

    @pytest.mark.parametrize("behavior", ["error", "missing"])
    def test_control_still_invalid_after_its_run_leaves_batch_unfinished_until_it_is_fixed(
            self, env, capsys, behavior):
        victim = FIRST[0]
        env.control_behavior[victim] = behavior
        res = env.run(capsys)
        assert res.rc != 0
        assert victim in res.out + res.err
        assert env.bundles() == []
        assert victim in env.ran_ids("llm-only")
        env.control_behavior.clear()
        env.reset()
        res = env.run(capsys)
        assert res.rc == 0
        assert env.ran_ids("llm-only") == [victim]
        assert env.ran_ids("lgtm") == []
        assert {c[ID]: c for c in env.bundle(1)[CASES]}[victim][CONTROL_OK] is _control_correct(victim)

    def test_failing_control_run_writes_no_bundle(self, env, capsys):
        env.control_rc = 1
        for cid in FIRST:
            env.control_behavior[cid] = "missing"
        res = env.run(capsys)
        assert res.rc != 0
        assert env.bundles() == []

    def test_valid_stored_control_is_never_rerun(self, env, capsys):
        for cid in FIRST:
            self._store(env, cid)
        assert env.run(capsys).rc == 0
        assert env.control_calls() == []
