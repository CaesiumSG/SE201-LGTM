"""E2E: every argv the cluster command hands to the four benchmark CLIs parses in that CLI's own argument parser."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from tests import test_kev_deploy as kd
from tests.test_kev_deploy import sb  # noqa: F401  fixture

BENCH = kd.REPO / "benchmark"
SCRIPTS = {
    "runner.py": BENCH / "kev_support" / "runner.py",
    "judge_eval.py": BENCH / "judge_eval.py",
    "evaluate.py": BENCH / "evaluate.py",
    "evaluate_real.py": BENCH / "real_world" / "evaluate_real.py",
}

class _Parsed(Exception):
    def __init__(self, ns: argparse.Namespace):
        self.ns = ns


def parse_with_real_cli(script: str, args: list[str], monkeypatch) -> argparse.Namespace:
    """Runs the CLI's main() up to its own parse_args(), then stops before any benchmark work."""
    real_parse = argparse.ArgumentParser.parse_args
    real_known = argparse.ArgumentParser.parse_known_args

    def stop(self, argv=None, namespace=None):
        raise _Parsed(real_parse(self, argv, namespace))

    def stop_known(self, argv=None, namespace=None):
        raise _Parsed(real_known(self, argv, namespace)[0])

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", stop)
    monkeypatch.setattr(argparse.ArgumentParser, "parse_known_args", stop_known)
    monkeypatch.setattr(sys, "argv", [script, *args])
    spec = importlib.util.spec_from_file_location(f"e2e_{script[:-3]}", SCRIPTS[script])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(_Parsed) as parsed:
        module.main()
    return parsed.value.ns


@pytest.fixture
def run(sb, tmp_path):
    b = kd.Bench(sb, tmp_path)
    b.results.mkdir()

    def go(*extra):
        result = b.run(*extra)
        assert result.returncode == 0, result.stdout + result.stderr
        steps = []
        for line in sb.log.read_text().splitlines():
            if line.startswith("PY\t"):
                _, script, *args = line.split("\t")
                steps.append((Path(script).name, args))
        return steps

    return b, go


def test_wrapper_argv_parses_in_each_real_cli_in_order_with_one_cancel(run, monkeypatch):
    b, go = run
    steps = go("--results-dir", b.results.as_posix())

    assert [s for s, _ in steps] == list(SCRIPTS)
    cancels = b.scancels()
    assert len(cancels) == 1 and kd.STUB_JOB_ID in b.sb.calls()[cancels[0]]
    assert cancels[0] > max(i for i, c in enumerate(b.sb.calls()) if c.startswith("PY\t"))

    parsed = {s: parse_with_real_cli(s, a, monkeypatch) for s, a in steps}
    assert kd.inside(str(parsed["runner.py"].out), b.out) and not Path(parsed["runner.py"].out).exists()
    judge = parsed["judge_eval.py"]
    assert [Path(p).as_posix() for p in (judge.run_dir, judge.export, judge.labels)] == [
        b.run_dir.as_posix(), b.export.as_posix(), b.labels.as_posix()]
    assert judge.live is True
    subdirectories = {"evaluate.py": "evaluate", "evaluate_real.py": "evaluate-real"}
    for s in kd.RESUME_STEPS:
        assert parsed[s].resume is True
        assert Path(parsed[s].output).as_posix() == (b.results / subdirectories[s]).as_posix()


def _load(script: str):
    spec = importlib.util.spec_from_file_location(f"e2e_shared_{script[:-3]}", SCRIPTS[script])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scored_row(case_id: str, category: str) -> dict:
    return {
        "id": case_id, "category": category, "split": "real_world", "expected": "vulnerable",
        "predicted": "vulnerable", "outcome": "TP", "correct": True, "case_label": "tp",
        "predicted_grounded": "vulnerable", "outcome_grounded": "TP",
        "n_findings": 0, "verdicts": [], "grounded": 0, "grounding_rate": None,
        "latency_seconds": 1.0, "est_tokens": 0, "findings": [],
    }


def test_both_evaluators_keep_their_run_manifests_when_given_the_one_results_directory(run, monkeypatch, tmp_path):
    b, go = run
    steps = dict(go("--results-dir", b.results.as_posix()))
    evaluate, real = _load("evaluate.py"), _load("evaluate_real.py")
    labelled = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))["cases"][0]
    real_case = real.fetch.load_cases()[0]
    cache = tmp_path / "clones"
    (cache / real.fetch.project_of(real_case) / ".git").mkdir(parents=True)
    monkeypatch.setattr(evaluate, "evaluate_case", lambda case, config: _scored_row(case["id"], case["category"]))
    monkeypatch.setattr(real, "preflight", lambda modes, config: {})
    monkeypatch.setattr(
        real, "run_unit", lambda case, mode, *a, **k: _scored_row(case["id"], case["category"])
    )
    monkeypatch.setattr(sys, "argv", ["evaluate.py", *steps["evaluate.py"], "--split", "all", "--cases", labelled["id"]])
    real_argv = [*steps["evaluate_real.py"], "--cache", str(cache), "--cases", real_case["id"],
                 "--modes", "llm-only"]

    for name, call in (("evaluate.py", evaluate.main), ("evaluate_real.py", lambda: real.main(real_argv))):
        try:
            call()
        except SystemExit as exc:
            if exc.code not in (None, 0):
                pytest.fail(f"{name} stopped on the shared results directory: {exc.code}")

    manifests = [json.loads(p.read_text(encoding="utf-8")) for p in b.results.rglob("run.json")]
    assert len(manifests) == 2
    assert sum("modes" in m for m in manifests) == 1


def test_wrapper_argv_without_results_directory_parses_with_normal_reviewer_path(run, monkeypatch):
    b, go = run
    parsed = {s: parse_with_real_cli(s, a, monkeypatch) for s, a in go()}
    for s in kd.RESUME_STEPS:
        assert parsed[s].resume is False
