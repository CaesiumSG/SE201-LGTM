"""Prompt-injection bench: conditions, patch-apply errors and patch validity (no model, no network)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

INJECTION = Path(__file__).resolve().parent.parent / "benchmark" / "injection"
PATCHES = sorted((INJECTION / "cases").glob("*.patch"))


@pytest.fixture
def bench():
    spec = importlib.util.spec_from_file_location("inj_bench_under_test", INJECTION / "run_injection_bench.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_main(bench, monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["run_injection_bench.py", *argv])
    bench.main()


@pytest.mark.parametrize("mode", ["sast-only", "lgtm-no-sast", "policy"])
def test_dropped_modes_are_rejected(bench, monkeypatch, mode, capsys):
    with pytest.raises(SystemExit) as exc:
        _run_main(bench, monkeypatch, "--mode", mode)
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_defaults_are_lgtm_and_qwen_model(bench, monkeypatch, tmp_path):
    seen = []

    def fake_single(case, config):
        seen.append((config.mode, config.ollama_model))
        return {"id": case["id"], "category": case["category"], "expected": "vulnerable",
                "predicted": "safe", "flagged": False, "latency_seconds": 0.0, "findings": [],
                "graph_state": None, "graph_index_seconds": None, "base_sha": None, "pr_sha": None}

    monkeypatch.setattr(bench, "evaluate_single_case", fake_single)
    _run_main(bench, monkeypatch, "--cases", "inj_01_sqli_comment", "--output", str(tmp_path))
    assert seen and set(seen) == {("lgtm", "qwen3.8:27b")}


class _Finding:
    def __init__(self, data):
        self.data = data

    def model_dump(self, exclude=None):
        return dict(self.data)


def _fake_pipeline_class():
    """Flags every case except the injected inj_02 repo."""

    class FakePipeline:
        def __init__(self, repo, config):
            self.repo = str(repo)

        def run(self, base, pr, output_dir=None):
            flagged = "inj_02" not in self.repo
            verdict = "vulnerable" if flagged else "safe"
            return SimpleNamespace(
                findings=[_Finding({"category": "sqli", "verdict": verdict})],
                meta=SimpleNamespace())

    return FakePipeline


def test_patch_that_fails_to_apply_is_an_error_not_a_bypass_or_detection(bench, monkeypatch, tmp_path):
    def build(tmp, patch_path):
        if patch_path.name == "inj_01_sqli_comment.patch":
            raise RuntimeError("git apply failed:\nerror: patch does not apply")

    monkeypatch.setattr(bench, "build_case_repo", build)
    monkeypatch.setattr(bench, "index_repo_docs", lambda *a, **k: 0)
    monkeypatch.setattr(bench, "ReviewPipeline", _fake_pipeline_class())

    _run_main(bench, monkeypatch, "--mode", "llm-only",
              "--cases", "inj_01_sqli_comment", "inj_02_sqli_docstring",
              "--output", str(tmp_path))

    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["errors"] == 1
    assert summary["total_cases"] == 2
    by_inj = {c["inj_case_id"]: c for c in summary["comparisons"]}
    assert not by_inj.get("inj_01_sqli_comment", {}).get("attack_success", False)
    assert by_inj["inj_02_sqli_docstring"]["attack_success"] is True
    assert (summary["originally_flagged"], summary["attacks_succeeded"]) == (1, 1)
    assert summary["attack_success_rate"] == 1.0


@pytest.mark.parametrize("failing", ["clean", "injected"])
@pytest.mark.parametrize("explanation", [
    "Agent execution failed: timeout",
    "LLM call failed: connection refused",
    "Agent did not produce parsable output",
])
def test_agent_failure_result_is_an_error_not_a_bypass_or_detection(
        bench, monkeypatch, tmp_path, failing, explanation):
    def finding(verdict, text):
        return _Finding({"finding_id": "sqli:1", "category": "sqli",
                         "verdict": verdict, "explanation": text})

    class Pipeline:
        def __init__(self, repo, config):
            self.injected = "inj_01" in str(repo)

        def run(self, base, pr, output_dir=None):
            broke = self.injected == (failing == "injected")
            findings = [finding("safe", explanation) if broke else
                        finding("vulnerable", "ok")]
            return SimpleNamespace(findings=findings, meta=SimpleNamespace())

    monkeypatch.setattr(bench, "build_case_repo", lambda tmp, patch: None)
    monkeypatch.setattr(bench, "index_repo_docs", lambda *a, **k: 0)
    monkeypatch.setattr(bench, "ReviewPipeline", Pipeline)

    _run_main(bench, monkeypatch, "--mode", "llm-only",
              "--cases", "inj_01_sqli_comment", "--output", str(tmp_path))

    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["errors"] == 1
    assert summary["comparisons"] == []
    assert summary["attacks_succeeded"] == 0
    assert not summary.get("attack_success_rate")


class _Applied(Exception):
    pass


@pytest.mark.parametrize("patch", PATCHES, ids=lambda p: p.name)
def test_patch_applies_cleanly_to_the_bench_repo(bench, monkeypatch, tmp_path, patch):
    real = bench.run_git

    def check_only(cmd, cwd):
        if cmd[:2] == ["git", "apply"]:
            res = subprocess.run(["git", "apply", "--check", *cmd[2:]], cwd=cwd,
                                 capture_output=True, text=True)
            assert res.returncode == 0, res.stderr
            raise _Applied
        return real(cmd, cwd)

    monkeypatch.setattr(bench, "run_git", check_only)
    with pytest.raises(_Applied):
        bench.build_case_repo(tmp_path, patch)


def test_every_labelled_patch_file_exists():
    labels = json.loads((INJECTION / "labels.json").read_text(encoding="utf-8"))["cases"]
    assert PATCHES and {INJECTION.parent / c["patch_file"] for c in labels} == set(PATCHES)
