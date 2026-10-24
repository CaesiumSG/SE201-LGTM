import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from lgtm.agents.base import AgentFinding
from lgtm.cli import main
from lgtm.config import GPU_MODELS, LGTMConfig, apply_gpu_model
from tests.test_graph_pipeline import (  # noqa: F401 - fixtures
    CLAIM_AUTHZ_A,
    CLAIM_AUTHZ_B,
    CLAIM_TRIAGE,
    KEV_MODEL,
    Reply,
    _kev_reply,
    _two_agent_llm,
    healthy_stack,
    install_graph,
    isolated_git_config,
    repo,
    semgrep,
    start_kev,
)


@pytest.mark.parametrize("options,model,url", [
    ([], "qwen3.8:27b", "http://127.0.0.1:11435"),
    (["--gpu-cluster"], "qwen3.8:27b", "http://127.0.0.1:11435"),
    (["--gpu-cluster", "--model", "custom:7b"], "custom:7b", "http://127.0.0.1:11435"),
    (["--gpu-cluster", "--ollama-url", "http://127.0.0.1:12000"],
     "qwen3.8:27b", "http://127.0.0.1:12000"),
])
def test_review_model_connection(tmp_path, monkeypatch, options, model, url):
    pipeline = MagicMock()
    pipeline.return_value.run.return_value.findings = []
    pipeline.return_value.run.return_value.meta.agent_errors = []
    pipeline.return_value.run.return_value.meta.duration_seconds = 0.0
    pipeline.return_value.run.return_value.json_path = None
    monkeypatch.setattr("lgtm.pipeline.ReviewPipeline", pipeline)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
        *options,
    ])

    assert result.exit_code == 0, result.output
    config = pipeline.call_args.args[1]
    assert config.ollama_model == model
    assert config.ollama_base_url == url


def test_gpu_cluster_overrides_config_file_connection(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text(
        '{"ollama_model": "local:7b", "ollama_base_url": "http://localhost:11434", '
        '"llm_temperature": 0.3}', encoding="utf-8",
    )
    pipeline = MagicMock()
    pipeline.return_value.run.return_value.findings = []
    pipeline.return_value.run.return_value.meta.agent_errors = []
    pipeline.return_value.run.return_value.meta.duration_seconds = 0.0
    pipeline.return_value.run.return_value.json_path = None
    monkeypatch.setattr("lgtm.pipeline.ReviewPipeline", pipeline)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
        "--config-file", str(config_file), "--gpu-cluster", "--model", "custom:7b",
    ])

    assert result.exit_code == 0, result.output
    config = pipeline.call_args.args[1]
    assert config.ollama_model == "custom:7b"
    assert config.ollama_base_url == "http://127.0.0.1:11435"
    assert config.llm_temperature == 0.3


def _mock_pipeline(monkeypatch):
    pipeline = MagicMock()
    pipeline.return_value.run.return_value.findings = []
    pipeline.return_value.run.return_value.meta.agent_errors = []
    pipeline.return_value.run.return_value.meta.duration_seconds = 0.0
    pipeline.return_value.run.return_value.json_path = None
    monkeypatch.setattr("lgtm.pipeline.ReviewPipeline", pipeline)
    return pipeline


@pytest.mark.parametrize("extra,url", [
    ([], "http://127.0.0.1:11435"),
    (["--ollama-url", "http://127.0.0.1:12000"], "http://127.0.0.1:12000"),
])
def test_gpu_model_review_connection(tmp_path, monkeypatch, extra, url):
    pipeline = _mock_pipeline(monkeypatch)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
        "--gpu-model", "qwen3.8-27b", *extra,
    ])

    assert result.exit_code == 0, result.output
    config = pipeline.call_args.args[1]
    assert config.ollama_model == "qwen3.8:27b"
    assert config.ollama_base_url == url
    assert config.reasoning is False


def test_gpu_model_overrides_config_file_connection(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text(
        '{"ollama_model": "local:7b", "ollama_base_url": "http://localhost:11434", '
        '"reasoning": true, "llm_temperature": 0.3}', encoding="utf-8",
    )
    pipeline = _mock_pipeline(monkeypatch)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
        "--config-file", str(config_file), "--gpu-model", "qwen3.8-27b",
    ])

    assert result.exit_code == 0, result.output
    config = pipeline.call_args.args[1]
    assert config.ollama_model == "qwen3.8:27b"
    assert config.ollama_base_url == "http://127.0.0.1:11435"
    assert config.reasoning is False
    assert config.llm_temperature == 0.3


@pytest.mark.parametrize("conflict", [["--gpu-cluster"], ["--model", "x:1"]])
def test_gpu_model_conflicts_are_usage_errors(tmp_path, monkeypatch, conflict):
    pipeline = _mock_pipeline(monkeypatch)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
        "--gpu-model", "qwen3.8-27b", *conflict,
    ])

    assert result.exit_code == 2
    assert "--gpu-model cannot be combined" in result.output
    pipeline.assert_not_called()


def test_gpu_model_rejects_unknown_key(tmp_path, monkeypatch):
    _mock_pipeline(monkeypatch)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
        "--gpu-model", "nope",
    ])

    assert result.exit_code == 2


def test_reasoning_off_without_gpu_model(tmp_path, monkeypatch):
    pipeline = _mock_pipeline(monkeypatch)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
    ])

    assert result.exit_code == 0, result.output
    assert pipeline.call_args.args[1].reasoning is False


# --- judge-validation: judge settings (AC-4-1, AC-4-4) ------------------------

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _judge_endpoint(config):
    from urllib.parse import urlparse

    return urlparse(config.judge_endpoint)


def test_default_judge_endpoint_is_loopback_on_the_kev_port_distinct_from_qwen():
    config = LGTMConfig()

    endpoint = _judge_endpoint(config)

    assert endpoint.hostname in LOOPBACK_HOSTS
    assert endpoint.port == 8008
    assert endpoint.port != _port(config.ollama_base_url)
    assert endpoint.port != _port(GPU_MODELS["qwen3.8-27b"].base_url)


def test_default_judge_timeout_and_model_are_set():
    config = LGTMConfig()

    assert config.judge_timeout > 0
    assert config.judge_model


def _port(url):
    from urllib.parse import urlparse

    return urlparse(url).port


@pytest.mark.parametrize("options", [
    [],
    ["--gpu-cluster"],
    ["--gpu-model", "qwen3.8-27b"],
    ["--ollama-url", "http://127.0.0.1:12000"],
])
def test_qwen_selection_leaves_the_judge_settings_at_their_defaults(tmp_path, monkeypatch, options):
    pipeline = _mock_pipeline(monkeypatch)

    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature", *options,
    ])

    assert result.exit_code == 0, result.output
    config = pipeline.call_args.args[1]
    defaults = LGTMConfig()
    assert config.judge_endpoint == defaults.judge_endpoint
    assert config.judge_model == defaults.judge_model
    assert config.judge_timeout == defaults.judge_timeout


def test_gpu_models_registry_and_apply_gpu_model_are_unchanged_for_qwen():
    assert set(GPU_MODELS) == {"qwen3.8-27b"}
    config = LGTMConfig()
    judge = (config.judge_endpoint, config.judge_model, config.judge_timeout)

    apply_gpu_model(config, "qwen3.8-27b")

    assert (config.ollama_model, config.ollama_base_url, config.reasoning) == (
        "qwen3.8:27b", "http://127.0.0.1:11435", False,
    )
    assert (config.judge_endpoint, config.judge_model, config.judge_timeout) == judge


# --- judge-validation: judge settings from the command line (Connectivity: AC-4-3) ----

def _review_cli(repo, tmp_path, monkeypatch, *options, config=None):
    monkeypatch.setattr("lgtm.pipeline.build_llm", lambda config: _two_agent_llm())
    args = [
        "review", "--repo", str(repo), "--base", "main", "--pr", "pr",
        "--output", str(tmp_path / "out"),
    ]
    if config is not None:
        config_file = tmp_path / "lgtm.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")
        args += ["--config-file", str(config_file)]
    return CliRunner().invoke(main, [*args, *options])


@pytest.mark.usefixtures("healthy_stack")
class TestJudgeCliOverrides:
    @pytest.mark.parametrize("config_file_points_elsewhere", [False, True], ids=["cli-only", "over-config-file"])
    def test_judge_endpoint_option_sets_where_requests_go(
        self, repo, tmp_path, monkeypatch, start_kev, config_file_points_elsewhere
    ):
        target = start_kev(lambda r: _kev_reply(r, True, 0.5))
        elsewhere = start_kev()
        config = {"judge_endpoint": elsewhere.url} if config_file_points_elsewhere else None

        result = _review_cli(
            repo, tmp_path, monkeypatch, "--judge-endpoint", target.url, "--judge-model", KEV_MODEL,
            config=config,
        )

        assert result.exit_code == 1, result.output
        assert len(target.requests) == 3
        assert all(claim in "".join(r.body["state"] for r in target.requests)
                   for claim in (CLAIM_TRIAGE, CLAIM_AUTHZ_A, CLAIM_AUTHZ_B))
        assert elsewhere.requests == []

    def test_judge_model_option_sets_the_model_sent_to_the_judge(
        self, repo, tmp_path, monkeypatch, start_kev
    ):
        kev = start_kev(lambda r: _kev_reply(r, True, 0.5))

        result = _review_cli(
            repo, tmp_path, monkeypatch, "--judge-model", "cli-model",
            config={"judge_endpoint": kev.url, "judge_model": "file-model"},
        )

        assert result.exit_code == 1, result.output
        assert kev.requests
        assert {r.body["model"] for r in kev.requests} == {"cli-model"}

    def test_judge_timeout_option_bounds_the_wait_for_the_judge(
        self, repo, tmp_path, monkeypatch, start_kev
    ):
        kev = start_kev(lambda r: Reply(mode="stall"))

        result = _review_cli(
            repo, tmp_path, monkeypatch, "--judge-timeout", "0.3",
            config={"judge_endpoint": kev.url, "judge_model": KEV_MODEL, "judge_timeout": 30.0},
        )

        assert result.exit_code == 2, result.output
        assert kev.open_stalls == 3  # the review finished while the server still held every call


# --- support-judge: exit code and its documentation (AC-3-6, AC-3-8) ---------------

README = Path(__file__).resolve().parent.parent / "README.md"


def _finding(kind: str) -> AgentFinding:
    fields = {
        "supported": {"supported": True, "judged": True, "provenance_confidence": 0.9},
        "unsupported": {"supported": False, "judged": True, "provenance_confidence": 0.8},
        "no-source": {"supported": False, "judged": True, "unsupported_reason": "no-cited-source"},
        "not-judged": {"not_judged_reason": "judge-unreachable"},
        "too-large": {"not_judged_reason": "request-too-large"},
        "baseline-vulnerable": {"verdict": "vulnerable"},
        "baseline-safe": {"verdict": "safe"},
    }[kind]
    return AgentFinding(finding_id=kind, file="a.py", line=1, **fields)


def _exit_code(tmp_path, monkeypatch, kinds, agent_errors=()):
    pipeline = _mock_pipeline(monkeypatch)
    run_result = pipeline.return_value.run.return_value
    run_result.findings = [_finding(kind) for kind in kinds]
    run_result.meta.agent_errors = [{"source": s, "message": "failed"} for s in agent_errors]
    result = CliRunner().invoke(main, [
        "review", "--repo", str(tmp_path), "--base", "main", "--pr", "feature",
    ])
    return result.exit_code


@pytest.mark.parametrize("kinds,agent_errors,expected", [
    (["supported"], [], 1),
    (["supported", "unsupported", "not-judged"], [], 1),
    (["supported", "too-large"], ["sec-2"], 1),
    (["unsupported", "not-judged"], [], 2),
    (["unsupported", "too-large"], [], 2),
    (["not-judged"], [], 2),
    (["unsupported"], ["sec-2"], 2),
    ([], ["sec-2"], 2),
    (["unsupported"], [], 0),
    (["no-source"], [], 0),
    (["unsupported", "no-source"], [], 0),
    ([], [], 0),
    (["baseline-vulnerable", "baseline-safe"], [], 1),
    (["baseline-safe"], [], 0),
])
def test_exit_code_is_1_if_any_supported_else_2_if_not_judged_or_agent_error_else_0(
    tmp_path, monkeypatch, kinds, agent_errors, expected
):
    assert _exit_code(tmp_path, monkeypatch, kinds, agent_errors) == expected


def _exit_code_text(text: str) -> str:
    flat = " ".join(text.split()).lower()
    start = flat.index("exit code")
    return flat[start:]


def _assert_documents_exit_codes(text: str) -> None:
    section = _exit_code_text(text)
    for code in ("0", "1", "2"):
        assert re.search(rf"(?<![\w.]){code}(?![\w.])", section), f"exit code {code} missing"
    assert "supported" in section
    assert "not judged" in section
    assert "agent" in section


def test_cli_help_states_exit_codes_1_2_and_0_and_when_each_applies():
    result = CliRunner().invoke(main, ["review", "--help"])

    assert result.exit_code == 0
    _assert_documents_exit_codes(result.output)


def test_readme_states_exit_codes_1_2_and_0_and_when_each_applies():
    _assert_documents_exit_codes(README.read_text(encoding="utf-8"))
