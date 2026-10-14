from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from lgtm.cli import main


@pytest.mark.parametrize("options,model,url", [
    ([], "qwen2.5-coder:7b", "http://localhost:11434"),
    (["--gpu-cluster"], "qwen2.5:7b", "http://127.0.0.1:11435"),
    (["--gpu-cluster", "--model", "custom:7b"], "custom:7b", "http://127.0.0.1:11435"),
    (["--gpu-cluster", "--ollama-url", "http://127.0.0.1:12000"],
     "qwen2.5:7b", "http://127.0.0.1:12000"),
])
def test_review_model_connection(tmp_path, monkeypatch, options, model, url):
    pipeline = MagicMock()
    pipeline.return_value.run.return_value.findings = []
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
