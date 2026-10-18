"""Tests for the GPU model registry and the reasoning option."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from lgtm.agents.base import build_llm
from lgtm.config import GPU_MODELS, GpuModel, LGTMConfig, apply_gpu_model


class TestRegistry:
    def test_qwen38_entry(self):
        assert GPU_MODELS["qwen3.8-27b"] == GpuModel(
            "qwen3.8:27b", "http://127.0.0.1:11435", False
        )

    def test_entries_are_immutable(self):
        with pytest.raises(FrozenInstanceError):
            GPU_MODELS["qwen3.8-27b"].tag = "other:1b"

    def test_apply_sets_model_url_and_reasoning(self):
        config = LGTMConfig(reasoning=True)
        apply_gpu_model(config, "qwen3.8-27b")
        assert config.ollama_model == "qwen3.8:27b"
        assert config.ollama_base_url == "http://127.0.0.1:11435"
        assert config.reasoning is False

    def test_apply_base_url_override_keeps_model_and_reasoning(self):
        config = LGTMConfig(reasoning=True)
        apply_gpu_model(config, "qwen3.8-27b", base_url="http://10.0.0.5:9999")
        assert config.ollama_base_url == "http://10.0.0.5:9999"
        assert config.ollama_model == "qwen3.8:27b"
        assert config.reasoning is False

    def test_apply_unknown_key_raises_keyerror(self):
        with pytest.raises(KeyError):
            apply_gpu_model(LGTMConfig(), "no-such-model")


class TestConfig:
    def test_reasoning_defaults_to_none(self):
        assert LGTMConfig().reasoning is None

    def test_reasoning_loads_from_config_file(self, tmp_path):
        path = tmp_path / "lgtm.json"
        path.write_text(json.dumps({"reasoning": False}), encoding="utf-8")
        assert LGTMConfig.from_file(path).reasoning is False


class _RecordingChatOllama:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class TestBuildLlm:
    def test_reasoning_omitted_when_none(self, monkeypatch):
        monkeypatch.setattr("langchain_ollama.ChatOllama", _RecordingChatOllama)
        llm = build_llm(LGTMConfig())
        assert "reasoning" not in llm.kwargs

    @pytest.mark.parametrize("reasoning", [False, True])
    def test_reasoning_passed_when_set(self, monkeypatch, reasoning):
        monkeypatch.setattr("langchain_ollama.ChatOllama", _RecordingChatOllama)
        llm = build_llm(LGTMConfig(reasoning=reasoning))
        assert llm.kwargs["reasoning"] is reasoning

    def test_installed_chatollama_accepts_reasoning(self):
        assert build_llm(LGTMConfig(reasoning=False)).reasoning is False
        assert build_llm(LGTMConfig()).reasoning is None
