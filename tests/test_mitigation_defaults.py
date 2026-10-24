"""The prompt-injection mitigations are on by default, for the LGTM modes only."""

from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from lgtm.cli import main
from lgtm.config import LGTMConfig
from lgtm.pipeline import mitigations_apply


def test_mitigations_default_on():
    config = LGTMConfig()
    assert config.strip_comments is True
    assert config.detect_prompt_injection is True


@pytest.mark.parametrize("mode", ["lgtm", "lgtm-no-sast"])
def test_mitigations_apply_in_lgtm_modes(mode):
    assert mitigations_apply(mode, LGTMConfig()) == {
        "strip_comments": True,
        "detect_prompt_injection": True,
    }


@pytest.mark.parametrize("mode", ["llm-only", "sast-only"])
def test_baselines_never_mitigated(mode):
    # Baseline B is the bare model on the raw diff (proposal); A never prompts.
    assert mitigations_apply(mode, LGTMConfig()) == {
        "strip_comments": False,
        "detect_prompt_injection": False,
    }


def test_config_can_switch_mitigations_off():
    config = LGTMConfig(strip_comments=False, detect_prompt_injection=False)
    assert mitigations_apply("lgtm", config) == {
        "strip_comments": False,
        "detect_prompt_injection": False,
    }


def _invoke(tmp_path, monkeypatch, *options):
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
    return pipeline.call_args.args[1]


def test_cli_defaults_leave_mitigations_on(tmp_path, monkeypatch):
    config = _invoke(tmp_path, monkeypatch)
    assert config.strip_comments is True
    assert config.detect_prompt_injection is True


def test_cli_no_flags_switch_mitigations_off(tmp_path, monkeypatch):
    config = _invoke(
        tmp_path, monkeypatch, "--no-strip-comments", "--no-detect-prompt-injection"
    )
    assert config.strip_comments is False
    assert config.detect_prompt_injection is False


def test_cli_flag_overrides_config_file(tmp_path, monkeypatch):
    config_file = tmp_path / "config.json"
    config_file.write_text('{"strip_comments": false}', encoding="utf-8")
    config = _invoke(tmp_path, monkeypatch, "--config-file", str(config_file))
    assert config.strip_comments is False  # file honoured when no flag is given
    config = _invoke(
        tmp_path, monkeypatch, "--config-file", str(config_file), "--strip-comments"
    )
    assert config.strip_comments is True
