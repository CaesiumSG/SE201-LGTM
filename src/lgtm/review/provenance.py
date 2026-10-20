"""Provenance record for a review run: model, code revision, sampling, budgets and flags."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from lgtm.config import LGTMConfig

_GIT_TIMEOUT_S = 10


def run_pin(config: LGTMConfig, repo_root: Path, refs: Mapping[str, str]) -> dict[str, Any]:
    head = _git(repo_root, "rev-parse", "HEAD")
    code_sha = head.strip() if head is not None else ""
    code_dirty: bool | None = None
    if head is not None:
        status = _git(repo_root, "status", "--porcelain")
        if status is not None:
            code_dirty = bool(status.strip())

    return {
        "model": config.ollama_model,
        "code_sha": code_sha,
        "code_dirty": code_dirty,
        "base_sha": refs.get("base", ""),
        "pr_sha": refs.get("pr", ""),
        "sampling": {
            "llm_temperature": config.llm_temperature,
            "reasoning": config.reasoning,
        },
        "budgets": {
            "max_tool_calls": config.max_tool_calls,
            "max_agent_iterations": config.max_agent_iterations,
            "investigator_max_tool_calls": config.investigator_max_tool_calls,
            "investigator_max_iterations": config.investigator_max_iterations,
            "investigator_diff_chars": config.investigator_diff_chars,
            "investigator_max_sections": config.investigator_max_sections,
            "section_max_chars": config.section_max_chars,
            "max_sections": config.max_sections,
        },
        "flags": {
            "mode": config.mode,
            "static_facts": config.static_facts,
            "authz_role_guidance": config.authz_role_guidance,
            "strip_comments": config.strip_comments,
            "detect_prompt_injection": config.detect_prompt_injection,
            "require_tool_use": config.require_tool_use,
        },
    }


def _git(repo_root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout
