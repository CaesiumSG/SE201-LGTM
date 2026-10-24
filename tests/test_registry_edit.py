"""Editing a registry entry changes the rendered model input at that text and nowhere else."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "EDITED-REGISTRY-TEXT"

RENDER = """
import json, sys
from lgtm.rag.retriever import PolicyRetriever
from lgtm.agents.tools import AgentToolbox

repo = sys.argv[1]
retriever = PolicyRetriever(repo)
retriever.retrieve = lambda q, top_k=None: []
toolbox = AgentToolbox(repo, "HEAD", retriever=None)
tools = {t.name: t.description for t in toolbox.build_tools(graph=False)}
print(json.dumps({
    "retriever_no_results": retriever.format_results("q"),
    "policy_index_unavailable": toolbox.search_policy_impl("q"),
    "search_policy_description": tools["search_policy"],
}))
"""

CASES = {
    "retriever_no_results": "No relevant documentation found for this query.",
    "policy_index_unavailable": "documentation index is not available",
    "search_policy_description": "Search the project's documentation",
}


def _render(package_root: Path, workdir: Path) -> dict:
    done = subprocess.run(
        [sys.executable, "-c", RENDER, str(workdir)],
        env={**os.environ, "PYTHONPATH": str(package_root)},
        capture_output=True,
        text=True,
        timeout=120,
        cwd=workdir,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.mark.parametrize("case", CASES)
def test_editing_one_registry_entry_changes_only_that_text(tmp_path, case):
    phrase = CASES[case]
    for name in ("original", "edited"):
        shutil.copytree(
            ROOT / "src" / "lgtm",
            tmp_path / name / "lgtm",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    registry = tmp_path / "edited" / "lgtm" / "agents" / "prompts.toml"
    text = registry.read_text(encoding="utf-8")
    assert phrase in text, "text must live in the registry"
    registry.write_text(text.replace(phrase, SENTINEL), encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()

    before = _render(tmp_path / "original", work)
    after = _render(tmp_path / "edited", work)

    assert SENTINEL in after[case]
    assert after == {key: value.replace(phrase, SENTINEL) for key, value in before.items()}
