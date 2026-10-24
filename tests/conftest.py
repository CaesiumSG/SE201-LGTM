"""Shared fixtures: a small temp git repo with a base and a PR branch."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A git repo with main (base) and pr branches, one python file + doc."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@t.local")
    git(repo, "config", "user.name", "T")

    (repo / "app.py").write_text(
        "def get_user(cursor, user_id):\n"
        '    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        "    return cursor.fetchone()\n",
        encoding="utf-8",
    )
    (repo / "policy.md").write_text(
        "# Security Policy\n\nAll SQL must use bound parameters.\n"
        "Only admins may delete users.\n",
        encoding="utf-8",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")

    git(repo, "checkout", "-q", "-b", "pr")
    (repo / "app.py").write_text(
        "def get_user(cursor, user_id):\n"
        '    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
        "    return cursor.fetchone()\n"
        "\n"
        "def find_user(cursor, name):\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "add find_user")
    git(repo, "checkout", "-q", "main")
    return repo


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch):
    monkeypatch.setattr("lgtm.agents.base._sleep", lambda seconds: None)


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    recorded: list[float] = []
    monkeypatch.setattr("lgtm.agents.base._sleep", recorded.append)
    return recorded


@pytest.fixture(autouse=True)
def _isolate_graph_env(monkeypatch):
    for key in [k for k in os.environ if k.upper().startswith("CODEGRAPH_")]:
        monkeypatch.delenv(key)
