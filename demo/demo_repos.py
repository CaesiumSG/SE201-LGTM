"""Which GitHub account holds the demo repositories on this machine.

The scripted tasks (workspace_presets.json) and the App tab name the original repositories under ``cyberjj999``.
Anyone else runs the demo on their own forks, so those names are rewritten to the owner of the GitHub App this
server created (the person who ran the setup page), or to ``LGTM_DEMO_OWNER`` when it is set in ``.env``.
"""

from __future__ import annotations

import os

import github_app as gh

CANONICAL_OWNER = "cyberjj999"
SHOPLY = f"{CANONICAL_OWNER}/shoply-demo"


def owner() -> str:
    return os.environ.get("LGTM_DEMO_OWNER") or (gh.load_app() or {}).get("owner") or CANONICAL_OWNER


def resolve(repo: str) -> str:
    """``cyberjj999/<name>`` as it is on this machine: ``<owner>/<name>``. Other repositories are unchanged."""
    first, _, name = repo.partition("/")
    return f"{owner()}/{name}" if first == CANONICAL_OWNER else repo


def name(repo: str) -> str:
    return repo.partition("/")[2]
