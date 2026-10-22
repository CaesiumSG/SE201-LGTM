from __future__ import annotations

from importlib import import_module

_EXPORTS = {
    "AgentToolbox": "lgtm.agents.tools",
    "SASTTriageAgent": "lgtm.agents.sast_triage",
    "AuthzReviewerAgent": "lgtm.agents.authz_reviewer",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(_EXPORTS[name]), name)
