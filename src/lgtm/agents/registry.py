"""Loader for the model-visible text registry in ``prompts.toml``."""

from __future__ import annotations

import tomllib
from functools import cache
from pathlib import Path
from typing import Any


@cache
def _tables() -> dict[str, Any]:
    return tomllib.loads(Path(__file__).with_name("prompts.toml").read_text(encoding="utf-8"))


def entry(path: str) -> Any:
    """Return the registry value at a dotted path such as ``tools.budget_exhausted``."""
    node: Any = _tables()
    for part in path.split("."):
        node = node[part]
    return node


def render(path: str, /, **fields: object) -> str:
    """Fill the placeholders of the registry text at ``path``."""
    return entry(path).format(**fields)
