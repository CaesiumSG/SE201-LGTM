"""Component registry: one `Entry` line per component slice."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Entry:
    module: object  # module object, or the name of benchmark/component_bench/<name>.py
    source: str = "labels"  # "labels" or "cases"
    aggregate: Callable | None = None  # (units, results_dir) -> summary section content
    applicable: frozenset[str] | None = None  # case ids the component's labels may use


REGISTRY: dict[str, Entry] = {}
