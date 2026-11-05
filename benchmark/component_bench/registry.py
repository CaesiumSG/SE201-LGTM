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
def _retrieval_aggregate(units, results_dir, labels_dir=None):
    from benchmark.component_bench import retrieval  # deferred: pulls in chromadb

    return retrieval.aggregate(units, results_dir, labels_dir)


REGISTRY["retrieval"] = Entry("retrieval", source="cases", aggregate=_retrieval_aggregate)

REGISTRY["investigator"] = Entry(module="investigator", source="cases", aggregate=__import__("benchmark.component_bench.investigator", fromlist=["aggregate"]).aggregate)

