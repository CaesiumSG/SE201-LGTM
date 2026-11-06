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

REGISTRY["authz"] = Entry("authz", aggregate=__import__("benchmark.component_bench.authz", fromlist=["aggregate"]).aggregate, applicable=frozenset({"aegra_authz_vulnerable", "aegra_authz_safe", "langflow_authz_vulnerable", "langflow_authz_safe", "litellm_authz_vulnerable", "litellm_authz_safe", "sqladmin-ajax-lookup-authz", "weblate-memory-api-authz", "wger-repetitions-config-idor", "pretix-exporter-cachedfile-idor", "airflow-partitioned-dagruns-authz", "airflow-hitl-execution-api-authz", "redash-dashboard-fork-authz", "zulip-realm-export-delete-idor", "paperless-sharelink-bola"}))

REGISTRY["sast-sqli"] = Entry("sast_sqli", aggregate=lambda units, results_dir: __import__("benchmark.component_bench.sast_sqli", fromlist=["aggregate"]).aggregate(units, results_dir), applicable=frozenset({"pyload_sqli_vulnerable", "pyload_sqli_safe", "postgraas_sqli_vulnerable", "postgraas_sqli_safe", "alerta_sqli_vulnerable", "alerta_sqli_safe", "superset-where-in-sqli", "litellm-global-spend-logs-sqli", "redash-query-results-param-sqli", "django-explain-options-sqli"}))

REGISTRY["kev-judge"] = Entry("kev_judge")

REGISTRY["sqli-review"] = Entry("sqli_review", aggregate=__import__("benchmark.component_bench.sqli_review", fromlist=["aggregate"]).aggregate, applicable=frozenset({"pyload_sqli_vulnerable", "pyload_sqli_safe", "postgraas_sqli_vulnerable", "postgraas_sqli_safe", "alerta_sqli_vulnerable", "alerta_sqli_safe", "superset-where-in-sqli", "litellm-global-spend-logs-sqli", "redash-query-results-param-sqli", "django-explain-options-sqli"}))
