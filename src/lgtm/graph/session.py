"""Lazily exported, per-snapshot CodeGraph sessions for the base and PR commits."""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path
from typing import Callable, Mapping

from lgtm.config import LGTMConfig
from lgtm.graph.exporter import ExportResult, _remove_owned_root, export_snapshot
from lgtm.graph.runner import GraphOutcome, GraphRunner, failed_outcome, sanitize_query

logger = logging.getLogger(__name__)

LABELS = ("base", "pr")


class GraphSession:
    def __init__(
        self,
        repo: str | Path,
        shas: Mapping[str, str],
        config: LGTMConfig,
        *,
        runner: GraphRunner | None = None,
        export: Callable[..., ExportResult] | None = None,
    ) -> None:
        self._repo = repo
        self._shas = shas
        self._config = config
        if runner is None:
            runner = GraphRunner(
                config.graph_binary,
                init_timeout_s=config.graph_init_timeout_s,
                query_timeout_s=config.graph_query_timeout_s,
                max_output_chars=config.graph_max_output_chars,
            )
        self._runner = runner
        self._export = export if export is not None else export_snapshot
        self._work: Path | None = None
        self._roots: dict[str, Path] = {}
        self._exports: dict[str, ExportResult] = {}
        self._latched: dict[str, str] = {}
        self._export_seconds = dict.fromkeys(LABELS, 0.0)
        self._init_seconds = dict.fromkeys(LABELS, 0.0)
        self._closed = False

    def __enter__(self) -> GraphSession:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def available(self) -> bool:
        return self._runner.available()

    @property
    def state(self) -> str:
        entries = [] if self.available else ["unavailable:missing"]
        entries += [f"degraded:{label}:{reason}" for label, reason in self._latched.items()]
        return ";".join(entries) or "ok"

    @property
    def export_seconds(self) -> float:
        return sum(self._export_seconds.values())

    @property
    def init_seconds(self) -> float:
        return sum(self._init_seconds.values())

    @property
    def timings(self) -> dict[str, dict[str, float]]:
        return {
            label: {"export": self._export_seconds[label], "init": self._init_seconds[label]}
            for label in LABELS
        }

    def snapshot(self, label: str) -> ExportResult | None:
        if label not in LABELS:
            raise ValueError(f"unknown snapshot label: {label!r}")
        return self._exports.get(label)

    def explore(self, label: str, query: str) -> GraphOutcome:
        if label not in LABELS:
            raise ValueError(f"unknown snapshot label: {label!r}")
        if self._closed:
            raise RuntimeError("graph session is closed")
        cleaned = sanitize_query(query)
        if not self.available:
            return failed_outcome("missing")
        root = self._prepare(label)
        if root is None:
            return failed_outcome(self._latched[label])
        outcome = self._runner.explore(root, cleaned)
        if not outcome.ok:
            self._latch(label, outcome.reason)
        return outcome

    def close(self) -> None:
        self._closed = True
        self._roots.clear()
        if self._work is not None:
            try:
                _remove_owned_root(self._work)
            except ValueError:
                logger.warning("could not remove graph export directory: %s", self._work)
            self._work = None

    def _prepare(self, label: str) -> Path | None:
        if label in self._latched:
            return None
        if label in self._roots:
            return self._roots[label]
        root = self._export_snapshot(label)
        if root is None or not self._init_snapshot(label, root):
            return None
        self._roots[label] = root
        return root

    def _export_snapshot(self, label: str) -> Path | None:
        started = time.monotonic()
        try:
            result = self._export(
                self._repo,
                self._shas[label],
                self._scratch() / label,
                max_files=self._config.graph_max_export_files,
                max_bytes=self._config.graph_max_export_bytes,
                timeout=self._config.git_timeout,
            )
        except Exception:
            logger.warning("graph export failed for the %s snapshot", label)
            self._latch(label, "export_failed")
            return None
        finally:
            self._export_seconds[label] += time.monotonic() - started
        self._exports[label] = result
        return result.root

    def _init_snapshot(self, label: str, root: Path) -> bool:
        started = time.monotonic()
        try:
            outcome = self._runner.init(root)
        finally:
            self._init_seconds[label] += time.monotonic() - started
        if not outcome.ok:
            self._latch(label, outcome.reason)
            return False
        return True

    def _latch(self, label: str, reason: str) -> None:
        # A launch failure is not specific to one snapshot, so it latches both labels.
        targets = LABELS if reason == "launch_failed" else (label,)
        for target in targets:
            self._latched.setdefault(target, reason)

    def _scratch(self) -> Path:
        if self._work is None:
            self._work = Path(tempfile.mkdtemp(prefix="lgtm-graph-session-"))
        return self._work
