"""Outcome types shared by the runner and component modules."""

from __future__ import annotations

import io
import subprocess
import tarfile
import tempfile
from dataclasses import replace
from pathlib import Path

from lgtm.agents.tools import AgentToolbox
from lgtm.graph.runner import remove_tree
from lgtm.graph.session import GraphSession
from lgtm.rag.indexer import index_repo_docs
from lgtm.rag.retriever import PolicyRetriever

FETCH_COMMAND = "python -m benchmark.component_bench.fetch_real_prs"


class InfraError(Exception):
    """Raised by run_item when a model, judge or dependency fails; the unit is recorded as error."""


def remove_index(index_dir: Path, retriever=None) -> None:
    """Closes the retriever's Chroma clients, then removes the unit's index dir, warning if it stays."""
    if retriever is not None:
        retriever.close()
    remove_tree(index_dir)


def _export(clone: Path, ref: str, dest: Path) -> None:
    """Regular files of `ref` extracted into `dest`; symlinks are skipped."""
    tar = subprocess.run(
        ["git", "-C", str(clone), "archive", "--format=tar", ref], capture_output=True, check=True
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
        archive.extractall(dest, members=[m for m in archive if m.isfile()], filter="data")


def production_toolbox(clone: Path, case: dict, config, results_dir) -> AgentToolbox:
    """Production toolbox over the case clone: live GraphSession and PolicyRetriever, or InfraError.

    The unit's policy index is built under `<results_dir>/.policy-index`.
    """
    for sha in (case["base_ref"], case["pr_ref"]):
        found = clone.is_dir() and subprocess.run(
            ["git", "-C", str(clone), "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
        ).returncode == 0
        if not found:
            raise InfraError(f"case clone or commit missing: {clone} {sha}; run `{FETCH_COMMAND}`")
    if not config.graph_enabled:
        raise InfraError("CodeGraph is turned off; model-backed components need it")
    index_root = Path(results_dir) / ".policy-index"
    index_root.mkdir(parents=True, exist_ok=True)
    index_dir = Path(tempfile.mkdtemp(prefix=f"{case['id']}-", dir=index_root))
    retriever = None
    try:
        tree = index_dir / "tree"
        unit_config = replace(config, chroma_persist_dir=str(index_dir / "chroma"))
        _export(clone, case["pr_ref"], tree)
        index_repo_docs(tree, unit_config)
        retriever = PolicyRetriever(tree, unit_config)
        if not retriever.is_available():
            raise InfraError(f"rag index unavailable for {case['pr_ref']} export of {clone}")
    except Exception as exc:
        remove_index(index_dir, retriever)
        if isinstance(exc, InfraError):
            raise
        raise InfraError(f"policy index build failed for {clone} at {case['pr_ref']}: {exc}") from exc
    retriever.indexed_ref = case["pr_ref"]
    shas = {"base": case["base_ref"], "pr": case["pr_ref"]}
    session = GraphSession(clone, shas, config)
    try:
        if session.state != "ok":
            raise InfraError(f"CodeGraph {session.state}")
        toolbox = AgentToolbox(clone, case["base_ref"], retriever, config, shas=shas, session=session)
        toolbox.index_dir = index_dir
        return toolbox
    except Exception as exc:
        session.close()
        remove_index(index_dir, retriever)
        if isinstance(exc, ValueError):
            raise InfraError(str(exc)) from exc
        raise


def track(ctx, toolbox) -> None:
    """Registers a toolbox so the runner closes its session and checks its graph_state."""
    if getattr(toolbox, "session", None) is not None:
        ctx.toolboxes.append(toolbox)
        ctx.stack.callback(toolbox.session.close)
    index_dir = getattr(toolbox, "index_dir", None)
    if index_dir is not None:
        ctx.stack.callback(remove_index, index_dir, getattr(toolbox, "retriever", None))


def finding_record(findings) -> dict:
    """Unit verdict and explanation for a reviewer: vulnerable when it reported anything."""
    text = "\n".join(f.explanation for f in findings if getattr(f, "explanation", ""))
    return {"verdict": "vulnerable" if findings else "safe", "explanation": text or "no finding reported"}


class NotScored:
    """Returned by run_item when the unit has no valid output to score."""

    def __init__(self, reason: str):
        self.reason = reason


class ModelSettingMismatch(RuntimeError):
    pass
