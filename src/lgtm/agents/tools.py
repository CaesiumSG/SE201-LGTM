"""Read-only LangChain tools for the review agents.

Guardrails:
- All tools are strictly read-only.
- File access is restricted to the repository directory.
- Code is read from committed snapshots only (the base and PR commits, bound
  to full SHAs), never from the working tree. PR changes are untrusted input
  and must never be executed or trusted as context.
- Tool calls are capped per agent invocation (default 5).
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from langchain_core.tools import tool

from lgtm.config import LGTMConfig
from lgtm.rag.retriever import PolicyRetriever

if TYPE_CHECKING:
    # lgtm.graph modules are imported inside the functions that use them so
    # baseline runs never load the graph package.
    from lgtm.graph.exporter import ExportResult
    from lgtm.graph.session import GraphSession

logger = logging.getLogger(__name__)

MAX_GREP_RESULTS = 30
MAX_READ_LINES = 200
MAX_OUTPUT_CHARS = 8000

SNAPSHOT_LABELS = ("base", "pr")
_SHA = re.compile(r"[0-9a-f]{40}")
_DRIVE = re.compile(r"[A-Za-z]:")
_SEPARATORS = re.compile(r"[\\/]")
_ABSENT_FILE = re.compile(r"does not exist in|exists on disk, but not in")

_ESCAPE = "ERROR: path must be repository-relative and remain inside the repository."
_UNKNOWN_LABEL = "ERROR: unknown snapshot '{value}'. Allowed values: base, pr."
_LEGACY_UNKNOWN_LABEL = "ERROR: unknown snapshot '{value}'. Allowed values: base."
_LEGACY_PR = "ERROR: snapshot 'pr' is not available in this run. Allowed values: base."
_NOT_PRESENT = "ERROR: file '{path}' not present in {label} snapshot @{sha}."
_CANNOT_READ = "ERROR: cannot read {label} snapshot."
_EMPTY_QUERY = "ERROR: query must not be empty."
_MISSING_BINARY_WARNING = (
    "CodeGraph binary not found; investigate_* tools are disabled and agents "
    "will use read_file, grep_repo and search_policy."
)
_LATCH_WARNING = (
    "CodeGraph unavailable for {label} snapshot ({reason}); "
    "further graph calls for it are skipped"
)


def _relative_path(value: str) -> str | None:
    """Normalize a repository-relative path or glob; None when it is absolute or leaves the tree."""
    if not value or "\x00" in value or value[0] in "\\/" or _DRIVE.match(value):
        return None
    parts = [part for part in _SEPARATORS.split(value) if part not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _incomplete_categories(export: ExportResult | None) -> str | None:
    if export is None or not export.incomplete:
        return None
    categories = sorted({entry["category"] for entry in export.skipped})
    return ",".join(categories) or "unknown"


class ToolCallLimitExceeded(RuntimeError):
    """Raised when an agent exceeds its tool-call budget."""


class AgentToolbox:
    """Factory for read-only tools over a repo's committed snapshots.

    Without ``shas`` the toolbox is standalone and base-only, with the base
    commit resolved from ``base_ref``.

    A fresh toolbox (or a ``reset_budget()`` call) should be used per agent
    invocation so the tool-call cap applies per finding reviewed.
    """

    def __init__(
        self,
        repo: str | Path,
        base_ref: str,
        retriever: PolicyRetriever | None = None,
        config: LGTMConfig | None = None,
        *,
        shas: Mapping[str, str] | None = None,
        session: GraphSession | None = None,
    ):
        self.repo = Path(repo).resolve()
        self.base_ref = base_ref
        self.retriever = retriever
        self.config = config or LGTMConfig()
        self.shas = dict(shas) if shas is not None else None
        self.session = session
        self.calls_used = 0
        self.call_log: list[dict] = []
        self._legacy_base_sha: str | None = None
        self._missing_binary_warned = False
        self._latch_warned: set[str] = set()
        self._toolbox_latches: dict[str, str] = {}
        self._health: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Budget
    # ------------------------------------------------------------------
    def reset_budget(self) -> None:
        self.calls_used = 0
        self.call_log = []

    def charge(self, tool_name: str, args: dict) -> bool:
        """Spend one slot for an attempted call. Returns False once the budget is spent.

        calls_used saturates at max_tool_calls.
        """
        self.call_log.append({"tool": tool_name, "args": args})
        if self.calls_used >= self.config.max_tool_calls:
            logger.warning("Tool call budget exhausted for %s", tool_name)
            return False
        self.calls_used += 1
        return True

    BUDGET_MESSAGE = (
        "ERROR: tool call budget exhausted. You must now produce your final "
        "JSON answer using the evidence gathered so far."
    )

    # ------------------------------------------------------------------
    # Snapshots and Git
    # ------------------------------------------------------------------
    def _snapshot(self, label: str) -> tuple[str, str] | str:
        """Return ``(label, sha)`` for an allowed label, else the error envelope."""
        if self.shas is None:
            if label == "pr":
                return _LEGACY_PR
            if label != "base":
                return _LEGACY_UNKNOWN_LABEL.format(value=label)
            sha = self._resolve_base_ref()
            if sha is None:
                return _CANNOT_READ.format(label=label)
            return label, sha
        if label not in SNAPSHOT_LABELS:
            return _UNKNOWN_LABEL.format(value=label)
        return label, self.shas[label]

    def _resolve_base_ref(self) -> str | None:
        ref = self.base_ref
        if self._legacy_base_sha is None and ref and not ref.startswith("-") and "\x00" not in ref:
            done = self._git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
            sha = done.stdout.strip().lower() if done is not None and done.returncode == 0 else ""
            if _SHA.fullmatch(sha):
                self._legacy_base_sha = sha
        return self._legacy_base_sha

    def _commit_exists(self, sha: str) -> bool:
        done = self._git(["cat-file", "-e", f"{sha}^{{commit}}"])
        return done is not None and done.returncode == 0

    def _git(self, args: list[str]) -> subprocess.CompletedProcess | None:
        """Run git in the repository; None when git could not run to completion."""
        try:
            return subprocess.run(
                ["git", "-C", str(self.repo), *args],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                # Absent-path detection matches git's English stderr.
                env={**os.environ, "LC_ALL": "C"},
                timeout=self.config.git_timeout,
                check=False,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    # ------------------------------------------------------------------
    # Tool implementations (plain methods, easy to unit test)
    # ------------------------------------------------------------------
    def read_file_impl(
        self,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
        snapshot: str = "base",
    ) -> str:
        resolved = self._snapshot(snapshot)
        if isinstance(resolved, str):
            return resolved
        label, sha = resolved
        rel = _relative_path(path)
        if rel is None:
            return _ESCAPE
        done = self._git(["show", f"{sha}:{rel}"])
        if done is None or done.returncode != 0:
            if (
                done is not None
                and _ABSENT_FILE.search(done.stderr)
                and self._commit_exists(sha)
            ):
                return _NOT_PRESENT.format(path=rel, label=label, sha=sha)
            return _CANNOT_READ.format(label=label)

        from lgtm.graph.format import render_read

        lines = done.stdout.splitlines()
        total = len(lines)
        start = max(1, start_line or 1)
        end = min(total, end_line or total)
        if start > total:
            return f"ERROR: start_line {start} is beyond end of file ({total} lines)."
        if end - start + 1 > MAX_READ_LINES:
            end = start + MAX_READ_LINES - 1
        body = "\n".join(lines[start - 1 : end])
        return render_read(label, sha, rel, start, end, body, MAX_OUTPUT_CHARS)

    def grep_repo_impl(
        self, pattern: str, file_glob: str | None = None, snapshot: str = "base"
    ) -> str:
        resolved = self._snapshot(snapshot)
        if isinstance(resolved, str):
            return resolved
        label, sha = resolved
        try:
            re.compile(pattern)
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        args = ["grep", "-n", "-E", "--max-count", "10", "-e", pattern, sha]
        if file_glob:
            glob = _relative_path(file_glob)
            if glob is None:
                return _ESCAPE
            args += ["--", glob]
        done = self._git(args)
        if done is None or done.returncode not in (0, 1):
            return _CANNOT_READ.format(label=label)

        from lgtm.graph.format import render_grep

        results = []
        prefix = f"{sha}:"
        for line in done.stdout.splitlines():
            if line.startswith(prefix):
                line = line[len(prefix):]
            results.append(line)
            if len(results) >= MAX_GREP_RESULTS:
                results.append(f"... (truncated at {MAX_GREP_RESULTS} matches)")
                break
        body = "\n".join(results) or "No matches found."
        return render_grep(label, sha, pattern, body, MAX_OUTPUT_CHARS)

    def search_policy_impl(self, query: str) -> str:
        if self.retriever is None:
            return (
                "ERROR: documentation index is not available. "
                "Base your judgment on code evidence only."
            )
        try:
            return self.retriever.format_results(query)[:MAX_OUTPUT_CHARS]
        except FileNotFoundError as exc:
            return f"ERROR: {exc}"

    def _investigate(self, label: str, query: str) -> str:
        if not self.charge(f"investigate_{label}_code", {"query": query}):
            return self.BUDGET_MESSAGE
        from lgtm.graph.format import render_graph
        from lgtm.graph.runner import sanitize_query

        try:
            cleaned = sanitize_query(query)
        except ValueError:
            return _EMPTY_QUERY
        sha = self.shas[label]
        if label in self._toolbox_latches:
            reason = self._toolbox_latches[label]
            return render_graph(label, sha, "unavailable", "", query=cleaned, reason=reason)
        try:
            outcome = self.session.explore(label, cleaned)
        except Exception:
            self._sync_health()
            self._toolbox_latches[label] = "nonzero"
            self._health.setdefault(label, "nonzero")
            self._warn_latched(label)
            return render_graph(label, sha, "unavailable", "", query=cleaned, reason="nonzero")
        self._sync_health()
        if not outcome.ok:
            self._warn_latched(label)
            return render_graph(label, sha, "unavailable", "", query=cleaned, reason=outcome.reason)
        status = "no_match" if outcome.reason == "no_match" else "ok"
        return render_graph(
            label,
            sha,
            status,
            outcome.text,
            query=cleaned,
            incomplete=_incomplete_categories(self.session.snapshot(label)),
            truncated=outcome.truncated,
            omitted_chars=outcome.omitted_chars,
        )

    def _sync_health(self) -> None:
        for entry in self.session.state.split(";"):
            if entry.startswith("degraded:"):
                _, label, reason = entry.split(":", 2)
                self._health.setdefault(label, reason)

    def graph_state(self) -> str:
        """Effective run health: ok, unavailable:missing, and degraded:<label>:<reason> in first-failure order."""
        if self.session is None:
            return "ok"
        self._sync_health()
        entries = [] if self.session.available else ["unavailable:missing"]
        entries += [f"degraded:{label}:{reason}" for label, reason in self._health.items()]
        return ";".join(entries) or "ok"

    def _warn_latched(self, label: str) -> None:
        if label in self._latch_warned:
            return
        reason = self._health.get(label)
        if reason is None:
            return
        self._latch_warned.add(label)
        logger.warning(_LATCH_WARNING.format(label=label, reason=reason))

    def _warn_missing_binary(self) -> None:
        if self._missing_binary_warned:
            return
        self._missing_binary_warned = True
        logger.warning(_MISSING_BINARY_WARNING)

    # ------------------------------------------------------------------
    # LangChain tool objects
    # ------------------------------------------------------------------
    def build_tools(self) -> list:
        toolbox = self

        @tool
        def read_file(path: str, start_line: int = 0, end_line: int = 0, snapshot: str = "base") -> str:
            """Read a file (or a range of lines) from a committed snapshot of
            the repository: "base" (default) or "pr". Use start_line/end_line
            (1-based, inclusive) to read a specific range; pass 0 for both to
            read from the beginning. Returns numbered lines."""
            args = {"path": path, "start_line": start_line, "end_line": end_line, "snapshot": snapshot}
            if not toolbox.charge("read_file", args):
                return toolbox.BUDGET_MESSAGE
            return toolbox.read_file_impl(
                path, start_line or None, end_line or None, snapshot
            )

        @tool
        def grep_repo(pattern: str, file_glob: str = "", snapshot: str = "base") -> str:
            """Search a committed snapshot of the repository ("base" default or
            "pr") for a regular expression. Optionally restrict to files
            matching file_glob (e.g. '*.py'). Returns matches as
            'file:line:content' (limited count)."""
            args = {"pattern": pattern, "file_glob": file_glob, "snapshot": snapshot}
            if not toolbox.charge("grep_repo", args):
                return toolbox.BUDGET_MESSAGE
            return toolbox.grep_repo_impl(pattern, file_glob or None, snapshot)

        @tool
        def search_policy(query: str) -> str:
            """Search the project's documentation (security policy, API spec,
            README) for rules relevant to a natural-language query. Returns
            the most relevant excerpts with their source file and lines."""
            if not toolbox.charge("search_policy", {"query": query}):
                return toolbox.BUDGET_MESSAGE
            return toolbox.search_policy_impl(query)

        @tool
        def investigate_base_code(query: str) -> str:
            """Query the CodeGraph index of the "base" snapshot for symbols, definitions
            and call relations matching a query. Results come from the committed base
            commit; a missing edge does not establish safety."""
            return toolbox._investigate("base", query)

        @tool
        def investigate_pr_code(query: str) -> str:
            """Query the CodeGraph index of the "pr" snapshot for symbols, definitions
            and call relations matching a query. Results come from the committed PR
            commit; a missing edge does not establish safety."""
            return toolbox._investigate("pr", query)

        tools = [read_file, grep_repo, search_policy]
        if self.shas is not None and self.session is not None:
            if self.session.available:
                tools = [investigate_base_code, investigate_pr_code, *tools]
            else:
                self._warn_missing_binary()
        for tool_obj in tools:
            tool_obj.metadata = {"toolbox": toolbox}
        return tools
