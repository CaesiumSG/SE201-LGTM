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

from lgtm.agents.base import SNAPSHOT_LABELS
from lgtm.config import GRAPH_OUTPUT_CHARS_CEILING, LGTMConfig
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

_SHA = re.compile(r"[0-9a-f]{40}")
_DRIVE = re.compile(r"[A-Za-z]:")
_SEPARATORS = re.compile(r"[\\/]")
_GIT_ENV_NAMES = ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG")

_ESCAPE = "ERROR: path must be repository-relative and remain inside the repository."
_UNKNOWN_LABEL = "ERROR: unknown snapshot '{value}'. Allowed values: base, pr."
_LEGACY_UNKNOWN_LABEL = "ERROR: unknown snapshot '{value}'. Allowed values: base."
_LEGACY_PR = "ERROR: snapshot 'pr' is not available in this run. Allowed values: base."
_NOT_PRESENT = "ERROR: file '{path}' not present in {label} snapshot @{sha}."
_CANNOT_READ = "ERROR: cannot read {label} snapshot."
_REJECTED_PATTERN = "ERROR: invalid regex: pattern is not a valid extended regular expression."
_MULTILINE_PATTERN = "ERROR: invalid regex: pattern must be a single line without NUL bytes."
_EMPTY_QUERY = "ERROR: query must not be empty."
_MISSING_BINARY_WARNING = (
    "CodeGraph binary not found; investigate_* tools are disabled and agents "
    "will use read_file, grep_repo and search_policy."
)
_LATCH_WARNING = (
    "CodeGraph unavailable for {label} snapshot ({reason}); "
    "further graph calls for it are skipped"
)


def relative_path(value: str) -> str | None:
    """Normalize a repository-relative path or glob; None when it is absolute or leaves the tree."""
    if not value or "\x00" in value or ":" in value or value[0] in "\\/" or _DRIVE.match(value):
        return None
    parts = [part for part in _SEPARATORS.split(value) if part not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def git_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in _GIT_ENV_NAMES or key.upper().startswith("LC_")
    }
    env.update(
        LC_ALL="C",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
    )
    return env


def run_git(
    repo: str | Path, args: list[str], timeout: float
) -> subprocess.CompletedProcess | None:
    """Run git in ``repo``; None when git could not run to completion."""
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env=git_env(),
            timeout=timeout,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def read_committed_blob(
    repo: str | Path, sha: str, rel: str, timeout: float
) -> subprocess.CompletedProcess | None:
    """One ``git cat-file blob`` of repository-relative ``rel`` at commit ``sha``."""
    return run_git(repo, ["cat-file", "blob", f"{sha}:{rel}"], timeout)


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
        for sha in (self.shas or {}).values():
            if not _SHA.fullmatch(sha):
                raise ValueError("snapshot SHAs must be full 40-character lowercase hex commits")
        self.session = session
        self.calls_used = 0
        self.call_log: list[dict] = []
        self._legacy_base_sha: str | None = None
        self._missing_binary_warned = False
        self._latch_warned: set[str] = set()
        self._toolbox_latched: set[str] = set()
        self._health: dict[str, str] = {}
        self._missing_at_startup = False
        if self.shas is not None and self.session is not None and not self.session.available:
            self._missing_at_startup = True
            self._warn_missing_binary()

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
    def _label_error(self, label: str) -> str | None:
        if self.shas is None:
            if label == "pr":
                return _LEGACY_PR
            if label != "base":
                return _LEGACY_UNKNOWN_LABEL.format(value=label)
            return None
        if label not in SNAPSHOT_LABELS:
            return _UNKNOWN_LABEL.format(value=label)
        return None

    def _snapshot_sha(self, label: str) -> str | None:
        if self.shas is None:
            return self._resolve_base_ref()
        return self.shas[label]

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
        return run_git(self.repo, args, self.config.git_timeout)

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
        error = self._label_error(snapshot)
        if error is not None:
            return error
        rel = relative_path(path)
        if rel is None:
            return _ESCAPE
        label = snapshot
        sha = self._snapshot_sha(label)
        if sha is None:
            return _CANNOT_READ.format(label=label)
        done = read_committed_blob(self.repo, sha, rel, self.config.git_timeout)
        if done is None:
            return _CANNOT_READ.format(label=label)
        if done.returncode != 0:
            if self._commit_exists(sha):
                return _NOT_PRESENT.format(path=rel, label=label, sha=sha)
            return _CANNOT_READ.format(label=label)

        from lgtm.graph.format import render_read

        lines = done.stdout.splitlines()
        total = len(lines)
        start = start_line if start_line and start_line > 0 else 1
        if start > total:
            return f"ERROR: start_line {start} is beyond end of file ({total} lines)."
        end = min(total, end_line) if end_line and end_line > 0 else total
        if end < start:
            end = total
        if end - start + 1 > MAX_READ_LINES:
            end = start + MAX_READ_LINES - 1
        body = "\n".join(lines[start - 1 : end])
        return render_read(label, sha, rel, start, end, body, MAX_OUTPUT_CHARS)

    def grep_repo_impl(
        self, pattern: str, file_glob: str | None = None, snapshot: str = "base"
    ) -> str:
        error = self._label_error(snapshot)
        if error is not None:
            return error
        glob = None
        if file_glob:
            glob = relative_path(file_glob)
            if glob is None:
                return _ESCAPE
        if "\x00" in pattern or "\n" in pattern:
            return _MULTILINE_PATTERN
        try:
            re.compile(pattern)
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        label = snapshot
        sha = self._snapshot_sha(label)
        if sha is None:
            return _CANNOT_READ.format(label=label)
        args = ["grep", "-n", "-E", "--max-count", "10", "-e", pattern, sha]
        if glob is not None:
            args += ["--", glob]
        done = self._git(args)
        if done is None:
            return _CANNOT_READ.format(label=label)
        if done.returncode not in (0, 1):
            if self._commit_exists(sha):
                return _REJECTED_PATTERN
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
        cap = min(self.config.graph_max_output_chars, GRAPH_OUTPUT_CHARS_CEILING)

        def unavailable(reason: str) -> str:
            return render_graph(
                label, sha, "unavailable", "", query=cleaned, reason=reason, max_chars=cap
            )

        if label in self._toolbox_latched:
            return unavailable(self._health[label])
        try:
            outcome = self.session.explore(label, cleaned)
        except Exception:
            self._sync_health()
            self._latch_toolbox(label, "nonzero")
            self._warn_latched(label)
            return unavailable(self._health[label])
        self._sync_health()
        if not outcome.ok:
            reason = outcome.reason
            if reason == "missing":
                for target in SNAPSHOT_LABELS:
                    self._latch_toolbox(target, "launch_failed")
                reason = self._health[label]
            self._warn_latched(label)
            return unavailable(reason)
        status = "no_match" if outcome.reason == "no_match" else "ok"
        return render_graph(
            label,
            sha,
            status,
            outcome.text,
            query=cleaned,
            max_chars=cap,
            incomplete=_incomplete_categories(self.session.snapshot(label)),
            truncated=outcome.truncated,
            omitted_chars=outcome.omitted_chars,
        )

    def _sync_health(self) -> None:
        for entry in self.session.state.split(";"):
            if entry.startswith("degraded:"):
                _, label, reason = entry.split(":", 2)
                self._health.setdefault(label, reason)

    def _latch_toolbox(self, label: str, reason: str) -> None:
        self._toolbox_latched.add(label)
        self._health.setdefault(label, reason)

    def graph_state(self) -> str:
        """Run health: ok, unavailable:missing, then degraded:<label>:<reason> in first-failure order."""
        if self.session is None:
            return "ok"
        self._sync_health()
        entries = ["unavailable:missing"] if self._missing_at_startup else []
        entries += [f"degraded:{label}:{reason}" for label, reason in self._health.items()]
        return ";".join(entries) or "ok"

    def snapshot_ok(self, label: str) -> bool:
        if self.session is None or not self.session.available:
            return False
        self._sync_health()
        return label not in self._health

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
            """Query the CodeGraph index of the base snapshot for symbols and call relations."""
            return toolbox._investigate("base", query)

        @tool
        def investigate_pr_code(query: str) -> str:
            """Query the CodeGraph index of the PR snapshot for symbols and call relations."""
            return toolbox._investigate("pr", query)

        tools = [read_file, grep_repo, search_policy]
        if self.shas is not None and self.session is not None and not self._missing_at_startup:
            tools = [investigate_base_code, investigate_pr_code, *tools]
        for tool_obj in tools:
            tool_obj.metadata = {"toolbox": toolbox}
        return tools
