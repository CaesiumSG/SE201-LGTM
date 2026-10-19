"""Read-only LangChain tools for the review agents.

Guardrails:
- All tools are strictly read-only.
- File access is restricted to the repository directory.
- Code and docs are read from the BASE branch only (PR changes are
  untrusted input and must never be executed or trusted as context).
- Tool calls are capped per agent invocation (default 5).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from langchain_core.tools import tool

from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import GitError, _run_git, read_file_at_ref
from lgtm.rag.retriever import PolicyRetriever

logger = logging.getLogger(__name__)

MAX_GREP_RESULTS = 30
MAX_READ_LINES = 200
MAX_OUTPUT_CHARS = 8000


class ToolCallLimitExceeded(RuntimeError):
    """Raised when an agent exceeds its tool-call budget."""


class AgentToolbox:
    """Factory for read-only tools bound to a repo's base branch.

    A fresh toolbox (or a ``reset_budget()`` call) should be used per agent
    invocation so the tool-call cap applies per finding reviewed.
    """

    def __init__(
        self,
        repo: str | Path,
        base_ref: str,
        retriever: PolicyRetriever | None = None,
        config: LGTMConfig | None = None,
    ):
        self.repo = Path(repo).resolve()
        self.base_ref = base_ref
        self.retriever = retriever
        self.config = config or LGTMConfig()
        self.calls_used = 0
        self.call_log: list[dict] = []

    # ------------------------------------------------------------------
    # Budget
    # ------------------------------------------------------------------
    def reset_budget(self) -> None:
        self.calls_used = 0
        self.call_log = []

    def _spend(self, tool_name: str, args: dict) -> bool:
        """Consume one tool call. Returns False when over budget."""
        self.calls_used += 1
        self.call_log.append({"tool": tool_name, "args": args})
        if self.calls_used > self.config.max_tool_calls:
            logger.warning(
                "Tool call budget exceeded (%d > %d) for %s",
                self.calls_used,
                self.config.max_tool_calls,
                tool_name,
            )
            return False
        return True

    _BUDGET_MSG = (
        "ERROR: tool call budget exhausted. You must now produce your final "
        "JSON answer using the evidence gathered so far."
    )

    # ------------------------------------------------------------------
    # Path safety
    # ------------------------------------------------------------------
    def _safe_rel_path(self, path: str) -> str:
        """Validate that ``path`` stays within the repository."""
        p = Path(path)
        if p.is_absolute():
            try:
                p = p.resolve().relative_to(self.repo)
            except ValueError:
                raise PermissionError(f"Path outside repository: {path}") from None
        rel = (self.repo / p).resolve()
        if rel != self.repo and self.repo not in rel.parents:
            raise PermissionError(f"Path outside repository: {path}")
        return str(p).replace("\\", "/")

    # ------------------------------------------------------------------
    # Tool implementations (plain methods, easy to unit test)
    # ------------------------------------------------------------------
    def read_file_impl(
        self, path: str, start_line: int | None = None, end_line: int | None = None
    ) -> str:
        try:
            rel = self._safe_rel_path(path)
        except PermissionError as exc:
            return f"ERROR: {exc}"
        try:
            content = read_file_at_ref(
                self.repo, self.base_ref, rel, self.config.git_timeout
            )
        except GitError:
            return (
                f"ERROR: file '{rel}' not found on base branch "
                f"'{self.base_ref}'. It may be new in the PR."
            )
        lines = content.splitlines()
        total = len(lines)
        start = max(1, start_line or 1)
        end = min(total, end_line or total)
        if start > total:
            return f"ERROR: start_line {start} is beyond end of file ({total} lines)."
        if end - start + 1 > MAX_READ_LINES:
            end = start + MAX_READ_LINES - 1
        numbered = [f"{i}: {lines[i - 1]}" for i in range(start, end + 1)]
        header = f"=== {rel} (lines {start}-{end} of {total}, base branch) ==="
        out = header + "\n" + "\n".join(numbered)
        return out[:MAX_OUTPUT_CHARS]

    def grep_repo_impl(self, pattern: str, file_glob: str | None = None) -> str:
        try:
            re.compile(pattern)
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        args = [
            "grep",
            "-n",
            "-E",
            "--max-count",
            "10",
            pattern,
            self.base_ref,
        ]
        if file_glob:
            args += ["--", file_glob]
        try:
            out = _run_git(args, self.repo, self.config.git_timeout)
        except GitError as exc:
            if "exit 1" in str(exc):
                return f"No matches found for pattern: {pattern}"
            return f"ERROR: {exc}"
        results = []
        prefix = f"{self.base_ref}:"
        for line in out.splitlines():
            if line.startswith(prefix):
                line = line[len(prefix):]
            results.append(line)
            if len(results) >= MAX_GREP_RESULTS:
                results.append(f"... (truncated at {MAX_GREP_RESULTS} matches)")
                break
        return "\n".join(results)[:MAX_OUTPUT_CHARS] or "No matches found."

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

    # ------------------------------------------------------------------
    # LangChain tool objects
    # ------------------------------------------------------------------
    def build_tools(self) -> list:
        toolbox = self

        @tool
        def read_file(path: str, start_line: int = 0, end_line: int = 0) -> str:
            """Read a file (or a range of lines) from the repository's BASE
            branch. Use start_line/end_line (1-based, inclusive) to read a
            specific range; pass 0 for both to read from the beginning.
            Returns numbered lines."""
            if not toolbox._spend("read_file", {"path": path, "start_line": start_line, "end_line": end_line}):
                return toolbox._BUDGET_MSG
            return toolbox.read_file_impl(
                path, start_line or None, end_line or None
            )

        @tool
        def grep_repo(pattern: str, file_glob: str = "") -> str:
            """Search the repository's BASE branch for a regular expression.
            Optionally restrict to files matching file_glob (e.g. '*.py').
            Returns matches as 'file:line:content' (limited count)."""
            if not toolbox._spend("grep_repo", {"pattern": pattern, "file_glob": file_glob}):
                return toolbox._BUDGET_MSG
            return toolbox.grep_repo_impl(pattern, file_glob or None)

        @tool
        def search_policy(query: str) -> str:
            """Search the project's documentation (security policy, API spec,
            README) for rules relevant to a natural-language query. Returns
            the most relevant excerpts with their source file and lines."""
            if not toolbox._spend("search_policy", {"query": query}):
                return toolbox._BUDGET_MSG
            return toolbox.search_policy_impl(query)

        return [read_file, grep_repo, search_policy]
