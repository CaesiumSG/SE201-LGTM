"""Main LGTM pipeline orchestrator.

Stages:
1. Context building — git diff, semgrep scan, RAG retriever.
2. SAST triage — LLM agent triages each semgrep finding in the diff.
3. Authorization review — LLM agent reviews each changed endpoint.
4. Evidence validation — every citation is checked against the repo.
5. Reporting — JSON + Markdown.

Supports three modes for benchmarking:
- ``lgtm``: full pipeline (SAST + LLM agents + RAG).
- ``sast-only``: semgrep findings reported directly, no LLM.
- ``llm-only``: LLM agents without semgrep seeding (heuristic SQL sinks).
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from lgtm.agents.authz_reviewer import (
    AuthzReviewerAgent,
    extract_changed_endpoints,
)
from lgtm.agents.base import AgentFinding, build_llm
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, get_pr_diff
from lgtm.rag.retriever import PolicyRetriever
from lgtm.reporting.report_builder import ReportBuilder, ReviewMetadata
from lgtm.sast.semgrep_runner import (
    SemgrepError,
    SemgrepFinding,
    filter_to_diff,
    run_semgrep,
)
from lgtm.validation.evidence import EvidenceValidator

logger = logging.getLogger(__name__)

# Heuristic SQL sink detector for llm-only mode
SQL_SINK_RE = re.compile(
    r"\.(execute|executemany|exec_driver_sql)\s*\(|text\s*\(|"
    r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*\b(FROM|INTO|SET|WHERE)\b",
    re.IGNORECASE,
)


@dataclass
class ReviewResult:
    findings: list[AgentFinding]
    meta: ReviewMetadata
    json_path: Path | None = None
    md_path: Path | None = None
    diffs: list[FileDiff] = field(default_factory=list)


class ReviewPipeline:
    def __init__(self, repo: str | Path, config: LGTMConfig | None = None, llm=None):
        self.repo = Path(repo).resolve()
        self.config = config or LGTMConfig()
        self._llm = llm  # injectable for tests

    # ------------------------------------------------------------------
    def run(
        self, base: str, pr: str, output_dir: str | Path | None = None
    ) -> ReviewResult:
        start = time.monotonic()
        mode = self.config.mode
        logger.info(
            "Starting LGTM review (%s): %s..%s in %s", mode, base, pr, self.repo
        )

        # ---- Stage 1: context ----------------------------------------
        diffs = get_pr_diff(self.repo, base, pr, self.config.git_timeout)
        diffs = [d for d in diffs if d.status != "deleted"]
        logger.info("PR changes %d file(s)", len(diffs))

        retriever: PolicyRetriever | None = None
        if mode != "sast-only":
            retriever = PolicyRetriever(self.repo, self.config)
            if not retriever.is_available():
                logger.warning(
                    "RAG index not found — run `lgtm index` first. "
                    "Agents will rely on code evidence only."
                )
                retriever = None

        semgrep_total = 0
        semgrep_in_diff: list[SemgrepFinding] = []
        if mode != "llm-only":
            semgrep_in_diff, semgrep_total = self._run_sast(diffs, base, pr)

        meta = ReviewMetadata(
            repo=str(self.repo),
            base=base,
            pr=pr,
            mode=mode,
            model=self.config.ollama_model if mode != "sast-only" else "none",
            semgrep_findings_total=semgrep_total,
            semgrep_findings_in_diff=len(semgrep_in_diff),
        )

        findings: list[AgentFinding] = []

        if mode == "sast-only":
            findings = [self._sast_finding_to_agent_finding(f) for f in semgrep_in_diff]
        else:
            llm = self._llm or build_llm(self.config)
            toolbox = AgentToolbox(self.repo, base, retriever, self.config)
            diff_by_path = {d.path: d for d in diffs}

            # ---- Stage 2: SAST triage --------------------------------
            if mode == "llm-only":
                semgrep_in_diff = self._heuristic_sql_findings(diffs)
                logger.info(
                    "llm-only mode: %d heuristic SQL sink(s) to triage",
                    len(semgrep_in_diff),
                )
            triage_agent = SASTTriageAgent(toolbox, self.config, llm)
            for sf in semgrep_in_diff:
                fd = diff_by_path.get(sf.path) or self._match_diff(sf.path, diffs)
                findings.append(triage_agent.triage(sf, fd))

            # ---- Stage 3: authorization review -----------------------
            endpoints = extract_changed_endpoints(diffs)
            meta.endpoints_reviewed = len(endpoints)
            authz_agent = AuthzReviewerAgent(toolbox, self.config, llm)
            for ep in endpoints:
                fd = diff_by_path.get(ep.file)
                notes = "\n".join(
                    f"- {sf.rule_id} at {sf.path}:{sf.start_line}: {sf.message}"
                    for sf in semgrep_in_diff
                    if sf.path == ep.file
                )
                findings.append(authz_agent.review(ep, fd, notes))

        # ---- Stage 4: evidence validation ----------------------------
        validator = EvidenceValidator(self.repo, base, diffs, self.config)
        findings = validator.validate_all(findings)

        # ---- Stage 5: report ------------------------------------------
        meta.duration_seconds = time.monotonic() - start
        builder = ReportBuilder(findings, meta)
        json_path = md_path = None
        if output_dir is not None:
            json_path, md_path = builder.write(output_dir)

        logger.info(
            "Review complete: %d finding(s) in %.1fs",
            len(findings),
            meta.duration_seconds,
        )
        return ReviewResult(
            findings=findings,
            meta=meta,
            json_path=json_path,
            md_path=md_path,
            diffs=diffs,
        )

    # ------------------------------------------------------------------
    def _run_sast(
        self, diffs: list[FileDiff], base: str, pr: str
    ) -> tuple[list[SemgrepFinding], int]:
        """Run semgrep on the PR version of the changed python files.

        The repo's working tree may be on any branch, so the changed files
        are materialized at the PR ref into a temp directory and scanned
        there (scanning only — PR code is never executed).
        """
        import tempfile

        from lgtm.diff.git_diff import GitError, read_file_at_ref

        changed_files = [d.path for d in diffs if d.path.endswith(".py")]
        if not changed_files:
            return [], 0
        semgrep_config = self.config.semgrep_config
        if semgrep_config == "auto":
            # Bundled CWE-89 rules work offline; "auto" needs registry access.
            bundled = Path(__file__).parent / "sast" / "rules"
            if bundled.is_dir():
                semgrep_config = str(bundled)
        try:
            with tempfile.TemporaryDirectory(prefix="lgtm-sast-") as tmpdir:
                tmp = Path(tmpdir)
                materialized: list[str] = []
                for rel in changed_files:
                    try:
                        content = read_file_at_ref(
                            self.repo, pr, rel, self.config.git_timeout
                        )
                    except GitError:
                        continue  # deleted or unreadable at the PR ref
                    target = tmp / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")
                    materialized.append(rel)
                all_findings = run_semgrep(
                    tmp, materialized, semgrep_config, self.config.semgrep_timeout
                )
        except SemgrepError as exc:
            logger.error("Semgrep failed, continuing without SAST: %s", exc)
            return [], 0
        in_diff = filter_to_diff(all_findings, diffs)
        return in_diff, len(all_findings)

    @staticmethod
    def _match_diff(path: str, diffs: list[FileDiff]) -> FileDiff | None:
        for d in diffs:
            if d.path.endswith(path) or path.endswith(d.path):
                return d
        return None

    @staticmethod
    def _sast_finding_to_agent_finding(sf: SemgrepFinding) -> AgentFinding:
        """sast-only baseline: report semgrep findings directly."""
        severity_conf = {"ERROR": 0.8, "WARNING": 0.5, "INFO": 0.3}
        from lgtm.agents.base import EvidenceItem

        return AgentFinding(
            finding_id=sf.finding_id,
            verdict="vulnerable",
            confidence=severity_conf.get(sf.severity.upper(), 0.5),
            cwe_id=sf.cwe[0] if sf.cwe else "",
            explanation=sf.message,
            evidence=[
                EvidenceItem(
                    type="code",
                    file=sf.path,
                    lines=[sf.start_line, sf.end_line],
                    content=sf.matched_code,
                )
            ],
            category="sqli" if sf.is_sqli else "sast",
            agent="semgrep",
            file=sf.path,
            line=sf.start_line,
        )

    @staticmethod
    def _heuristic_sql_findings(diffs: list[FileDiff]) -> list[SemgrepFinding]:
        """llm-only baseline: flag added lines that look like SQL sinks."""
        findings: list[SemgrepFinding] = []
        for fd in diffs:
            if not fd.path.endswith(".py"):
                continue
            for hunk in fd.hunks:
                for change in hunk.added_lines:
                    if SQL_SINK_RE.search(change.content):
                        findings.append(
                            SemgrepFinding(
                                rule_id="llm-only.sql-sink-heuristic",
                                path=fd.path,
                                start_line=change.new_lineno or hunk.new_start,
                                end_line=change.new_lineno or hunk.new_start,
                                message=(
                                    "Added line appears to construct or execute "
                                    "SQL; verify it is parameterized."
                                ),
                                severity="WARNING",
                                cwe=["CWE-89"],
                                matched_code=change.content.strip(),
                            )
                        )
                        break  # one heuristic finding per hunk is enough
        return findings
