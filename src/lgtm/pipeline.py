"""Main LGTM pipeline orchestrator.

Stages:
1. Context building — git diff, semgrep scan, RAG retriever.
2. SAST triage — LLM agent triages each semgrep finding in the diff.
3. Authorization review — the investigator groups changed hunks into sections and an LLM agent reviews each one.
4. Evidence validation — every citation is checked against the repo, then the judge rules on each candidate.
5. Reporting — JSON + Markdown.

Supports four modes for benchmarking:
- ``lgtm``: full pipeline (SAST + LLM agents + RAG + tools).
- ``sast-only``: semgrep findings reported directly, no LLM (Baseline A).
- ``llm-only``: one tool-free LLM call over the diff — no SAST output, no
  RAG, no tools (Baseline B, as defined in the proposal).
- ``lgtm-no-sast``: ablation — the LGTM agents with RAG and tools, but a
  regex SQL-sink detector replaces Semgrep. Isolates what Semgrep adds.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from lgtm.agents.authz_reviewer import AuthzReviewerAgent
from lgtm.agents.base import AgentFinding, RunRecord, build_llm
from lgtm.agents.investigator import run_investigator
from lgtm.analysis.facts import sql_sink_facts
from lgtm.agents.plain_reviewer import PlainLLMReviewer
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox, relative_path
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff, get_pr_diff
from lgtm.rag.retriever import PolicyRetriever
from lgtm.review.coverage import (
    InvestigatorInput,
    InvestigatorStatus,
    SectionResult,
    build_coverage,
)
from lgtm.review.dedup import dedup_findings
from lgtm.review.endpoints import extract_changed_endpoints, gate_to_endpoint_hunks
from lgtm.review.sections import ScanPlan, Section, plan_sections
from lgtm.reporting.report_builder import ReportBuilder, ReviewMetadata
from lgtm.sast.semgrep_runner import (
    SemgrepError,
    SemgrepFinding,
    filter_to_diff,
    run_semgrep,
)
from lgtm.validation.evidence import EvidenceValidator
from lgtm.validation.judge import JudgeCall, judge_candidates

if TYPE_CHECKING:
    from lgtm.graph.session import GraphSession

logger = logging.getLogger(__name__)

PRODUCTION_REQUEST_FORMAT = "current"

# Heuristic SQL sink detector for the lgtm-no-sast ablation
SQL_SINK_RE = re.compile(
    r"\.(execute|executemany|exec_driver_sql)\s*\(|text\s*\(|"
    r"\b(SELECT|INSERT|UPDATE|DELETE)\b.*\b(FROM|INTO|SET|WHERE)\b",
    re.IGNORECASE,
)


MITIGATED_MODES = ("lgtm", "lgtm-no-sast")


def mitigations_apply(mode: str, config: LGTMConfig) -> dict[str, bool]:
    """Which prompt-injection mitigations are active for this mode.

    The mitigations are part of LGTM, so they apply to ``lgtm`` and its
    ``lgtm-no-sast`` ablation. The ``llm-only`` baseline is the bare model
    on the raw diff (proposal, Baseline B) and must stay that way for the
    comparison to mean anything; ``sast-only`` never prompts a model.
    """
    active = mode in MITIGATED_MODES
    return {
        "strip_comments": active and config.strip_comments,
        "detect_prompt_injection": active and config.detect_prompt_injection,
    }


@dataclass
class ReviewResult:
    findings: list[AgentFinding]
    meta: ReviewMetadata
    json_path: Path | None = None
    md_path: Path | None = None
    diffs: list[FileDiff] = field(default_factory=list)
    run_records: list[RunRecord] = field(default_factory=list)


@dataclass
class _SectionStage:
    findings: list[AgentFinding]
    plan: ScanPlan
    results: dict[str, SectionResult]
    investigator_status: InvestigatorStatus
    investigator_error: str | None
    investigator_input: InvestigatorInput
    investigator_tool_calls: int
    errors: list[dict[str, str]]
    run_records: list[RunRecord] = field(default_factory=list)


class ReviewPipeline:
    def __init__(
        self,
        repo: str | Path,
        config: LGTMConfig | None = None,
        llm=None,
        judge: JudgeCall | None = None,
    ):
        self.repo = Path(repo).resolve()
        self.config = config or LGTMConfig()
        self._llm = llm  # injectable for tests
        self._judge = judge  # request -> answer mapping; defaults to the HTTP client

    # ------------------------------------------------------------------
    def run(
        self, base: str, pr: str, output_dir: str | Path | None = None
    ) -> ReviewResult:
        if self.config.mode not in ("lgtm", "lgtm-no-sast"):
            return self._review(base, pr, base, pr, output_dir)

        # Lazy import: sast-only and llm-only do not load lgtm.graph.
        from lgtm.graph import session as graph_session
        from lgtm.graph import snapshot as graph_snapshot

        shas = graph_snapshot.resolve_refs(self.repo, base, pr)
        session = None
        if self.config.graph_enabled:
            session = graph_session.GraphSession(self.repo, shas, self.config)
        try:
            return self._review(
                base,
                pr,
                shas["base"],
                shas["pr"],
                output_dir,
                shas=shas,
                session=session,
            )
        finally:
            if session is not None:
                session.close()

    def _review(
        self,
        base: str,
        pr: str,
        base_rev: str,
        pr_rev: str,
        output_dir: str | Path | None,
        shas: Mapping[str, str] | None = None,
        session: GraphSession | None = None,
    ) -> ReviewResult:
        start = time.monotonic()
        mode = self.config.mode
        logger.info(
            "Starting LGTM review (%s): %s..%s in %s", mode, base, pr, self.repo
        )
        # Resolved SHAs pin Git reads against moving refs.

        # ---- Stage 1: context ----------------------------------------
        scan_diffs = get_pr_diff(self.repo, base_rev, pr_rev, self.config.git_timeout)
        diffs = [d for d in scan_diffs if d.status != "deleted"]
        logger.info("PR changes %d file(s)", len(diffs))

        retriever: PolicyRetriever | None = None
        if mode in ("lgtm", "lgtm-no-sast"):
            retriever = PolicyRetriever(self.repo, self.config)
            if not retriever.is_available():
                logger.warning(
                    "RAG index not found — run `lgtm index` first. "
                    "Agents will rely on code evidence only."
                )
                retriever = None

        semgrep_total = 0
        semgrep_in_diff: list[SemgrepFinding] = []
        sast_error: str | None = None
        if mode in ("lgtm", "sast-only"):
            semgrep_in_diff, semgrep_total, sast_error = self._run_sast(
                diffs, base_rev, pr_rev
            )

        meta = ReviewMetadata(
            repo=str(self.repo),
            base=base,
            pr=pr,
            mode=mode,
            model=self.config.ollama_model if mode != "sast-only" else "none",
            semgrep_findings_total=semgrep_total,
            semgrep_findings_in_diff=len(semgrep_in_diff),
            sast_error=sast_error,
            base_sha=base_rev if shas is not None else "",
            pr_sha=pr_rev if shas is not None else "",
        )

        findings: list[AgentFinding] = []
        section_stage: _SectionStage | None = None

        from lgtm.diff.sanitizer import detect_prompt_injections, sanitize_diffs

        mitigate = mitigations_apply(mode, self.config)
        llm_diffs = sanitize_diffs(diffs) if mitigate["strip_comments"] else diffs
        llm_scan_diffs = (
            sanitize_diffs(scan_diffs) if mitigate["strip_comments"] else scan_diffs
        )

        if mode == "sast-only":
            findings = [self._sast_finding_to_agent_finding(f) for f in semgrep_in_diff]
        elif mode == "llm-only":
            llm = self._llm or build_llm(self.config)
            findings = PlainLLMReviewer(self.config, llm).review(llm_diffs)
        else:
            llm = self._llm or build_llm(self.config)
            toolbox = AgentToolbox(
                self.repo, base_rev, retriever, self.config, shas=shas, session=session
            )
            diff_by_path = {d.path: d for d in llm_diffs}

            # ---- Stage 2: SAST triage --------------------------------
            if mode == "lgtm-no-sast":
                semgrep_in_diff = self._heuristic_sql_findings(diffs)
                logger.info(
                    "lgtm-no-sast mode: %d heuristic SQL sink(s) to triage",
                    len(semgrep_in_diff),
                )
            triage_agent = SASTTriageAgent(toolbox, self.config, llm)
            for sf in semgrep_in_diff:
                fd = diff_by_path.get(sf.path) or self._match_diff(sf.path, llm_diffs)
                facts = ""
                if self.config.static_facts:
                    facts = sql_sink_facts(self._pr_source(pr_rev, sf.path), sf.start_line)
                finding = triage_agent.triage(sf, fd, facts)
                if finding is None:
                    continue
                finding.pr_graph_ok = toolbox.graph_stamp("pr")
                findings.append(finding)
            meta.agent_errors.extend({**e, "stage": "sast_triage"} for e in triage_agent.errors)

            # ---- Stage 3: authorization review -----------------------
            section_stage = self._review_sections(
                llm_scan_diffs, semgrep_in_diff, toolbox, llm
            )
            findings.extend(section_stage.findings)
            meta.agent_errors.extend(section_stage.errors)
            meta.endpoints_reviewed = len(extract_changed_endpoints(diffs))
            meta.graph_state = toolbox.graph_state() if session is not None else "disabled"
            meta.graph_index_seconds = (
                round(session.init_seconds, 2) if session is not None else 0.0
            )

        if mitigate["detect_prompt_injection"]:
            findings.extend(detect_prompt_injections(diffs))

        # ---- Stage 4: evidence validation ----------------------------
        validator = EvidenceValidator(
            self.repo,
            base_rev,
            diffs,
            self.config,
            shas={"base": base_rev, "pr": pr_rev} if shas is not None else None,
        )
        findings = validator.validate_all(findings)
        if mode in ("lgtm", "lgtm-no-sast"):
            findings = judge_candidates(
                findings,
                validator.read_cited_code,
                self.config,
                self._judge,
                request_format=PRODUCTION_REQUEST_FORMAT,
            )
        if section_stage is not None:
            by_id = {f.finding_id: f.supported for f in findings}
            for result in section_stage.results.values():
                result.supported = [by_id.get(i) for i in result.finding_ids]
            meta.coverage = build_coverage(
                section_stage.plan,
                investigator_status=section_stage.investigator_status,
                investigator_error=section_stage.investigator_error,
                investigator_input=section_stage.investigator_input,
                investigator_tool_calls=section_stage.investigator_tool_calls,
                results=section_stage.results,
            )

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
            run_records=section_stage.run_records if section_stage is not None else [],
        )

    # ------------------------------------------------------------------
    def _review_sections(
        self,
        scan_diffs: list[FileDiff],
        semgrep_in_diff: list[SemgrepFinding],
        toolbox: AgentToolbox,
        llm,
    ) -> _SectionStage:
        investigator_status: InvestigatorStatus = "skipped"
        investigator_input: InvestigatorInput = "none"
        investigator_error: str | None = None
        investigator_tool_calls = 0
        proposed = None
        run_records: list[RunRecord] = []
        if self.config.authz_planner == "endpoint":
            # Checkpoint-era gating: review only hunks that carry a route
            # decorator, one section per file, no investigator.
            gated, gated_out = gate_to_endpoint_hunks(scan_diffs)
            plan = plan_sections(gated, None, self.config)
            plan.planner = "endpoint"
            plan.fallback_reason = "endpoint gating"
            plan.hunks_gated = gated_out
        else:
            if any(d.path.endswith(".py") and d.hunks for d in scan_diffs):
                investigation = run_investigator(scan_diffs, self.config, toolbox, llm)
                investigator_status = investigation.status
                investigator_input = investigation.input_mode
                investigator_error = investigation.error
                investigator_tool_calls = investigation.tool_calls
                proposed = investigation.proposed
                run_records.append(investigation.run_record)
            plan = plan_sections(scan_diffs, proposed, self.config)

        authz_agent = AuthzReviewerAgent(toolbox, self.config, llm)
        results: dict[str, SectionResult] = {}
        section_findings: list[AgentFinding] = []
        for section in plan.sections:
            scoped = replace(
                section,
                context=[p for p in section.context if self._inside_snapshot(p.path)],
            )
            notes = "\n".join(
                f"- {sf.rule_id} at {sf.path}:{sf.start_line}: {sf.message}"
                for sf in semgrep_in_diff
                if sf.path in scoped.files
            )
            seen_errors = len(authz_agent.errors)
            reviewed = authz_agent.review_section(scoped, notes)
            error = authz_agent.errors[seen_errors:]
            for finding in reviewed:
                finding.pr_graph_ok = toolbox.graph_stamp("pr")
            results[section.section_id] = self._section_result(
                reviewed, error[0]["message"] if error else None
            )
            section_findings.extend(reviewed)

        return _SectionStage(
            findings=dedup_findings(section_findings),
            errors=authz_agent.errors,
            plan=plan,
            results=results,
            investigator_status=investigator_status,
            investigator_error=investigator_error,
            investigator_input=investigator_input,
            investigator_tool_calls=investigator_tool_calls,
            run_records=run_records + authz_agent.run_records,
        )

    @staticmethod
    def _section_result(findings: list[AgentFinding], error: str | None) -> SectionResult:
        return SectionResult(
            status="failed" if error else "completed",
            supported=[f.supported for f in findings],
            finding_ids=[f.finding_id for f in findings],
            error=error,
        )

    @staticmethod
    def _inside_snapshot(path: str) -> bool:
        if relative_path(path) is None:
            return False
        # Windows strips trailing dots and spaces from components, so these resolve to "..".
        return not any(re.fullmatch(r"\.\.[. ]*", part) for part in re.split(r"[\\/]", path))

    # ------------------------------------------------------------------
    def _run_sast(
        self, diffs: list[FileDiff], base: str, pr: str
    ) -> tuple[list[SemgrepFinding], int, str | None]:
        """Run semgrep on the PR version of the changed python files.

        The repo's working tree may be on any branch, so the changed files
        are materialized at the PR ref into a temp directory and scanned
        there (scanning only — PR code is never executed).
        """
        import tempfile

        from lgtm.diff.git_diff import GitError, read_file_at_ref

        changed_files = [d.path for d in diffs if d.path.endswith(".py")]
        if not changed_files:
            return [], 0, None
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
            return [], 0, str(exc)
        in_diff = filter_to_diff(all_findings, diffs)
        return in_diff, len(all_findings), None

    def _pr_source(self, pr: str, path: str) -> str:
        """PR-version file content for static analysis (parsed, never run)."""
        from lgtm.diff.git_diff import GitError, read_file_at_ref

        try:
            return read_file_at_ref(self.repo, pr, path, self.config.git_timeout)
        except GitError:
            return ""

    @staticmethod
    def _match_diff(path: str, diffs: list[FileDiff]) -> FileDiff | None:
        for d in diffs:
            if d.path.endswith(path) or path.endswith(d.path):
                return d
        return None

    @staticmethod
    def _sast_finding_to_agent_finding(sf: SemgrepFinding) -> AgentFinding:
        """sast-only baseline: report semgrep findings directly."""
        from lgtm.agents.base import EvidenceItem

        return AgentFinding(
            finding_id=sf.finding_id,
            verdict="vulnerable",
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
        """lgtm-no-sast ablation: flag added lines that look like SQL sinks."""
        findings: list[SemgrepFinding] = []
        for fd in diffs:
            if not fd.path.endswith(".py"):
                continue
            for hunk in fd.hunks:
                for change in hunk.added_lines:
                    if SQL_SINK_RE.search(change.content):
                        findings.append(
                            SemgrepFinding(
                                rule_id="lgtm-no-sast.sql-sink-heuristic",
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
