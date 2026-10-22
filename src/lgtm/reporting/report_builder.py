"""Report builder: JSON findings + human-readable Markdown report."""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from lgtm.agents.base import AgentFinding

logger = logging.getLogger(__name__)

VERDICT_EMOJI = {
    "vulnerable": "🔴",
    "possible": "🟠",
    "insufficient_evidence": "⚪",
    "safe": "🟢",
}

VERDICT_ORDER = ["vulnerable", "possible", "insufficient_evidence", "safe"]


@dataclass
class ReviewMetadata:
    repo: str = ""
    base: str = ""
    pr: str = ""
    mode: str = "lgtm"
    model: str = ""
    started_at: str = ""
    duration_seconds: float = 0.0
    semgrep_findings_total: int = 0
    semgrep_findings_in_diff: int = 0
    sast_error: str | None = None
    graph_state: str | None = None
    graph_index_seconds: float | None = None
    base_sha: str = ""
    pr_sha: str = ""
    extra: dict = field(default_factory=dict)
    coverage: dict | None = None
    agent_errors: list[dict[str, str]] = field(default_factory=list)


class ReportBuilder:
    def __init__(self, findings: list[AgentFinding], meta: ReviewMetadata):
        self.findings = sorted(
            findings,
            key=lambda f: VERDICT_ORDER.index(f.verdict) if f.verdict in VERDICT_ORDER else 99,
        )
        self.meta = meta

    # ------------------------------------------------------------------
    def build_json(self) -> dict:
        grounded = [f for f in self.findings if f.evidence_valid]
        return {
            "tool": "lgtm",
            "version": "0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "review": {
                "repo": self.meta.repo,
                "base": self.meta.base,
                "pr": self.meta.pr,
                "mode": self.meta.mode,
                "model": self.meta.model,
                "duration_seconds": round(self.meta.duration_seconds, 2),
                "graph_state": self.meta.graph_state,
                "graph_index_seconds": self.meta.graph_index_seconds,
                "base_sha": self.meta.base_sha,
                "pr_sha": self.meta.pr_sha,
                "coverage": self.meta.coverage,
            },
            "stats": {
                "total_findings": len(self.findings),
                "by_verdict": dict(Counter(f.verdict for f in self.findings)),
                "by_cwe": dict(Counter(f.cwe_id for f in self.findings if f.cwe_id)),
                "by_category": dict(
                    Counter(f.category for f in self.findings if f.category)
                ),
                "evidence_grounded": len(grounded),
                "evidence_grounding_rate": (
                    round(len(grounded) / len(self.findings), 3)
                    if self.findings
                    else None
                ),
                "semgrep_findings_total": self.meta.semgrep_findings_total,
                "semgrep_findings_in_diff": self.meta.semgrep_findings_in_diff,
                "sast_error": self.meta.sast_error,
            },
            "findings": [
                f.model_dump(exclude={"raw_response"}) for f in self.findings
            ],
        }

    # ------------------------------------------------------------------
    def build_markdown(self) -> str:
        lines: list[str] = []
        add = lines.append

        add("# LGTM Security Review Report")
        add("")
        add(f"- **Repository:** `{self.meta.repo}`")
        add(f"- **PR:** `{self.meta.base}` → `{self.meta.pr}`")
        add(f"- **Mode:** {self.meta.mode} | **Model:** {self.meta.model}")
        add(f"- **Duration:** {self.meta.duration_seconds:.1f}s")
        add("")

        # Summary
        add("## Summary")
        add("")
        verdict_counts = Counter(f.verdict for f in self.findings)
        cwe_counts = Counter(f.cwe_id for f in self.findings if f.cwe_id)
        add(f"**{len(self.findings)} finding(s)** after triage and validation.")
        add("")
        add("| Verdict | Count |")
        add("|---|---|")
        for verdict in VERDICT_ORDER:
            if verdict_counts.get(verdict):
                emoji = VERDICT_EMOJI.get(verdict, "")
                add(f"| {emoji} {verdict} | {verdict_counts[verdict]} |")
        add("")
        if cwe_counts:
            add("| CWE | Count |")
            add("|---|---|")
            for cwe, count in sorted(cwe_counts.items()):
                add(f"| {cwe} | {count} |")
            add("")

        # Grounding stats
        add("## Evidence Grounding")
        add("")
        grounded = sum(1 for f in self.findings if f.evidence_valid)
        ungrounded = sum(1 for f in self.findings if f.evidence_valid is False)
        rate = f"{grounded / len(self.findings) * 100:.0f}%" if self.findings else "n/a"
        add(
            f"- {grounded}/{len(self.findings)} findings fully grounded "
            f"({rate}); {ungrounded} with evidence issues."
        )
        add(
            f"- Semgrep: {self.meta.semgrep_findings_in_diff} finding(s) in diff "
            f"(of {self.meta.semgrep_findings_total} total)."
        )
        if self.meta.sast_error:
            add(f"- Semgrep failed: {self.meta.sast_error}")
        add("")

        # Per-finding sections
        add("## Findings")
        add("")
        if not self.findings:
            add("_No findings. The PR passed all configured checks._")
        for i, f in enumerate(self.findings, 1):
            emoji = VERDICT_EMOJI.get(f.verdict, "")
            add(f"### {i}. {emoji} [{f.verdict.upper()}] {f.cwe_id or 'uncategorized'} — `{f.file}:{f.line}`")
            add("")
            add(f"- **Finding ID:** `{f.finding_id}`")
            add(f"- **Agent:** {f.agent} | **Category:** {f.category or 'n/a'}")
            grounding = (
                "✅ grounded"
                if f.evidence_valid
                else ("⚠️ evidence issues" if f.evidence_valid is False else "not validated")
            )
            add(f"- **Evidence validation:** {grounding}")
            add(f"- **Tool calls used:** {f.tool_calls_used}")
            add("")
            add(f"**Explanation:** {f.explanation or '_none provided_'}")
            add("")
            if f.evidence:
                add("**Evidence:**")
                add("")
                for ev in f.evidence:
                    if ev.type == "policy":
                        add(f"- 📄 Policy — `{ev.source or 'unknown'}`:")
                        add(f"  > {ev.content.strip()[:500]}")
                    else:
                        if ev.snapshot:
                            sha = self.meta.pr_sha if ev.snapshot == "pr" else self.meta.base_sha
                            loc = f"[{ev.snapshot} {sha[:7] or 'unknown'}] `{ev.file}`"
                            if ev.lines:
                                loc += f":{ev.lines[0]}-{ev.lines[-1]}"
                        else:
                            loc = f"`{ev.file}`"
                            if ev.lines:
                                loc += f" lines {ev.lines[0]}-{ev.lines[-1]}"
                        add(f"- 💻 Code — {loc}:")
                        add("")
                        add("  ```")
                        for snippet_line in ev.content.strip().splitlines()[:12]:
                            add(f"  {snippet_line}")
                        add("  ```")
                add("")
            if f.evidence_issues:
                add("**Evidence issues:**")
                for issue in f.evidence_issues:
                    add(f"- ⚠️ {issue}")
                add("")
            if f.suggested_fix and f.verdict != "safe":
                add(f"**Suggested fix:** {f.suggested_fix}")
                add("")
            add("---")
            add("")

        add("_Generated by LGTM — findings are advisory; a human reviewer makes the final call._")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    def write(self, output_dir: str | Path) -> tuple[Path, Path]:
        """Write report.json and report.md; returns their paths."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        json_path = out / "report.json"
        md_path = out / "report.md"
        json_path.write_text(
            json.dumps(self.build_json(), indent=2, default=str), encoding="utf-8"
        )
        md_path.write_text(self.build_markdown(), encoding="utf-8")
        logger.info("Wrote %s and %s", json_path, md_path)
        return json_path, md_path
