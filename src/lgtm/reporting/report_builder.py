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

SUPPORT_EMOJI = {"supported": "🔴", "not real": "🟡", "unsupported": "🟢", "not judged": "⚪"}


def _support_label(finding: AgentFinding) -> str:
    if finding.supported is None:
        return "not judged"
    if finding.supported and finding.kev_verdict == "not_real":
        return "not real"
    return "supported" if finding.supported else "unsupported"


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
        order = list(SUPPORT_EMOJI)
        self.findings = sorted(findings, key=lambda f: order.index(_support_label(f)))
        self.meta = meta

    # ------------------------------------------------------------------
    def build_json(self) -> dict:
        counts = Counter(_support_label(f) for f in self.findings)
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
                "agent_errors": self.meta.agent_errors,
            },
            "stats": {
                "total_findings": len(self.findings),
                "supported": counts["supported"],
                "not_real": counts["not real"],
                "unsupported": counts["unsupported"],
                "not_judged": counts["not judged"],
                "by_cwe": dict(Counter(f.cwe_id for f in self.findings if f.cwe_id)),
                "by_category": dict(
                    Counter(f.category for f in self.findings if f.category)
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
        support_counts = Counter(_support_label(f) for f in self.findings)
        cwe_counts = Counter(f.cwe_id for f in self.findings if f.cwe_id)
        add(f"**{len(self.findings)} finding(s)** after triage and validation.")
        add("")
        add("| Support | Count |")
        add("|---|---|")
        for label, emoji in SUPPORT_EMOJI.items():
            if support_counts[label]:
                add(f"| {emoji} {label} | {support_counts[label]} |")
        add("")
        if cwe_counts:
            add("| CWE | Count |")
            add("|---|---|")
            for cwe, count in sorted(cwe_counts.items()):
                add(f"| {cwe} | {count} |")
            add("")

        add(
            f"- Semgrep: {self.meta.semgrep_findings_in_diff} finding(s) in diff "
            f"(of {self.meta.semgrep_findings_total} total)."
        )
        if self.meta.sast_error:
            add(f"- Semgrep failed: {self.meta.sast_error}")
        add("")

        if self.meta.agent_errors:
            add("## Agent Errors")
            add("")
            for err in self.meta.agent_errors:
                add(f"- `{err.get('source', 'unknown')}`: {err.get('message', '')}")
            add("")

        # Per-finding sections
        add("## Findings")
        add("")
        if not self.findings:
            if self.meta.agent_errors:
                add("_No findings reported; some sections or hits failed (see Agent Errors)._")
            else:
                add("_No findings. The PR passed all configured checks._")
        for i, f in enumerate(self.findings, 1):
            label = _support_label(f)
            add(
                f"### {i}. {SUPPORT_EMOJI[label]} [{label.upper()}] "
                f"{f.cwe_id or 'uncategorized'} — `{f.file}:{f.line}`"
            )
            add("")
            add(f"- **Finding ID:** `{f.finding_id}`")
            if f.severity:
                add(f"- **Severity:** {f.severity}")
            if f.provenance_confidence is not None:
                add(f"- **Provenance confidence:** {f.provenance_confidence:.0%}")
            if f.not_judged_reason:
                add(f"- **Not judged reason:** {f.not_judged_reason}")
            if f.unsupported_reason:
                add(f"- **Unsupported reason:** {f.unsupported_reason}")
            add(f"- **Agent:** {f.agent} | **Category:** {f.category or 'n/a'}")
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
                        if ev.grounded_in_pr is not None:
                            loc += f" (grounded in PR: {'yes' if ev.grounded_in_pr else 'no'})"
                        add(f"- 💻 Code — {loc}:")
                        add("")
                        add("  ```")
                        for snippet_line in ev.content.strip().splitlines()[:12]:
                            add(f"  {snippet_line}")
                        add("  ```")
                add("")
            if f.suggested_fix and label in ("supported", "not judged"):
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
