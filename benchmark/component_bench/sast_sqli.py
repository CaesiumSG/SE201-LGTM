"""SAST SQLi triage benchmark: keep/drop on gold Semgrep hits and distractor hits."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from benchmark.component_bench.outcomes import InfraError, NotScored
from lgtm.agents import registry as prompts
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.agents.tools import AgentToolbox
from lgtm.graph.snapshot import resolve_refs
from lgtm.pipeline import PRODUCTION_REQUEST_FORMAT
from lgtm.sast.semgrep_runner import SemgrepFinding
from lgtm.validation.evidence import EvidenceValidator
from lgtm.validation.judge import judge_candidates


def _commit_excerpt(repo, path, excerpt):
    """Write the excerpt at its real line numbers (blank padding above) and commit it locally."""
    target = Path(repo) / path
    target.parent.mkdir(parents=True, exist_ok=True)
    text = "\n" * (excerpt["start_line"] - 1) + "\n".join(excerpt["lines"]) + "\n"
    target.write_bytes(text.encode("utf-8"))
    git = ["git", "-c", "user.name=bench", "-c", "user.email=bench@localhost", "-c", "commit.gpgsign=false"]
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "excerpt"]):
        subprocess.run([*git, *args], cwd=repo, check=True, capture_output=True)


def run_item(item, ctx):
    fields = dict(item["gold_input"])
    excerpt = fields.pop("excerpt", None)
    finding = SemgrepFinding(**fields)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as empty_repo:
        shas = None
        if excerpt is not None:
            try:
                _commit_excerpt(empty_repo, finding.path, excerpt)
                shas = resolve_refs(empty_repo, "HEAD", "HEAD")
            except (OSError, subprocess.CalledProcessError, ValueError) as exc:
                raise InfraError(f"temp repo setup failed: {exc}") from exc
        agent = SASTTriageAgent(AgentToolbox(empty_repo, "HEAD", config=ctx.config, shas=shas), ctx.config, llm=ctx.llm)
        try:
            result = agent.triage(finding, None)
        finally:
            ctx.metrics.add_agent("sast_triage", agent.run_records, agent.toolbox.build_tools(graph=False))
        if result is not None:
            validator = EvidenceValidator(empty_repo, "HEAD", None, ctx.config, shas=shas)
            validator.validate_all([result])
            judge_candidates(
                [result], validator.read_cited_code, ctx.config, ctx.judge, request_format=PRODUCTION_REQUEST_FORMAT
            )
            if not result.judged:
                raise InfraError(f"judge did not answer: {result.not_judged_reason}")
            return {"kept": result.supported is True}
    message = agent.errors[-1]["message"]
    if message == prompts.entry("shared.unparsable_explanation"):
        return NotScored(message)
    raise InfraError(message)


def score(item, output):
    gold = item["gold"]["keep"]
    kept = output["kept"]
    tp, fp, fn, tn = (float(gold and kept), float(kept and not gold), float(gold and not kept), float(not gold and not kept))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "correct": tp + tn}


def aggregate(units, results_dir):
    total = {k: sum(u["scores"][k] for u in units if u["status"] == "scored") for k in ("tp", "fp", "fn")}
    precision = total["tp"] / (total["tp"] + total["fp"]) if total["tp"] + total["fp"] else 0.0
    recall = total["tp"] / (total["tp"] + total["fn"]) if total["tp"] + total["fn"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}
