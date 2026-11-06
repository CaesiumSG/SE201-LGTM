"""SAST SQLi triage benchmark: keep/drop after the triage agent and Kev judge on gold Semgrep hits."""

from __future__ import annotations

from pathlib import Path

from benchmark.component_bench.outcomes import InfraError, NotScored, production_toolbox, track
from benchmark.component_bench.schema import load_cases
from benchmark.real_world.fetch import project_of
from lgtm.agents.sast_triage import SASTTriageAgent
from lgtm.diff.git_diff import GitError, get_pr_diff
from lgtm.diff.sanitizer import sanitize_diffs
from lgtm.pipeline import PRODUCTION_REQUEST_FORMAT, ReviewPipeline
from lgtm.sast.semgrep_runner import SemgrepFinding
from lgtm.validation.evidence import EvidenceValidator
from lgtm.validation.judge import judge_candidates

CLONE_CACHE = Path(__file__).resolve().parents[1] / "real_world" / ".cache"


def _judge_explanation(result) -> str:
    if result.unsupported_reason:
        return result.unsupported_reason
    return (
        f"supported={result.supported}; verdict={result.kev_verdict}; severity={result.kev_severity}; "
        f"provenance_confidence={result.provenance_confidence}"
    )


def run_item(item, ctx):
    fields = {k: v for k, v in item["gold_input"].items() if k != "excerpt"}
    finding = SemgrepFinding(**fields)
    case = next(c for c in load_cases() if c["id"] == item["case_id"])
    toolbox = production_toolbox(CLONE_CACHE / project_of(case), case, ctx.config, ctx.results_dir)
    track(ctx, toolbox)
    try:
        diffs = [d for d in get_pr_diff(toolbox.repo, case["base_ref"], case["pr_ref"]) if d.status != "deleted"]
    except GitError as exc:
        raise InfraError(str(exc)) from exc
    file_diff = ReviewPipeline._match_diff(finding.path, sanitize_diffs(diffs))
    agent = SASTTriageAgent(toolbox, ctx.config, llm=ctx.llm)
    try:
        result = agent.triage(finding, file_diff)
    finally:
        ctx.metrics.add_agent("sast_triage", agent.run_records, toolbox.build_tools(graph=False))
    if result is None:
        error = agent.errors[-1]
        if error["kind"] == "unparsable":
            return NotScored(error["message"])
        raise InfraError(error["message"])
    stages = {"triage": {"evidence": len(result.evidence), "explanation": result.explanation}}
    if result.evidence:
        validator = EvidenceValidator(
            toolbox.repo, case["base_ref"], diffs, ctx.config, shas=toolbox.shas
        )
        validator.validate_all([result])
        judge_candidates(
            [result], validator.read_cited_code, ctx.config, ctx.judge, request_format=PRODUCTION_REQUEST_FORMAT
        )
        if not result.judged:
            raise InfraError(f"judge did not answer: {result.not_judged_reason}")
        stages["judge"] = {
            "decision": "keep" if result.supported is True else "drop",
            "explanation": _judge_explanation(result),
        }
    else:
        stages["judge"] = {"decision": "not_run", "explanation": "triage cited no evidence"}
    kept = stages["judge"]["decision"] == "keep"
    ctx.record = {
        "verdict": "keep" if kept else "drop",
        "explanation": result.explanation,
        "stages": stages,
    }
    return {
        "kept": kept,
        "stages": stages,
        "detail": {"gold_keep": item["gold"]["keep"]},
    }


def score(item, output):
    gold = item["gold"]["keep"]
    kept = output["kept"]
    tp, fp, fn, tn = (float(gold and kept), float(kept and not gold), float(gold and not kept), float(not gold and not kept))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "correct": tp + tn}


def aggregate(units, results_dir):
    total = {k: sum(u["scores"][k] for u in units if u["status"] == "scored") for k in ("tp", "fp", "fn")}
    tp, fp, fn = total["tp"], total["fp"], total["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}
