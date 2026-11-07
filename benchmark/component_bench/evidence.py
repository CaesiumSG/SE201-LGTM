"""Evidence validator benchmark: accept/reject verdicts on gold findings and single-fault distractor citations."""

from __future__ import annotations

import subprocess
from pathlib import Path

from benchmark.component_bench import schema
from benchmark.component_bench.outcomes import InfraError
from lgtm.agents.base import EvidenceItem
from lgtm.validation.evidence import EvidenceValidator

CLONE_CACHE = Path(__file__).resolve().parents[1] / "real_world" / ".cache"


def _sha(repo: Path, branch: str) -> str:
    done = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}"],
        cwd=repo, capture_output=True, text=True,
    )
    if done.returncode != 0:
        raise InfraError(f"branch {branch} is missing in {repo}; run benchmark/real_world/fetch.py")
    return done.stdout.strip()


def run_item(item, ctx):
    case = next(c for c in schema.load_cases() if c["id"] == item["case_id"])
    project = case["repo_url"].rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]
    repo = CLONE_CACHE / project
    if not repo.is_dir():
        raise InfraError(f"clone for {project} is missing at {repo}; run benchmark/real_world/fetch.py")
    base, pr = (f"rw/{item['case_id']}/{role}" for role in ("base", "pr"))
    shas = {"base": _sha(repo, base), "pr": _sha(repo, pr)}
    validator = EvidenceValidator(repo, base, config=ctx.config, shas=shas)
    issues = validator.resolution_issues(EvidenceItem(**item["gold_input"]["evidence"]))
    return {
        "accepted": not issues,
        "detail": {"validator_reasons": issues, "stated_reason": item["gold"].get("reason")},
    }


def score(item, output):
    accepted = output["accepted"]
    gold = not item.get("distractor")
    return {
        "tp": int(gold and accepted),
        "fn": int(gold and not accepted),
        "fp": int(not gold and accepted),
        "tn": int(not gold and not accepted),
    }


def aggregate(units, results_dir):
    total = {k: sum(u["scores"][k] for u in units if u["status"] == "scored") for k in ("tp", "fn", "fp", "tn")}
    tp, fn, fp = total["tp"], total["fn"], total["fp"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {**total, "precision": precision, "recall": recall, "f1": f1}
