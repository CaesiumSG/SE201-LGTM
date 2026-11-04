from __future__ import annotations

from pathlib import Path

from lgtm.agents.base import AgentFinding
from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import FileDiff
from lgtm.validation.evidence import EvidenceValidator
from lgtm.validation.judge import JudgeCall, judge_candidates


def validate_candidates(
    repo: str | Path,
    candidates: list[AgentFinding],
    base_rev: str,
    pr_rev: str,
    diffs: list[FileDiff],
    config: LGTMConfig | None = None,
    *,
    judge: JudgeCall | None = None,
) -> list[AgentFinding]:
    """Ground then judge candidates for one case repository; the endpoint comes from ``config``."""
    config = config or LGTMConfig()
    validator = EvidenceValidator(
        repo, base_rev, diffs, config, shas={"base": base_rev, "pr": pr_rev}
    )
    grounded = validator.validate_all(candidates)
    return judge_candidates(grounded, validator.read_cited_code, config, judge)


__all__ = ["EvidenceValidator", "judge_candidates", "validate_candidates"]
