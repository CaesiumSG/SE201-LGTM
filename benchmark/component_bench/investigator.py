"""Investigator benchmark: runs the investigator on each case and writes its sections for offline rating."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from benchmark.component_bench.outcomes import InfraError, NotScored, production_toolbox, remove_index, track
from benchmark.real_world.fetch import project_of
from lgtm.agents.investigator import run_investigator
from lgtm.diff.git_diff import GitError, get_pr_diff
from lgtm.review.sections import _LINE_PREFIX, _SHAPE_ERROR, _hunk_ref

HERE = Path(__file__).resolve().parent
RUBRIC = HERE / "investigator_rubric.md"
CLONE_CACHE = HERE.parent / "real_world" / ".cache"


def load_case_diffs(case: dict, config, results_dir):
    toolbox = production_toolbox(CLONE_CACHE / project_of(case), case, config, results_dir)
    try:
        diffs = get_pr_diff(toolbox.repo, case["base_ref"], case["pr_ref"])
    except GitError as exc:
        toolbox.session.close()
        remove_index(toolbox.index_dir, toolbox.retriever)
        raise InfraError(str(exc)) from exc
    return diffs, toolbox


def _render_hunks(diffs, hunk_ids: list[str]) -> list[dict]:
    refs = {ref.hunk_id: ref for d in diffs for ref in (_hunk_ref(d, i) for i in range(len(d.hunks)))}
    out = []
    for hunk_id in hunk_ids:
        ref = refs.get(hunk_id)
        lines = None if ref is None else [_LINE_PREFIX[c.kind] + c.content for c in ref.changes]
        out.append({"hunk_id": hunk_id, "lines": lines})
    return out


def run_item(item: dict, ctx) -> dict | NotScored:
    case = item["case"]
    diffs, toolbox = load_case_diffs(case, ctx.config, ctx.results_dir)
    track(ctx, toolbox)
    result = run_investigator(diffs, ctx.config, toolbox, ctx.llm)
    if result.run_record is not None:
        ctx.metrics.add_agent("investigator", [result.run_record], toolbox.build_tools())
    if result.status != "ok":
        if result.error == _SHAPE_ERROR:
            return NotScored(result.error)
        raise InfraError(result.error or "investigator failed")
    doc = {
        "case_id": case["id"],
        "diff": "\n".join(d.hunk_text() for d in diffs),
        "sections": [
            {
                "id": s.section_id,
                "title": s.title,
                "rationale": s.rationale,
                "hunks": _render_hunks(diffs, s.hunk_refs),
            }
            for s in result.proposed
        ],
    }
    if not any(h["lines"] is not None for s in doc["sections"] for h in s["hunks"]):
        return NotScored("investigator plan has no section with a valid hunk")
    out = Path(ctx.results_dir) / "investigator"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{case['id']}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    (out / "ratings" / f"{case['id']}.json").unlink(missing_ok=True)
    shutil.copyfile(RUBRIC, out / RUBRIC.name)
    ctx.record = {
        "verdict": "plan",
        "explanation": "\n".join(f"{s['title']}: {s['rationale']}" for s in doc["sections"]),
    }
    return doc


def score(item: dict, output: dict) -> dict:
    return {}


def _read_rating(path: Path, case_id: str) -> float:
    doc = json.loads(path.read_text(encoding="utf-8"))
    rating = doc.get("rating")
    if doc.get("case_id") != case_id:
        raise ValueError(f"{path}: case_id {doc.get('case_id')!r} is not {case_id!r}")
    reason = doc.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(f"{path}: reason is missing or empty")
    if isinstance(rating, bool) or not isinstance(rating, (int, float)) or not 0 <= rating <= 1:
        raise ValueError(f"{path}: rating {rating!r} is not a number from 0.00 to 1.00")
    return rating


def aggregate(units, results_dir) -> dict:
    ratings_dir = Path(results_dir) / "investigator" / "ratings"
    with_result = [u["case_id"] for u in units if u["status"] == "scored"]
    ratings, unrated = {}, []
    for case_id in with_result:
        path = ratings_dir / f"{case_id}.json"
        if path.exists():
            ratings[case_id] = _read_rating(path, case_id)
        else:
            unrated.append(case_id)
    return {
        "ratings": ratings,
        "mean": sum(ratings.values()) / len(ratings) if ratings else None,
        "rated": len(ratings),
        "with_result": len(with_result),
        "unrated": unrated,
        "plan_invalid": [u["case_id"] for u in units if u["status"] == "not_scored"],
    }
