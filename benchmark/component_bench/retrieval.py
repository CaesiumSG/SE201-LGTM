"""Policy retrieval benchmark: hit@k, recall@k and MRR against gold policy passages, one unit per authz case."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from benchmark.component_bench import schema
from benchmark.component_bench.outcomes import InfraError, NotScored
from lgtm.config import LGTMConfig
from lgtm.rag.indexer import index_repo_docs
from lgtm.rag.retriever import PolicyRetriever as _PolicyRetriever

HERE = Path(__file__).resolve().parent
POLICY_DIR = HERE.parent / "real_world" / "policies"
LABELS = HERE / "labels" / "retrieval.json"
POLICY_NAME = "security-policy.md"


class PolicyRetriever(_PolicyRetriever):
    """Indexes the policy directory under its own `.lgtm/chroma` before serving queries."""

    def __init__(self, repo, config=None):
        config = config or LGTMConfig()
        index_repo_docs(repo, config)
        super().__init__(repo, config)


def _items(labels_dir) -> list[dict]:
    path = Path(labels_dir) / LABELS.name if labels_dir else LABELS
    return json.loads(path.read_text(encoding="utf-8"))["items"]


def _labels(case_id: str, labels_dir=None) -> list[dict]:
    return [i for i in _items(labels_dir) if i["case_id"] == case_id]


def _overlaps(chunk: tuple, gold: dict) -> bool:
    source, start, end = chunk
    return source == gold["source"] and start <= gold["end_line"] and gold["start_line"] <= end


def run_item(item, ctx):
    case = next(c for c in schema.load_cases() if c["id"] == item["case_id"])
    policy = POLICY_DIR / f"{case['repo_url'].rstrip('/').rsplit('/', 1)[-1]}.md"
    if case["category"] != "authz" or not policy.is_file():
        return NotScored(f"{case['id']}: policy retrieval not applicable")
    labels = item.get("labels") or _labels(case["id"], getattr(ctx, "labels_dir", None))
    if not labels:
        return NotScored(f"{case['id']}: no gold policy-passage labels")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        (Path(tmp) / POLICY_NAME).write_text(policy.read_text(encoding="utf-8"), encoding="utf-8")
        try:
            chunks = PolicyRetriever(tmp, ctx.config).retrieve(case["description"], top_k=ctx.config.rag_top_k)
        except Exception as exc:  # noqa: BLE001 - missing index or embedder is an infra failure
            raise InfraError(f"policy retrieval failed: {exc}") from exc
    return {
        "case_id": case["id"],
        "label_ids": [lb["label_id"] for lb in labels],
        "gold": [lb["gold"] for lb in labels],
        "ranked": [(c.source, c.start_line, c.end_line) for c in chunks],
    }


def score(item, output):
    gold, ranked = output["gold"], output["ranked"]
    found = sum(any(_overlaps(c, g) for c in ranked) for g in gold)
    first = next((r for r, c in enumerate(ranked, 1) if any(_overlaps(c, g) for g in gold)), None)
    return {
        "hit_at_k": int(found > 0),
        "recall_at_k": found / len(gold),
        "mrr": 1 / first if first else 0,
    }


def aggregate(units, results_dir, labels_dir=None) -> dict:
    """Draft and approved label counts and the gold label ids behind each case."""
    counts = {"draft": 0, "approved": 0}
    by_case: dict[str, list[str]] = {}
    for i in _items(labels_dir):
        counts[i["review_state"]] += 1
        by_case.setdefault(i["case_id"], []).append(i["label_id"])
    return {"labels": counts, "label_ids": by_case}
