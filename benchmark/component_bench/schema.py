"""Gold label file schema and validation."""

from __future__ import annotations

import json
from pathlib import Path

CASES_PATH = Path(__file__).resolve().parents[1] / "real_world" / "cases.json"
DEVELOPMENT_CASES_PATH = Path(__file__).resolve().parents[1] / "real_prs" / "cases.json"
REQUIRED =("label_id", "case_id", "source", "review_state", "gold_input", "gold")
REVIEW_STATES = ("draft", "approved")


class LabelError(ValueError):
    pass


def _development_case(c: dict) -> dict:
    return {
        "id": c["id"],
        "repo_url": f"https://github.com/{c['repo']}",
        "base_ref": c["introducing"]["base_commit"],
        "pr_ref": c["introducing"]["merge_commit"],
        "category": c["category"],
        "cwe": c["cwe"],
        "description": c["title"],
        "split": "real_prs",
    }


def load_cases() -> list[dict]:
    real_world = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]
    development = json.loads(DEVELOPMENT_CASES_PATH.read_text(encoding="utf-8"))["cases"]
    return real_world + [_development_case(c) for c in development]


def validate_labels(doc: dict, applicable: set[str] | None = None) -> None:
    if not isinstance(doc, dict) or not doc.get("component"):
        raise LabelError("label file needs a component")
    items = doc.get("items")
    if not isinstance(items, list):
        raise LabelError("label file needs an items list")
    case_ids = {c["id"] for c in load_cases()}
    seen: set[str] = set()
    for item in items:
        missing = [f for f in REQUIRED if not isinstance(item, dict) or f not in item]
        if missing:
            raise LabelError(f"label missing fields: {', '.join(missing)}")
        lid, cid = item["label_id"], item["case_id"]
        if lid in seen:
            raise LabelError(f"duplicate label_id {lid}")
        seen.add(lid)
        if cid not in case_ids:
            raise LabelError(f"label {lid}: unknown case_id {cid}")
        if applicable is not None and cid not in applicable:
            raise LabelError(f"label {lid}: case {cid} is outside the component's applicable set")
        if item["review_state"] not in REVIEW_STATES:
            raise LabelError(f"label {lid}: review_state must be draft or approved")
