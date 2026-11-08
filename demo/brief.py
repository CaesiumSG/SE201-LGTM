"""Readable briefs for findings: a one-line headline and four short facts, written from the agent's explanation.

The agent's full explanation is what the judge saw and what the evaluation scored, so it is never changed; the brief
is shown on top of it, and the full text stays one click away. Claude on Bedrock writes each brief once (about a
cent), restating only what the explanation says; briefs are cached in the dashboard database.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import workspace   # MODEL, prices, spend ledger

FIELDS = {
    "headline": "What is wrong, as a plain sentence a non-expert understands, at most 12 words. Name the input and where "
                "it ends up; no jargon such as 'unsanitized' or 'interpolates'. Example: \"`name` from the URL goes "
                "straight into the SQL query.\"",
    "where": "File:line and the function, at most 10 words. Example: \"`app/routes/users.py:66`, in `search_users()`\"",
    "impact": "What an attacker can concretely do, at most 16 words, no example payloads. Example: \"A manager can read "
              "every user's email and password hash.\"",
    "breaks": "The project's own policy or documented rule it breaks (a file such as security-policy.md and its section), "
              "at most 10 words; never a CWE name. Empty string when the explanation names no such rule. "
              "Example: \"security-policy.md §5: SQL must use bound parameters\"",
    "fix": "The fix, at most 10 words. Example: \"Pass `name` as a bound parameter.\"",
    "fix_code": "The corrected code only, as it would appear in the file: the one to five lines that change, no "
                "comments, no prose, no backticks or code fences. Copy it from the suggested fix with the same names "
                "and placeholders, only reformatted; empty string when "
                "the suggested fix gives no code.",
}


def write(key: str | None, budget: float, f: dict) -> dict | None:
    if not key or workspace.ledger_total() >= budget or not (f.get("explanation") or "").strip():
        return None
    tool = {"name": "brief", "description": "A short, readable brief of the finding.",
            "input_schema": {"type": "object", "required": list(FIELDS),
                             "properties": {k: {"type": "string", "description": v} for k, v in FIELDS.items()}}}
    prompt = (f"Rewrite this security finding for a busy developer. Use only facts stated below; do not add new claims. "
              f"Plain English, short phrases, code names in backticks.\n\nIssue: {f.get('cwe')} at {f.get('file')}:{f.get('line')}\n"
              f"Explanation:\n{f['explanation'][:4000]}\n\nSuggested fix: {(f.get('suggested_fix') or '')[:1000]}")
    import anthropic

    client = anthropic.AnthropicBedrock(api_key=key, aws_region="us-east-1", timeout=60, max_retries=2)
    started = time.monotonic()
    msg = client.messages.create(model=workspace.MODEL, max_tokens=500, tools=[tool], tool_choice={"type": "tool", "name": "brief"},
                                 messages=[{"role": "user", "content": prompt}])
    usd = (msg.usage.input_tokens * workspace.PRICE_IN + msg.usage.output_tokens * workspace.PRICE_OUT) / 1e6 * workspace.PRICE_SAFETY
    with workspace._LEDGER_LOCK:
        with workspace.LEDGER.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": workspace.MODEL, "usd": round(usd, 6),
                                 "input": msg.usage.input_tokens, "output": msg.usage.output_tokens,
                                 "seconds": round(time.monotonic() - started, 2), "run": "demo:brief"}) + "\n")
    got = next((b.input for b in msg.content if b.type == "tool_use"), None) or {}
    out = {k: str(got.get(k) or "").strip() for k in FIELDS}
    out["fix_code"] = out["fix_code"].strip("`").removeprefix("python\n").strip()
    return out if out["headline"] else None


def briefs(store, key: str | None, budget: float, items: dict[str, dict]) -> dict[str, dict]:
    """Briefs for {cache key: finding}, writing the missing ones (in parallel) and caching them."""
    if not items:
        return {}
    marks = ",".join("?" * len(items))
    have = {r["key"]: json.loads(r["body"]) for r in store.q(f"SELECT key, body FROM finding_briefs WHERE key IN ({marks})", list(items))}
    # Briefs written before fix_code existed are rewritten once when the finding has a suggested fix.
    todo = {k: f for k, f in items.items() if k not in have or ("fix_code" not in have[k] and (f.get("suggested_fix") or "").strip())}
    if todo:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for k, b in zip(todo, pool.map(lambda f: _safe(key, budget, f), todo.values())):
                if b:
                    store.upsert("finding_briefs", {"key": k, "body": json.dumps(b), "created_at": time.strftime("%Y-%m-%dT%H:%M:%S")}, key="key")
                    have[k] = b
    return have


def _safe(key, budget, f):
    try:
        return write(key, budget, f)
    except Exception:  # noqa: BLE001 - without a brief, the full explanation is shown as before
        return None


FENCE = {".py": "python", ".js": "javascript", ".ts": "typescript", ".go": "go", ".java": "java", ".rb": "ruby", ".php": "php"}


def fix_markdown(b: dict | None, path: str) -> str:
    """The suggested fix for a GitHub comment: one sentence and the corrected code, or "" without a brief."""
    if not b or not b.get("fix"):
        return ""
    lang = FENCE.get(Path(path or "").suffix, "")
    return f"**Suggested fix:** {b['fix']}" + (f"\n\n```{lang}\n{b['fix_code']}\n```" if b.get("fix_code") else "")


def markdown(b: dict) -> str:
    """The brief for a GitHub comment."""
    rows = [("Where", b.get("where")), ("Impact", b.get("impact")), ("Breaks", b.get("breaks")), ("Fix", b.get("fix"))]
    return "\n".join([f"**{b['headline']}**", ""] + [f"- **{k}:** {v}" for k, v in rows if v])
