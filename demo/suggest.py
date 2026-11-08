"""Committable fixes for LGTM's inline comments: GitHub "suggestion" blocks.

For a confirmed finding, Claude on Bedrock is shown the block of lines the pull request added around the flagged
line (with their line numbers) and asked for the smallest replacement that fixes the bug. The answer is used only
if it replaces a contiguous span of lines the pull request itself added, so GitHub can apply it with one click
("Commit suggestion"). Anything else falls back to the prose fix. Spend goes on the shared, capped Bedrock ledger.
"""

from __future__ import annotations

import json
import time

import workspace   # MODEL, prices, ledger

MAX_BLOCK = 40   # added lines shown to the model around the finding


def added_lines(patch: str) -> dict[int, str]:
    """Line number in the new file -> text, for every line the patch adds."""
    out, new = {}, None
    for raw in (patch or "").splitlines():
        if raw.startswith("@@"):
            try:
                new = int(raw.split("+", 1)[1].split(" ", 1)[0].split(",")[0])
            except (IndexError, ValueError):
                new = None
            continue
        if new is None:
            continue
        if raw.startswith("+"):
            out[new] = raw[1:]
            new += 1
        elif raw.startswith("-") or raw.startswith("\\"):
            continue
        else:
            new += 1
    return out


def block_around(added: dict[int, str], line: int) -> list[int]:
    """The contiguous run of added lines that contains (or sits nearest to) the finding's line."""
    if not added:
        return []
    start = min(added, key=lambda n: abs(n - int(line)))
    if abs(start - int(line)) > 3:
        return []
    lo = hi = start
    while lo - 1 in added and start - (lo - 1) < MAX_BLOCK // 2:
        lo -= 1
    while hi + 1 in added and (hi + 1) - lo < MAX_BLOCK:
        hi += 1
    return list(range(lo, hi + 1))


def suggest(key: str | None, budget: float, path: str, added: dict[int, str], finding: dict) -> dict | None:
    """{"start_line", "end_line", "replacement"} for a committable fix, or None when no safe one can be made."""
    if not key or workspace.ledger_total() >= budget:
        return None
    nums = block_around(added, finding.get("line") or 0)
    if not nums:
        return None
    numbered = "\n".join(f"{n}: {added[n]}" for n in nums)
    tool = {"name": "fix", "description": "The minimal replacement that fixes the finding.",
            "input_schema": {"type": "object", "required": ["start_line", "end_line", "replacement"], "properties": {
                "start_line": {"type": "integer", "description": "First line number to replace (from the numbered lines)"},
                "end_line": {"type": "integer", "description": "Last line number to replace, inclusive"},
                "replacement": {"type": "string", "description": "The new code for exactly those lines, with the file's indentation, no line numbers"},
            }}}
    prompt = (f"A security review found this in `{path}`:\n\n{finding.get('cwe')}: {finding.get('explanation', '')[:1500]}\n\n"
              f"Suggested fix (prose): {finding.get('suggested_fix', '')[:800]}\n\n"
              f"These are the lines the pull request added, with their line numbers in the new file:\n```\n{numbered}\n```\n\n"
              "Replace the smallest contiguous span of these numbered lines with fixed code. Keep everything else the same: "
              "same names, same behaviour, same indentation. Only use what the file already imports unless the fix needs nothing new. "
              "Answer by calling the tool.")
    import anthropic

    client = anthropic.AnthropicBedrock(api_key=key, aws_region="us-east-1", timeout=60, max_retries=2)
    started = time.monotonic()
    msg = client.messages.create(model=workspace.MODEL, max_tokens=1200, tools=[tool], tool_choice={"type": "tool", "name": "fix"},
                                 messages=[{"role": "user", "content": prompt}])
    usd = (msg.usage.input_tokens * workspace.PRICE_IN + msg.usage.output_tokens * workspace.PRICE_OUT) / 1e6 * workspace.PRICE_SAFETY
    with workspace._LEDGER_LOCK:
        with workspace.LEDGER.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": workspace.MODEL, "usd": round(usd, 6),
                                 "input": msg.usage.input_tokens, "output": msg.usage.output_tokens,
                                 "seconds": round(time.monotonic() - started, 2), "run": f"demo:suggest:{path}"}) + "\n")
    got = next((b.input for b in msg.content if b.type == "tool_use"), None) or {}
    try:
        a, b, text = int(got["start_line"]), int(got["end_line"]), str(got["replacement"]).rstrip("\n")
    except (KeyError, TypeError, ValueError):
        return None
    # Models often repeat unchanged lines just outside the span they named. GitHub replaces exactly the span, so widen
    # it over those lines (when the pull request added them too); otherwise committing would duplicate them.
    rep = text.split("\n")
    k = 0
    while k + 1 < len(rep) and (b + k + 1) in added and rep[len(rep) - k - 1:] == [added[n] for n in range(b + 1, b + k + 2)]:
        k += 1
    b += k
    k = 0
    while k + 1 < len(rep) and (a - k - 1) in added and rep[:k + 1] == [added[n] for n in range(a - k - 1, a)]:
        k += 1
    a -= k
    span = list(range(a, b + 1))
    if not span or any(n not in added for n in span):      # GitHub only takes a suggestion on lines in the diff
        return None
    # The result of applying it must not repeat a neighbouring line (the duplicate-line failure above).
    before, after = added.get(a - 1), added.get(b + 1)
    if (after is not None and rep[-1] == after and rep[-1].strip()) or (before is not None and rep[0] == before and rep[0].strip()):
        return None
    if text == "\n".join(added[n] for n in span) or "```" in text:
        return None
    return {"start_line": a, "end_line": b, "replacement": text}


def apply_span(lines: list[str], start: int, end: int, replacement: str) -> list[str]:
    """``lines`` with 1-based lines start..end replaced by ``replacement``."""
    return lines[:start - 1] + replacement.split("\n") + lines[end:]


def verify(endpoint: str, finding: dict, path: str, added: dict[int, str], fix: dict) -> tuple[bool, str]:
    """Ask the same evidence judge whether the finding still holds in the fixed code. (fixed?, reason)"""
    import sys
    import urllib.request
    from pathlib import Path

    src = str(Path(__file__).resolve().parent.parent / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    from lgtm.validation.judge import SYSTEM_ONE_PATH, _questions, parse_kev_reply

    nums = block_around(added, finding.get("line") or 0)
    nums = sorted(set(nums) | set(range(fix["start_line"], fix["end_line"] + 1)))
    code = []
    for n in nums:
        if n == fix["start_line"]:
            code.extend(fix["replacement"].split("\n"))
        elif fix["start_line"] < n <= fix["end_line"] or n not in added:
            continue
        else:
            code.append(added[n])
    state = "\n".join([
        f"Claim: {finding.get('explanation', '')}", f"CWE: {finding.get('cwe')}", f"Category: {finding.get('category')}",
        f"Location: {path}:{fix['start_line']}", f"Cited item: {path}:{nums[0]}-{nums[0] + len(code) - 1} at head snapshot",
        "\n".join(code)])
    req = urllib.request.Request(endpoint.rstrip("/") + SYSTEM_ONE_PATH, method="POST", headers={"Content-Type": "application/json"},
                                 data=json.dumps({"model": "jaredpalmer/kev-4b", "state": state, "questions": _questions(True)}).encode())
    with urllib.request.urlopen(req, timeout=90) as r:
        ans = parse_kev_reply(json.loads(r.read()))
    still = ans["supported"] == "yes" and ans["verdict"] == "real"
    return (not still, f"judge on the fixed code: supported={ans['supported']}, verdict={ans['verdict']}")
