from __future__ import annotations

import re

from lgtm.config import GRAPH_OUTPUT_CHARS_CEILING

FOOTER = "NOTE: dynamic Python edges are best effort; a missing edge does not establish safety."
_MARKERS = re.compile(r"^(\s*)(\[(?:CODEGRAPH|READ|GREP|END|TRUNCATED|INCOMPLETE)\b|Result of)", re.I)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]")
_CATEGORIES = re.compile(r"[A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)*")
_ABSOLUTE = re.compile(r"^(?:/|//|[a-zA-Z]:/)")


def _field(value: object, limit: int = 160) -> str:
    value = _CONTROL.sub(" ", str(value)).replace('"', "'").replace("]", " ")
    return value[:limit]


def _body(body: str) -> str:
    return "\n".join(_MARKERS.sub(lambda m: m.group(1) + "| " + m.group(2), line) for line in body.splitlines())


def _cap(header: str, body: str, end: str, limit: int, footer: str = "", marker: str = "") -> tuple[str, int]:
    def assemble(retained: str, cut: bool) -> str:
        parts = [header, retained, marker or ("[TRUNCATED]" if cut else ""), footer, end]
        return "\n".join(part for part in parts if part)

    complete = assemble(body, False)
    if len(complete) <= limit:
        return complete, 0
    minimum = assemble("", True)
    if len(minimum) > limit:
        raise ValueError("output limit cannot fit provenance")
    room = limit - len(minimum)
    retained_length = min(len(body), max(0, room - 1))
    return assemble(body[:retained_length], True), len(body) - retained_length


def _root_body(body, root):
    if not root:
        return body
    normalized = str(root).replace("\\", "/").rstrip("/")
    if not normalized:
        return body
    core = r"[\\/]{1,2}".join(re.escape(part) for part in normalized.split("/"))
    flags = re.I if re.match(r"^[a-zA-Z]:", normalized) else 0
    segment = r"""[^\s()\[\]`'",=]"""
    continuation = r"""[A-Za-z0-9_-]|\.[A-Za-z0-9_-]"""
    token = re.compile(
        rf"(?:file:[\\/]{{2,3}})?{core}(?:(?P<rest>[\\/]{segment}*)|(?!{continuation}))",
        flags,
    )

    def redact(match):
        return "<snapshot>" + (match.group("rest") or "").replace("\\", "/")

    return "\n".join(token.sub(redact, line) for line in body.splitlines())


def _categories(incomplete: object) -> str:
    category_source = str(incomplete or "")
    category_match = re.match(_CATEGORIES, category_source)
    if not category_match or len(category_match.group(0)) > 60:
        return "unknown"
    path_suffix = category_source[category_match.end():category_match.end() + 1]
    if path_suffix and path_suffix in "/\\:":
        return "unknown"
    return category_match.group(0)


def render_graph(label, sha, status, body, *, query="", max_chars=GRAPH_OUTPUT_CHARS_CEILING, reason=None, root=None, incomplete=None, truncated=False, omitted_chars=0):
    label, sha, status = _field(label, 20), _field(sha, 40), _field(status, 20)
    limit = min(GRAPH_OUTPUT_CHARS_CEILING, max_chars)
    query = _field(query, 80)
    body = _body(_root_body(body, root))
    if status == "no_match": body = "No matching symbols found."
    elif status == "unavailable": body = "Graph unavailable; use read_file/grep_repo with the same snapshot label."
    try:
        omitted_chars = max(0, int(omitted_chars))
    except (TypeError, ValueError):
        omitted_chars = 0
    categories = _categories(incomplete)
    supplied = omitted_chars
    total = supplied
    has_truncation = bool(truncated or supplied)
    while True:
        attrs = f"snapshot={label} sha={sha} status={status}"
        if reason: attrs += f" reason={_field(reason, 30)}"
        if has_truncation: attrs += " truncated=true"
        if incomplete: attrs += " incomplete=true"
        header = f'[CODEGRAPH {attrs} query="{query}"]'
        footer = (f"NOTE: INCOMPLETE categories={categories}\n" if incomplete else "") + FOOTER
        marker = f"[TRUNCATED omitted_chars={total}]" if has_truncation or total else ""
        result, actual = _cap(header, body, "[END CODEGRAPH]", limit, footer, marker)
        next_total = supplied + actual
        next_truncation = has_truncation or actual > 0
        if next_total == total and next_truncation == has_truncation:
            return result
        total, has_truncation = next_total, next_truncation


def _locator(path):
    path = str(path).replace("\\", "/")
    if _ABSOLUTE.match(path):
        return "<redacted>"
    return _field(path)


def render_read(label, sha, path, start, end, body, max_chars=8000):
    header = f"[READ snapshot={_field(label,20)} sha={_field(sha,40)} path={_locator(path)} lines={start}-{end}]"
    numbered = "\n".join(f"{start + i}: {line}" for i, line in enumerate(_body(body).splitlines()))
    return _cap(header, numbered, "[END READ]", max_chars)[0]


def render_grep(label, sha, pattern, body, max_chars=8000):
    header = f'[GREP snapshot={_field(label,20)} sha={_field(sha,40)} pattern="{_field(pattern,80)}"]'
    body = _body(body)
    locator = re.compile(r"^(?:[a-zA-Z]:[/\\]|[/\\]).*?(?=[:-]\d+[:-])")
    lines = []
    for line in body.splitlines():
        match = locator.match(line)
        lines.append("<redacted>" + line[match.end():] if match else line)
    return _cap(header, "\n".join(lines), "[END GREP]", min(8000, max_chars))[0]
