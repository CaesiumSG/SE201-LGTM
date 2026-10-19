from __future__ import annotations

import re

FOOTER = "NOTE: dynamic Python edges are best effort; a missing edge does not establish safety."
_MARKERS = re.compile(r"^(\s*)(\[(?:CODEGRAPH|READ|GREP|END|TRUNCATED|INCOMPLETE)\b|Result of)", re.I)


def _field(value: object, limit: int = 160) -> str:
    value = str(value).replace('"', "'")
    return re.sub(r"[\x00-\x1f\x7f\]]", " ", value)[:limit]


def _body(body: str) -> str:
    return "\n".join(_MARKERS.sub(lambda m: m.group(1) + "| " + m.group(2), line) for line in body.splitlines())


def _cap(header: str, body: str, end: str, limit: int, footer: str = "") -> str:
    body = _body(body)
    trailer = ("\n" + footer if footer else "") + "\n" + end
    available = limit - len(header) - 1 - len(trailer)
    if available < 0:
        raise ValueError("output limit cannot fit provenance")
    truncated = len(body) > available
    if truncated:
        marker = "[TRUNCATED]"
        available -= len(marker) + 1
        body = body[:max(0, available)].rstrip() + "\n" + marker
    return header + "\n" + body + trailer if body else header + trailer


def render_graph(label, sha, status, body, *, query="", max_chars=6000, reason=None, root=None, incomplete=None, truncated=False, omitted_chars=0):
    label, sha, status = _field(label, 20), _field(sha, 40), _field(status, 20)
    attrs = f"snapshot={label} sha={sha} status={status}"
    if reason: attrs += f" reason={_field(reason, 30)}"
    if truncated: attrs += " truncated=true"
    if incomplete: attrs += " incomplete=true"
    query = _field(query, 80)
    header = f'[CODEGRAPH {attrs} query="{query}"]'
    if root: body = body.replace(str(root), "<snapshot>")
    if status == "no_match": body = "No matching symbols found."
    elif status == "unavailable": body = "Graph unavailable; use read_file/grep_repo with the same snapshot label."
    if incomplete:
        body = f"[INCOMPLETE categories={_field(incomplete, 60)} omitted={max(0, int(omitted_chars))}]\n{body}"
    limit = min(6000, max_chars)
    try:
        result = _cap(header, body, "[END CODEGRAPH]", limit, FOOTER)
        if "[TRUNCATED]" in result and "truncated=true" not in header:
            return render_graph(label, sha, status, body, query=query, max_chars=limit, reason=reason, root=root, incomplete=incomplete, truncated=True, omitted_chars=omitted_chars)
        return result
    except ValueError:
        return _cap(f'[CODEGRAPH snapshot={label} sha={sha} status={status} truncated=true query=""]', "", "[END CODEGRAPH]", limit, FOOTER)


def render_read(label, sha, path, start, end, body, max_chars=8000):
    path = _field(path.replace("\\", "/")).replace("C:/Users/", "<root>/")
    header = f"[READ snapshot={_field(label,20)} sha={_field(sha,40)} path={path} lines={start}-{end}]"
    numbered = "\n".join(f"{start + i}: {line}" for i, line in enumerate(_body(body).splitlines()))
    return _cap(header, numbered, "[END READ]", max_chars)


def render_grep(label, sha, pattern, body, max_chars=8000):
    header = f'[GREP snapshot={_field(label,20)} sha={_field(sha,40)} pattern="{_field(pattern,80)}"]'
    return _cap(header, body, "[END GREP]", max_chars)
