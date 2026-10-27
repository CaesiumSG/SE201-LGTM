"""Route-decorator gating for the authorization review (checkpoint behaviour).

Until 24 Oct the authz agent only looked at hunks that contained a Flask or
FastAPI route decorator. The real-world CVE evaluation and the field trial
showed that this misses most authorization changes (the check is usually far
from the decorator), so the default is now the investigator-planned section
review. This module keeps the old gating available as ``authz_planner =
"endpoint"`` so the checkpoint numbers can be reproduced and the two can be
compared on the same cases.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, replace

from lgtm.diff.git_diff import FileDiff

logger = logging.getLogger(__name__)

# Flask / FastAPI route decorators
ROUTE_RE = re.compile(
    r"@(?P<obj>[A-Za-z_][\w.]*)\.(?P<verb>route|get|post|put|patch|delete)\s*"
    r"\(\s*['\"](?P<path>[^'\"]+)['\"]"
)


@dataclass
class ChangedEndpoint:
    """A route whose implementation is touched by the PR."""

    file: str
    route_path: str
    http_methods: list[str] = field(default_factory=list)
    decorator_line: int = 0  # new-file line number of the decorator
    endpoint_id: str = ""

    def __post_init__(self) -> None:
        if not self.endpoint_id:
            methods = ",".join(self.http_methods) or "ANY"
            self.endpoint_id = f"authz:{self.file}:{self.route_path}[{methods}]"


def _hunk_has_route(hunk) -> bool:
    return bool(hunk.added_lines) and any(ROUTE_RE.search(c.content) for c in hunk.changes)


def extract_changed_endpoints(diffs: list[FileDiff]) -> list[ChangedEndpoint]:
    """Route definitions in or around the added lines of a PR diff.

    Reported in the review metadata (``endpoints_reviewed``) so a run shows
    how many of its sections the old gating would have reviewed.
    """
    endpoints: list[ChangedEndpoint] = []
    seen: set[str] = set()
    for fd in diffs:
        if fd.status == "deleted" or not fd.path.endswith(".py"):
            continue
        for hunk in fd.hunks:
            if not hunk.added_lines:
                continue
            for change in hunk.changes:
                match = ROUTE_RE.search(change.content)
                if not match:
                    continue
                verb = match.group("verb")
                methods = [verb.upper()] if verb != "route" else []
                if verb == "route":
                    mlist = re.search(r"methods\s*=\s*\[([^\]]*)\]", change.content)
                    if mlist:
                        methods = re.findall(r"['\"](\w+)['\"]", mlist.group(1))
                ep = ChangedEndpoint(
                    file=fd.path,
                    route_path=match.group("path"),
                    http_methods=methods,
                    decorator_line=change.new_lineno or hunk.new_start,
                )
                if ep.endpoint_id not in seen:
                    seen.add(ep.endpoint_id)
                    endpoints.append(ep)
    return endpoints


def gate_to_endpoint_hunks(diffs: list[FileDiff]) -> tuple[list[FileDiff], int]:
    """Keep only Python hunks that contain a route decorator.

    Returns the gated diffs and the number of Python hunks gated out, so the
    coverage record can say how much of the PR the old pipeline never saw.
    """
    kept: list[FileDiff] = []
    gated_out = 0
    for fd in diffs:
        if not fd.path.endswith(".py"):
            kept.append(fd)  # excluded as non_python by the planner anyway
            continue
        if fd.status == "deleted":
            gated_out += len(fd.hunks)
            continue
        hunks = [h for h in fd.hunks if _hunk_has_route(h)]
        gated_out += len(fd.hunks) - len(hunks)
        if hunks:
            kept.append(replace(fd, hunks=hunks))
    logger.info(
        "Endpoint gating: %d hunk(s) with a route decorator kept, %d gated out",
        sum(len(d.hunks) for d in kept if d.path.endswith(".py")),
        gated_out,
    )
    return kept, gated_out
