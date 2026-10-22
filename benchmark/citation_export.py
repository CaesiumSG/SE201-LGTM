#!/usr/bin/env python3
"""Export the claim-citation units of a recorded run for blind labelling.

One unit per code evidence item of every recorded finding, with the code read
from the cited snapshot of the case repository. No judge output is exported.

Usage:
    python benchmark/citation_export.py RUN_DIR OUT.json --repo CASE_ID=REPO_PATH [--repo ...]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Iterator, Mapping
from pathlib import Path

SNAPSHOT_SHA_KEY = {"base": "base_sha", "pr": "pr_sha"}
REBUILT_COMMITS = {"base": ("main", "base"), "pr": ("pr", "pr change")}
SHA_SHAPE = re.compile(r"[0-9a-fA-F]{4,64}")


def read_records(run_dir: Path) -> list[dict]:
    records = []
    for path in sorted(run_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(record, dict) and "findings" in record and "id" in record:
            records.append(record)
    return records


def unit_id(case_id: str, finding_index: int, evidence_index: int) -> str:
    return f"{case_id}/{finding_index}.{evidence_index}"


def code_items(record: dict) -> Iterator[tuple[str, dict, dict]]:
    """(unit id, finding, code evidence item) in recorded order."""
    for fi, finding in enumerate(record["findings"]):
        for ei, item in enumerate(finding.get("evidence") or []):
            if item.get("type", "code") == "code":
                yield unit_id(record["id"], fi, ei), finding, item


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=30)


def _resolve(repo: Path, sha: str, snapshot: str | None) -> str | None:
    if _git(repo, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0:
        return sha
    # evaluate.py build_case_repo rebuilds with new SHAs: base is main "base", pr is pr "pr change"
    ref, subject = REBUILT_COMMITS.get(snapshot, (None, None))
    if not ref:
        return None
    done = _git(repo, "log", "-1", "--format=%H%n%s", f"refs/heads/{ref}", "--")
    found = done.stdout.decode("utf-8", "replace").splitlines()
    if done.returncode == 0 and len(found) == 2 and found[1] == subject:
        return found[0]
    return None


def _read_lines(repo: Path, sha: str | None, item: dict) -> str | None:
    lines = item.get("lines")
    if not (sha and SHA_SHAPE.fullmatch(sha) and item.get("file") and lines):
        return None
    sha = _resolve(repo, sha, item.get("snapshot"))
    if sha is None:
        return None
    done = subprocess.run(
        ["git", "-C", str(repo), "show", f"{sha}:{item['file']}"],
        capture_output=True, timeout=30,
    )
    if done.returncode != 0:
        return None
    text = done.stdout.decode("utf-8", "replace").splitlines()
    start, end = lines[0], lines[-1]
    if start < 1 or end < start or end > len(text):
        return None
    return "\n".join(text[start - 1 : end])


def export_run(run_dir: Path, repos: Mapping[str, Path], out_path: Path) -> list[dict]:
    units = []
    for record in read_records(Path(run_dir)):
        for uid, finding, item in code_items(record):
            snapshot = item.get("snapshot")
            sha = record.get(SNAPSHOT_SHA_KEY.get(snapshot, ""))
            code = _read_lines(Path(repos[record["id"]]), sha, item)
            unit = {
                "unit_id": uid,
                "claim": finding.get("explanation", ""),
                "file": item.get("file"),
                "lines": item.get("lines"),
                "snapshot": snapshot,
                "code": code or "",
            }
            if code is None:
                unit["unreadable"] = True
            units.append(unit)
    Path(out_path).write_text(json.dumps({"units": units}, indent=2), encoding="utf-8")
    return units


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--repo", action="append", default=[], metavar="CASE_ID=PATH", required=True)
    args = parser.parse_args()
    repos = {cid: Path(path) for cid, _, path in (r.partition("=") for r in args.repo)}
    units = export_run(args.run_dir, repos, args.out)
    print(f"{len(units)} unit(s) written to {args.out}")


if __name__ == "__main__":
    main()
