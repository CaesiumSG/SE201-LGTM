#!/usr/bin/env python3
"""Fetch the real-world CVE cases and build their base/PR branches.

For every case in ``cases.json`` this script:

1. clones the project (partial clone, no checkout) into the cache directory;
2. checks that every SHA the case names exists, fetching it if necessary;
3. creates local branches ``rw/<case-id>/base`` and ``rw/<case-id>/pr``.

Safe cases are real history: base = parent of the fix, PR = the fix commit.
Vulnerable cases are a *synthetic revert*: base = the fix commit, PR = a
commit on top of it that restores only the non-test source files the fix
touched to their pre-fix content. Branches are built with git plumbing, so
no working tree is touched, and the revert commit uses a fixed identity and
date so its SHA is reproducible (it is recorded as ``pr_ref`` in cases.json
and checked on every run).

Usage:
    python benchmark/real_world/fetch.py
    python benchmark/real_world/fetch.py --cases aegra_authz_vulnerable
    python benchmark/real_world/fetch.py --record-pr-refs   # write built SHAs
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES_FILE = HERE / "cases.json"
DEFAULT_CACHE = HERE / ".cache"

# Fixed identity and date: the synthetic revert commit must hash identically
# on every machine.
REVERT_ENV = {
    "GIT_AUTHOR_NAME": "LGTM Bench",
    "GIT_AUTHOR_EMAIL": "bench@lgtm.local",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
    "GIT_COMMITTER_NAME": "LGTM Bench",
    "GIT_COMMITTER_EMAIL": "bench@lgtm.local",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
}


class FetchError(RuntimeError):
    """A case cannot be reproduced; the message says why."""


def load_cases(path: Path = CASES_FILE) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def project_of(case: dict) -> str:
    """Cache directory name: the last segment of the repo URL."""
    return case["repo_url"].rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]


def branch(case_id: str, role: str) -> str:
    """Local branch name for a case; ``role`` is ``base`` or ``pr``."""
    return f"rw/{case_id}/{role}"


def is_test_path(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return (
        any(p in ("tests", "test", "testing") for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def git(
    repo: Path,
    *args: str,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> str:
    # Bytes in and out: text mode would turn the "\n" in --index-info input
    # into "\r\n" on Windows, and git would then see paths ending in "\r".
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        input=stdin.encode("utf-8") if stdin is not None else None,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})},
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise FetchError(f"git {' '.join(args)} failed in {repo.name}:\n{stderr}")
    return result.stdout.decode("utf-8", errors="replace")


def ensure_clone(url: str, dest: Path) -> None:
    if (dest / ".git").is_dir():
        # A killed `git clone` leaves .git behind but never resolves HEAD.
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "--verify", "-q", "HEAD"],
            capture_output=True,
        )
        if head.returncode != 0:
            raise FetchError(
                f"{dest} is an incomplete clone (interrupted?). "
                "Delete it and re-run."
            )
        return
    if dest.exists() and any(dest.iterdir()):
        raise FetchError(
            f"{dest} exists but is not a git clone (interrupted clone?). "
            "Delete it and re-run."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  cloning {url} (blobs fetched on demand) ...", flush=True)
    result = subprocess.run(
        [
            "git", "clone", "--filter=blob:none", "--no-checkout",
            # autocrlf off: the diff must be byte-identical to upstream
            "-c", "core.autocrlf=false", "-c", "core.longpaths=true",
            url, str(dest),
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0:
        raise FetchError(f"git clone {url} failed:\n{result.stderr.strip()}")


def has_commit(repo: Path, sha: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
    ).returncode == 0


def ensure_commit(repo: Path, sha: str, what: str) -> None:
    if has_commit(repo, sha):
        return
    try:
        git(repo, "fetch", "--quiet", "origin", sha)
    except FetchError:
        pass  # reported below with a clearer message
    if not has_commit(repo, sha):
        raise FetchError(
            f"{what} {sha} is missing from {repo.name}: not in the clone, and "
            f"`git fetch origin {sha}` did not retrieve it"
        )


def changed_source_files(repo: Path, before: str, after: str) -> list[str]:
    # --no-renames keeps this a pure tree comparison (no blob downloads)
    out = git(repo, "diff", "--name-only", "--no-renames", before, after)
    return sorted(p for p in out.splitlines() if p and not is_test_path(p))


def build_synthetic_revert(repo: Path, case: dict, prefix: str, fix: str) -> str:
    """Commit on top of ``fix`` restoring ``touched_files`` to ``prefix``."""
    files = case["touched_files"]
    with tempfile.TemporaryDirectory(prefix="lgtm-rw-") as tmp:
        env = {**REVERT_ENV, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        git(repo, "read-tree", fix, env=env)
        restore: list[str] = []
        remove: list[str] = []
        for path in files:
            entry = git(repo, "ls-tree", prefix, "--", path).strip()
            if not entry:  # the fix added this file: the revert deletes it
                remove.append(path)
                continue
            meta, _ = entry.split("\t", 1)
            mode, _kind, sha = meta.split()
            git(repo, "cat-file", "blob", sha)  # pull the blob into the clone
            restore.append(f"{mode} {sha}\t{path}")
        if restore:
            git(repo, "update-index", "--index-info", env=env,
                stdin="\n".join(restore) + "\n")
        for path in remove:
            git(repo, "update-index", "--force-remove", "--", path, env=env)
        tree = git(repo, "write-tree", env=env).strip()
        message = (
            f"Synthetic revert for {case['ghsa']}\n\n"
            "Restores the pre-fix content of:\n"
            + "".join(f"- {p}\n" for p in files)
        )
        return git(repo, "commit-tree", tree, "-p", fix, "-m", message,
                   env=env).strip()


def prepare_case(case: dict, repo: Path) -> tuple[str, str]:
    """Verify one case against the clone, build its branches, return SHAs."""
    fixes = case["fix_commits"]
    for sha in fixes:
        ensure_commit(repo, sha, "fix commit")
    for earlier, later in zip(fixes, fixes[1:]):
        if git(repo, "rev-parse", f"{later}^").strip() != earlier:
            raise FetchError(f"fix commits are not a linear chain at {later}")
    prefix = git(repo, "rev-parse", f"{fixes[0]}^").strip()
    fix = fixes[-1]

    touched = changed_source_files(repo, prefix, fix)
    if touched != sorted(case["touched_files"]):
        raise FetchError(
            f"touched_files mismatch: cases.json lists {sorted(case['touched_files'])}"
            f" but the fix changes {touched}"
        )

    if case["construction"] == "fix-commit":  # safe: real history
        base, pr = prefix, fix
        if (case["base_ref"], case["pr_ref"]) != (base, pr):
            raise FetchError(
                f"base/pr refs in cases.json ({case['base_ref']}, {case['pr_ref']})"
                f" do not match the history ({base}, {pr})"
            )
    elif case["construction"] == "synthetic-revert":
        base = fix
        if case["base_ref"] != base:
            raise FetchError(
                f"base_ref {case['base_ref']} is not the fix commit {base}"
            )
        pr = build_synthetic_revert(repo, case, prefix, fix)
        wrong = git(repo, "diff", "--name-only", "--no-renames", prefix, pr,
                    "--", *case["touched_files"]).split()
        if wrong:
            raise FetchError(f"revert does not match the pre-fix content: {wrong}")
        in_pr = git(repo, "diff", "--name-only", "--no-renames", base, pr).split()
        if sorted(in_pr) != touched:
            raise FetchError(
                f"revert diff touches {sorted(in_pr)}, expected {touched}"
            )
    else:
        raise FetchError(f"unknown construction {case['construction']!r}")

    for role, sha in (("base", base), ("pr", pr)):
        git(repo, "update-ref", f"refs/heads/{branch(case['id'], role)}", sha)
    return base, pr


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cases", nargs="*", help="subset of case ids")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE,
                        help="clone directory (default: benchmark/real_world/.cache)")
    parser.add_argument("--record-pr-refs", action="store_true",
                        help="write the built synthetic-revert SHAs into cases.json")
    args = parser.parse_args(argv)

    cases = load_cases()
    if args.cases:
        known = {c["id"] for c in cases}
        if set(args.cases) - known:
            parser.error(f"unknown case ids: {sorted(set(args.cases) - known)}")
        cases = [c for c in cases if c["id"] in args.cases]

    failures = 0
    built: dict[str, str] = {}
    for url in dict.fromkeys(c["repo_url"] for c in cases):
        group = [c for c in cases if c["repo_url"] == url]
        repo = args.cache / project_of(group[0])
        print(f"{project_of(group[0])}:")
        try:
            ensure_clone(url, repo)
        except FetchError as exc:
            print(f"  FAIL clone: {exc}", file=sys.stderr)
            failures += len(group)
            continue
        for case in group:
            try:
                base, pr = prepare_case(case, repo)
                stat = git(repo, "diff", "--shortstat", base, pr).strip()
            except FetchError as exc:
                print(f"  FAIL {case['id']}: {exc}", file=sys.stderr)
                failures += 1
                continue
            built[case["id"]] = pr
            note = ""
            if case["construction"] == "synthetic-revert":
                if case["pr_ref"] is None:
                    note = "  (pr_ref not recorded yet)"
                elif case["pr_ref"] != pr:
                    print(f"  FAIL {case['id']}: built {pr}, cases.json has "
                          f"{case['pr_ref']}", file=sys.stderr)
                    failures += 1
                    continue
            print(f"  ok {case['id']}: {base[:8]}..{pr[:8]}  {stat}{note}")

    if args.record_pr_refs and not failures:
        data = json.loads(CASES_FILE.read_text(encoding="utf-8"))
        for case in data["cases"]:
            if case["construction"] == "synthetic-revert" and case["id"] in built:
                case["pr_ref"] = built[case["id"]]
        CASES_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print("recorded pr_ref values in cases.json")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
