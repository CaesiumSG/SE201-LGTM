#!/usr/bin/env python3
"""Fetch the real-world CVE cases and build their base/PR branches.

For every case in ``cases.json`` this script:

1. clones the project (partial clone, no checkout) into the cache directory;
2. checks that every SHA the case names exists, fetching it if necessary;
3. creates local branches ``rw/<case-id>/base`` and ``rw/<case-id>/pr``.

Safe cases are real history: base = parent of the fix, PR = the fix commit.
Vulnerable cases are a *synthetic revert* made of two synthetic commits on
top of the pre-fix commit:

- base: the fix tree with every file the fix touched that is not in
  ``touched_files`` (tests, docs, ...) restored to its pre-fix state, so it
  holds the fixed source but none of the fix's other changes;
- PR: the pre-fix tree, so the PR diff is exactly the reverse of the fix's
  changes to ``touched_files``.

Branches are built with git plumbing, so no working tree is touched, and the
synthetic commits use a fixed identity and date so their SHAs are
reproducible (recorded as ``base_ref`` and ``pr_ref`` in cases.json and
checked on every run).

Usage:
    python benchmark/real_world/fetch.py
    python benchmark/real_world/fetch.py --cases aegra_authz_vulnerable
    python benchmark/real_world/fetch.py --record-refs   # write built SHAs
    python benchmark/real_world/fetch.py --policies      # + policy variants

``--policies`` also builds ``rw/<id>/base-policy`` and ``rw/<id>/pr-policy``:
the same trees plus ``policies/<project>.md`` as ``security-policy.md``, so
the authorization agent can be run with and without a project policy.
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
POLICY_DIR = HERE / "policies"
# Same file name Shoply uses, so LGTM's doc indexer and validator treat it
# exactly like the synthetic benchmark's policy.
POLICY_PATH = "security-policy.md"

# Fixed identity and date: the synthetic commits must hash identically on
# every machine.
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


def changed_files(repo: Path, before: str, after: str) -> list[str]:
    # --no-renames keeps this a pure tree comparison (no blob downloads)
    out = git(repo, "diff", "--name-only", "--no-renames", before, after)
    return sorted(p for p in out.splitlines() if p)


def changed_source_files(repo: Path, before: str, after: str) -> list[str]:
    return [p for p in changed_files(repo, before, after) if not is_test_path(p)]


def write_tree(repo: Path, env: dict[str, str]) -> str:
    # Without --missing-ok, write-tree in a partial clone first downloads every
    # blob the index references that is not in the clone yet.
    return git(repo, "write-tree", "--missing-ok", env=env).strip()


def commit_tree(repo: Path, tree: str, parent: str, message: str,
                env: dict[str, str] | None = None) -> str:
    return git(repo, "commit-tree", "--no-gpg-sign", tree, "-p", parent,
               "-m", message, env={**REVERT_ENV, **(env or {})}).strip()


def build_synthetic_base(repo: Path, case: dict, prefix: str, fix: str,
                         paths: list[str]) -> str:
    """Commit on ``prefix`` with the tree of ``fix`` but ``paths`` as in ``prefix``."""
    with tempfile.TemporaryDirectory(prefix="lgtm-rw-") as tmp:
        env = {"GIT_INDEX_FILE": str(Path(tmp) / "index")}
        git(repo, "read-tree", fix, env=env)
        restore: list[str] = []
        remove: list[str] = []
        for path in paths:
            entry = git(repo, "ls-tree", prefix, "--", path).strip()
            if not entry:  # the fix added this file
                remove.append(path)
                continue
            meta, _ = entry.split("\t", 1)
            mode, _kind, sha = meta.split()
            git(repo, "cat-file", "blob", sha)  # pull the blob into the clone
            restore.append(f"{mode} {sha}\t{path}")
        if restore:
            git(repo, "update-index", "--add", "--index-info", env=env,
                stdin="\n".join(restore) + "\n")
        for path in remove:
            git(repo, "update-index", "--force-remove", "--", path, env=env)
        tree = write_tree(repo, env)
    message = (
        f"Synthetic base for {case['ghsa']}\n\n"
        "Applies the fix's changes to:\n"
        + "".join(f"- {p}\n" for p in case["touched_files"])
    )
    return commit_tree(repo, tree, prefix, message)


def build_synthetic_revert(repo: Path, case: dict, prefix: str,
                           base: str) -> str:
    """Commit on ``base`` whose tree is the pre-fix tree."""
    message = (
        f"Synthetic revert for {case['ghsa']}\n\n"
        "Restores the pre-fix content of:\n"
        + "".join(f"- {p}\n" for p in case["touched_files"])
    )
    return commit_tree(repo, f"{prefix}^{{tree}}", base, message)


def prepare_case(case: dict, repo: Path,
                 check_refs: bool = True) -> tuple[str, str]:
    """Verify one case against the clone, build its branches, return SHAs.

    With ``check_refs`` a synthetic case's recorded ``base_ref``/``pr_ref``
    must match the built SHAs; ``None`` means not recorded yet.
    """
    fixes = case["fix_commits"]
    for sha in fixes:
        ensure_commit(repo, sha, "fix commit")
    for earlier, later in zip(fixes, fixes[1:]):
        if git(repo, "rev-parse", f"{later}^").strip() != earlier:
            raise FetchError(f"fix commits are not a linear chain at {later}")
    prefix = git(repo, "rev-parse", f"{fixes[0]}^").strip()
    fix = fixes[-1]

    all_changed = changed_files(repo, prefix, fix)
    touched = [p for p in all_changed if not is_test_path(p)]
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
        others = [p for p in all_changed if p not in touched]
        base = build_synthetic_base(repo, case, prefix, fix, others)
        pr = build_synthetic_revert(repo, case, prefix, base)
        if changed_files(repo, prefix, base) != touched:
            raise FetchError(
                f"synthetic base differs from the pre-fix tree in "
                f"{changed_files(repo, prefix, base)}, expected {touched}"
            )
        if changed_files(repo, fix, base) != others:
            raise FetchError("synthetic base does not match the fix's source tree")
        if changed_files(repo, base, pr) != touched:
            raise FetchError(
                f"revert diff touches {changed_files(repo, base, pr)}, "
                f"expected {touched}"
            )
        if check_refs:
            for name, built in (("base_ref", base), ("pr_ref", pr)):
                if case[name] is not None and case[name] != built:
                    raise FetchError(f"built {name} {built}, cases.json has {case[name]}")
    else:
        raise FetchError(f"unknown construction {case['construction']!r}")

    for role, sha in (("base", base), ("pr", pr)):
        git(repo, "update-ref", f"refs/heads/{branch(case['id'], role)}", sha)
    return base, pr


def policy_text(case: dict) -> str | None:
    """The project's policy (LF-normalised), or None if it has none.

    Normalising keeps the blob SHA identical whatever core.autocrlf did to
    the working-tree copy.
    """
    path = POLICY_DIR / f"{project_of(case)}.md"
    if not path.is_file():
        return None
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def _commit_with_policy(repo: Path, tree_ish: str, blob: str, parent: str,
                        project: str) -> str:
    with tempfile.TemporaryDirectory(prefix="lgtm-rw-") as tmp:
        env = {"GIT_INDEX_FILE": str(Path(tmp) / "index")}
        git(repo, "read-tree", tree_ish, env=env)
        git(repo, "update-index", "--add", "--cacheinfo",
            f"100644,{blob},{POLICY_PATH}", env=env)
        tree = write_tree(repo, env)
    return commit_tree(repo, tree, parent,
                       f"Add {POLICY_PATH} (access-control policy for {project})")


def prepare_policy(case: dict, repo: Path, base: str, pr: str,
                   text: str) -> tuple[str, str]:
    """Build ``rw/<id>/base-policy`` and ``rw/<id>/pr-policy``.

    Both are the plain base / PR trees plus one extra file, the project's
    policy, so the PR's own diff is unchanged and the only difference from
    the own-docs variant is what the doc index contains.
    """
    for ref in (base, pr):
        if git(repo, "ls-tree", ref, "--", POLICY_PATH).strip():
            raise FetchError(
                f"{POLICY_PATH} already exists at {ref[:8]} in {repo.name}; "
                "the policy would shadow the project's own file"
            )
    blob = git(repo, "hash-object", "-w", "--stdin", stdin=text).strip()
    project = project_of(case)
    base_policy = _commit_with_policy(repo, base, blob, base, project)
    pr_policy = _commit_with_policy(repo, pr, blob, base_policy, project)
    if git(repo, "diff", base, pr) != git(repo, "diff", base_policy, pr_policy):
        raise FetchError("policy variant changed the PR diff")
    for role, sha in (("base-policy", base_policy), ("pr-policy", pr_policy)):
        git(repo, "update-ref", f"refs/heads/{branch(case['id'], role)}", sha)
    return base_policy, pr_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cases", nargs="*", help="subset of case ids")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE,
                        help="clone directory (default: benchmark/real_world/.cache)")
    parser.add_argument("--policies", action="store_true",
                        help="also build rw/<id>/{base,pr}-policy for projects "
                        "that have a file in policies/")
    parser.add_argument("--record-refs", action="store_true",
                        help="write the built synthetic-revert base/PR SHAs into "
                        "cases.json")
    args = parser.parse_args(argv)

    cases = load_cases()
    if args.cases:
        known = {c["id"] for c in cases}
        if set(args.cases) - known:
            parser.error(f"unknown case ids: {sorted(set(args.cases) - known)}")
        cases = [c for c in cases if c["id"] in args.cases]

    failures = 0
    built: dict[str, tuple[str, str]] = {}
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
                base, pr = prepare_case(case, repo, check_refs=not args.record_refs)
                stat = git(repo, "diff", "--shortstat", base, pr).strip()
                policy = policy_text(case) if args.policies else None
                if policy is not None:
                    prepare_policy(case, repo, base, pr, policy)
                    stat += "  +policy variant"
            except FetchError as exc:
                print(f"  FAIL {case['id']}: {exc}", file=sys.stderr)
                failures += 1
                continue
            built[case["id"]] = (base, pr)
            note = ""
            if case["construction"] == "synthetic-revert" and (
                    None in (case["base_ref"], case["pr_ref"])):
                note = "  (refs not recorded yet)"
            print(f"  ok {case['id']}: {base[:8]}..{pr[:8]}  {stat}{note}")

    if args.record_refs and not failures:
        data = json.loads(CASES_FILE.read_text(encoding="utf-8"))
        for case in data["cases"]:
            if case["construction"] == "synthetic-revert" and case["id"] in built:
                case["base_ref"], case["pr_ref"] = built[case["id"]]
        CASES_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print("recorded base_ref/pr_ref values in cases.json")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
