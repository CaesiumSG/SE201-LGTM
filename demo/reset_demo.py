#!/usr/bin/env python3
"""Put the demo back to how it was before any rehearsal.

Without flags this only PRINTS what it would do. Add --apply to do it.

On GitHub, for the demo repositories (shoply-demo and the three replay repos):
  * closes every open pull request whose branch starts with ``demo/`` or ``lgtm-demo/`` and deletes that branch,
  * deletes any leftover ``demo/`` or ``lgtm-demo/`` branches with no pull request.
It never touches the default branch, ``feature/*``, or the replay source branches (``epic-order``,
``documents-api-v3``, ``ssf-conformance``) that the Workspace tasks replay from, and never reopens or deletes
merged pull requests.

On this machine, for each workspace clone in demo/.data/workspace/:
  * checks out the latest default branch, discards edits and untracked files, deletes local demo branches,
  * forgets the pull request each workspace had pushed (its entry in meta.json).

The dashboard keeps its history (runs and findings are in demo/.data/lgtm.db and are not touched). Restart
``demo/server.py`` afterwards: it holds the workspace state in memory.

    python demo/reset_demo.py            # show the plan
    python demo/reset_demo.py --apply    # do it
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKSPACES = HERE / ".data" / "workspace"
META = WORKSPACES / "meta.json"
PRESETS = HERE / "workspace_presets.json"
REHEARSAL = re.compile(r"^(demo|lgtm-demo)/")


def run(cmd: list[str], check: bool = True) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        sys.exit(f"failed: {' '.join(cmd[:4])} …\n{(p.stderr or p.stdout).strip()[-400:]}")
    return p.stdout


def demo_repos() -> list[str]:
    repos = {p["repo"] for p in json.loads(PRESETS.read_text(encoding="utf-8"))}
    return sorted(repos)


def remote_plan(repo: str) -> tuple[list[dict], list[str]]:
    prs = json.loads(run(["gh", "pr", "list", "--repo", repo, "--state", "open", "--limit", "200",
                          "--json", "number,title,headRefName"]) or "[]")
    prs = [p for p in prs if REHEARSAL.match(p["headRefName"])]
    branches = run(["gh", "api", f"repos/{repo}/branches", "--paginate", "--jq", ".[].name"]).split()
    with_pr = {p["headRefName"] for p in prs}
    return prs, [b for b in branches if REHEARSAL.match(b) and b not in with_pr]


def reset_remote(repo: str, apply: bool) -> None:
    prs, loose = remote_plan(repo)
    print(f"\n{repo}")
    if not prs and not loose:
        print("  nothing to clean on GitHub")
    for p in prs:
        print(f"  close PR #{p['number']} “{p['title']}” and delete branch {p['headRefName']}")
        if apply:
            run(["gh", "pr", "close", str(p["number"]), "--repo", repo, "--delete-branch"])
    for b in loose:
        print(f"  delete leftover branch {b}")
        if apply:
            run(["gh", "api", "-X", "DELETE", f"repos/{repo}/git/refs/heads/{b}"])


def reset_local(repo: str, apply: bool) -> None:
    d = WORKSPACES / repo
    if not (d / ".git").is_dir():
        return
    git = ["git", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential", "-C", str(d)]
    ref = run([*git, "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], check=False).strip()
    default = ref.split("/", 1)[1] if "/" in ref else "main"
    local = [b.strip() for b in run([*git, "branch", "--format=%(refname:short)"], check=False).split()
             if REHEARSAL.match(b.strip())]
    print(f"  local clone {repo}: reset to origin/{default}" + (f", delete {len(local)} local branch(es)" if local else ""))
    if apply:
        run([*git, "fetch", "--quiet", "--prune", "origin"])
        run([*git, "checkout", "--quiet", "--force", "--detach", f"origin/{default}"])
        run([*git, "reset", "--quiet", "--hard"])
        run([*git, "clean", "-fdq"])
        for b in local:
            run([*git, "branch", "-D", b], check=False)


def reset_meta(repos: list[str], apply: bool) -> None:
    try:
        meta = json.loads(META.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    forget = [r for r in repos if r in meta]
    if forget:
        print(f"\nworkspace memory: forget {', '.join(forget)}")
    if apply and forget:
        for r in forget:
            meta.pop(r, None)
        META.write_text(json.dumps(meta, indent=1), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--apply", action="store_true", help="actually do it (the default only prints the plan)")
    ap.add_argument("--local-only", action="store_true", help="only reset the workspace on this machine")
    ap.add_argument("--remote-only", action="store_true", help="only clean up GitHub")
    ap.add_argument("--repo", action="append", help="limit to one repository, e.g. cyberjj999/wagtail-replay (repeatable)")
    args = ap.parse_args()
    repos = args.repo or demo_repos()
    print(("APPLYING" if args.apply else "DRY RUN (nothing is changed; add --apply)") + f" for {len(repos)} repositories")
    if not args.local_only:
        for r in repos:
            reset_remote(r, args.apply)
    if not args.remote_only:
        print("\nthis machine")
        for r in repos:
            reset_local(r, args.apply)
        reset_meta(repos, args.apply)
    print("\n" + ("Done. Restart demo/server.py so it forgets the old workspace state." if args.apply
                  else "That was a dry run. Re-run with --apply to do it."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
