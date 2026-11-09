"""Clone the real_prs development cases and pin their revisions.

Usage: python -m benchmark.component_bench.fetch_real_prs

Shares the clone directory of benchmark/real_world/fetch.py. For each development
case it fetches `base_ref` and `pr_ref` and points `rw/<case id>/base` and
`rw/<case id>/pr` at them. Re-running leaves existing clones and branches in place.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.component_bench import schema  # noqa: E402
from benchmark.real_world import fetch  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    cases = [c for c in schema.load_cases() if c["split"] == "real_prs"]
    failures = 0
    for url in dict.fromkeys(c["repo_url"] for c in cases):
        group = [c for c in cases if c["repo_url"] == url]
        repo = fetch.DEFAULT_CACHE / fetch.project_of(group[0])
        print(f"{repo.name}:")
        try:
            fetch.ensure_clone(url, repo)
        except fetch.FetchError as exc:
            print(f"  FAIL clone: {exc}", file=sys.stderr)
            failures += len(group)
            continue
        for case in group:
            try:
                for role in ("base", "pr"):
                    sha = case[f"{role}_ref"]
                    fetch.ensure_commit(repo, sha, f"{role} commit")
                    fetch.git(repo, "update-ref", f"refs/heads/{fetch.branch(case['id'], role)}", sha)
            except fetch.FetchError as exc:
                print(f"  FAIL {case['id']}: {exc}", file=sys.stderr)
                failures += 1
                continue
            print(f"  ok {case['id']}: {case['base_ref'][:8]}..{case['pr_ref'][:8]}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
