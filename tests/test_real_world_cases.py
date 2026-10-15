"""No-network guards for the real-world CVE benchmark.

``cases.json`` must stay internally consistent (fields, CWEs, SHAs, twins),
and ``fetch.py``'s branch construction is exercised on a throwaway local
repo so the synthetic-revert logic is tested without cloning anything.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

RW = Path(__file__).resolve().parent.parent / "benchmark" / "real_world"

_spec = importlib.util.spec_from_file_location("rw_fetch", RW / "fetch.py")
fetch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch)

CASES = json.loads((RW / "cases.json").read_text(encoding="utf-8"))["cases"]
SHA = re.compile(r"^[0-9a-f]{40}$")
REQUIRED = {
    "id", "category", "split", "origin", "expected_verdict", "cwe", "file",
    "vulnerable_lines", "description", "repo_url", "ghsa", "cve",
    "fix_commits", "base_ref", "pr_ref", "construction", "touched_files",
    "notes",
}
CWES = {"sqli": {"CWE-89"}, "authz": {"CWE-639", "CWE-862", "CWE-863"}}


class TestCasesJson:
    def test_required_fields_and_types(self):
        for c in CASES:
            assert REQUIRED <= set(c), f"{c.get('id')}: missing {REQUIRED - set(c)}"
            assert c["split"] == "real_world" and c["origin"] == "cve", c["id"]
            assert c["expected_verdict"] in ("vulnerable", "safe"), c["id"]
            assert c["construction"] in ("fix-commit", "synthetic-revert"), c["id"]
            assert c["touched_files"] and c["file"] in c["touched_files"], c["id"]
            assert not any(fetch.is_test_path(p) for p in c["touched_files"]), c["id"]

    def test_ids_unique(self):
        ids = [c["id"] for c in CASES]
        assert len(ids) == len(set(ids))

    def test_category_and_cwe_valid(self):
        for c in CASES:
            assert c["category"] in CWES, c["id"]
            assert c["cwe"] in CWES[c["category"]], c["id"]

    def test_identifiers_well_formed(self):
        for c in CASES:
            assert re.fullmatch(r"GHSA(-[2-9cfghjmpqrvwx]{4}){3}", c["ghsa"]), c["id"]
            assert re.fullmatch(r"CVE-\d{4}-\d{4,}", c["cve"]), c["id"]
            assert c["repo_url"].startswith("https://github.com/"), c["id"]

    def test_all_refs_are_full_shas(self):
        for c in CASES:
            refs = [*c["fix_commits"], c["base_ref"], c["pr_ref"]]
            assert all(isinstance(r, str) and SHA.match(r) for r in refs), c["id"]

    def test_construction_matches_refs(self):
        for c in CASES:
            last = c["fix_commits"][-1]
            if c["construction"] == "fix-commit":
                assert c["expected_verdict"] == "safe", c["id"]
                assert c["pr_ref"] == last and c["base_ref"] not in c["fix_commits"]
            else:
                assert c["expected_verdict"] == "vulnerable", c["id"]
                assert c["base_ref"] == last and c["pr_ref"] not in c["fix_commits"]

    def test_vulnerable_lines_only_on_vulnerable_cases(self):
        for c in CASES:
            if c["expected_verdict"] == "vulnerable":
                assert c["vulnerable_lines"], c["id"]
                assert all(isinstance(n, int) and n > 0 for n in c["vulnerable_lines"])
            else:
                assert c["vulnerable_lines"] == [], c["id"]

    def test_every_vulnerable_case_has_a_safe_twin(self):
        by_ghsa: dict[str, list[dict]] = {}
        for c in CASES:
            by_ghsa.setdefault(c["ghsa"], []).append(c)
        for ghsa, group in by_ghsa.items():
            verdicts = sorted(c["expected_verdict"] for c in group)
            assert verdicts == ["safe", "vulnerable"], ghsa
            a, b = group
            for key in ("repo_url", "fix_commits", "touched_files", "category", "cwe"):
                assert a[key] == b[key], f"{ghsa}: twins differ on {key}"

    def test_size_and_mix(self):
        ghsas = {c["ghsa"] for c in CASES}
        assert 4 <= len(ghsas) <= 6
        assert {c["category"] for c in CASES} == {"sqli", "authz"}


class TestFetchHelpers:
    def test_project_and_branch_names(self):
        case = {"repo_url": "https://github.com/BerriAI/litellm.git"}
        assert fetch.project_of(case) == "litellm"
        assert fetch.branch("litellm_authz_safe", "pr") == "rw/litellm_authz_safe/pr"

    @pytest.mark.parametrize("path,expected", [
        ("tests/unit/test_runs.py", True),
        ("src/pkg/test_helpers.py", True),
        ("src/pkg/runs_test.py", True),
        ("src/pkg/conftest.py", True),
        ("src/pkg/api/runs.py", False),
        ("src/pkg/latest.py", False),
    ])
    def test_is_test_path(self, path, expected):
        assert fetch.is_test_path(path) is expected


IDENT = {
    "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@t.local",
    "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@t.local",
}


@pytest.fixture()
def local_project(tmp_path):
    """pre-fix commit, then a fix that edits a.py, adds c.py, edits a test."""
    repo = tmp_path / "proj"
    repo.mkdir()
    g = lambda *a, **kw: fetch.git(repo, *a, env=IDENT, **kw)  # noqa: E731
    g("init", "-q", "-b", "main")

    def commit(files: dict[str, str], msg: str) -> str:
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text, encoding="utf-8", newline="\n")
        g("add", "-A")
        g("commit", "-q", "-m", msg)
        return g("rev-parse", "HEAD").strip()

    pre = commit({"a.py": "v1\n", "b.py": "keep\n", "tests/test_a.py": "t1\n"}, "pre")
    fix = commit({"a.py": "v2\n", "c.py": "new\n", "tests/test_a.py": "t2\n"}, "fix")
    return repo, pre, fix


def _case(case_id, construction, base, pr, fix):
    return {
        "id": case_id, "ghsa": "GHSA-aaaa-bbbb-cccc", "construction": construction,
        "repo_url": "https://github.com/example/proj",
        "fix_commits": [fix], "touched_files": ["a.py", "c.py"],
        "base_ref": base, "pr_ref": pr,
    }


class TestPrepareCase:
    def test_safe_case_is_real_history(self, local_project):
        repo, pre, fix = local_project
        base, pr = fetch.prepare_case(_case("x_safe", "fix-commit", pre, fix, fix), repo)
        assert (base, pr) == (pre, fix)
        assert fetch.git(repo, "rev-parse", "rw/x_safe/base").strip() == pre
        assert fetch.git(repo, "rev-parse", "rw/x_safe/pr").strip() == fix

    def test_vulnerable_case_restores_only_touched_source_files(self, local_project):
        repo, pre, fix = local_project
        base, pr = fetch.prepare_case(
            _case("x_vuln", "synthetic-revert", fix, None, fix), repo
        )
        assert base == fix
        show = lambda path: fetch.git(repo, "show", f"{pr}:{path}")  # noqa: E731
        assert show("a.py") == "v1\n"                 # restored to pre-fix
        assert show("b.py") == "keep\n"               # untouched
        assert show("tests/test_a.py") == "t2\n"      # tests are not reverted
        assert fetch.git(repo, "ls-tree", "--name-only", pr, "c.py").strip() == ""
        assert fetch.git(repo, "rev-parse", f"{pr}^").strip() == fix

    def test_synthetic_commit_sha_is_reproducible(self, local_project):
        repo, _pre, fix = local_project
        case = _case("x_vuln", "synthetic-revert", fix, None, fix)
        first = fetch.prepare_case(case, repo)
        assert fetch.prepare_case(case, repo) == first

    def test_touched_files_mismatch_fails_loudly(self, local_project):
        repo, pre, fix = local_project
        case = _case("x_safe", "fix-commit", pre, fix, fix)
        case["touched_files"] = ["a.py"]
        with pytest.raises(fetch.FetchError, match="touched_files mismatch"):
            fetch.prepare_case(case, repo)

    def test_policy_variant_adds_only_the_policy_file(self, local_project):
        repo, pre, fix = local_project
        case = _case("x_vuln", "synthetic-revert", fix, None, fix)
        base, pr = fetch.prepare_case(case, repo)
        bp, pp = fetch.prepare_policy(case, repo, base, pr, "# policy\nrule\n")
        show = lambda ref, path: fetch.git(repo, "show", f"{ref}:{path}")  # noqa: E731
        assert show(bp, "security-policy.md") == "# policy\nrule\n"
        assert show(pp, "security-policy.md") == "# policy\nrule\n"
        # the project's own tree is otherwise untouched, and so is the PR diff
        assert fetch.git(repo, "diff", "--name-only", base, bp).split() == ["security-policy.md"]
        assert fetch.git(repo, "diff", base, pr) == fetch.git(repo, "diff", bp, pp)
        assert fetch.git(repo, "rev-parse", "rw/x_vuln/base-policy").strip() == bp
        assert fetch.git(repo, "rev-parse", "rw/x_vuln/pr-policy").strip() == pp

    def test_policy_shas_are_reproducible(self, local_project):
        repo, _pre, fix = local_project
        case = _case("x_vuln", "synthetic-revert", fix, None, fix)
        base, pr = fetch.prepare_case(case, repo)
        first = fetch.prepare_policy(case, repo, base, pr, "p\n")
        assert fetch.prepare_policy(case, repo, base, pr, "p\n") == first

    def test_policy_refuses_to_shadow_an_existing_file(self, local_project):
        repo, pre, fix = local_project
        (repo / "security-policy.md").write_text("project's own\n", newline="\n")
        fetch.git(repo, "add", "-A", env=IDENT)
        fetch.git(repo, "commit", "-q", "-m", "own policy", env=IDENT)
        head = fetch.git(repo, "rev-parse", "HEAD").strip()
        case = _case("x_safe", "fix-commit", pre, fix, fix)
        with pytest.raises(fetch.FetchError, match="already exists"):
            fetch.prepare_policy(case, repo, head, fix, "p\n")

    def test_shipped_policies_cite_sources_and_name_no_advisory(self):
        policies = sorted((RW / "policies").glob("*.md"))
        assert {p.stem for p in policies} == {"aegra", "langflow", "litellm"}
        for p in policies:
            text = p.read_text(encoding="utf-8")
            assert "https://" in text, p.name
            assert not re.search(r"CVE-\d{4}|GHSA-", text), p.name
            assert len(text) < 5000, f"{p.name} would be cut by the 5000-char prompt cap"

    def test_interrupted_clone_is_rejected(self, tmp_path):
        dest = tmp_path / "half"
        dest.mkdir()
        fetch.git(dest, "init", "-q")  # .git exists, HEAD never resolves
        with pytest.raises(fetch.FetchError, match="incomplete clone"):
            fetch.ensure_clone("https://example.invalid/x/y", dest)

    def test_complete_clone_is_accepted(self, local_project):
        repo, _pre, _fix = local_project
        fetch.ensure_clone("https://example.invalid/x/y", repo)  # no clone attempted

    def test_missing_sha_fails_loudly(self, local_project):
        repo, pre, _fix = local_project
        bogus = "0" * 40
        with pytest.raises(fetch.FetchError, match="missing"):
            fetch.prepare_case(_case("x", "fix-commit", pre, bogus, bogus), repo)
