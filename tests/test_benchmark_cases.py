"""Integration guards for the benchmark: every patch must apply cleanly and
labels.json must stay consistent with the patch files."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
LABELS = json.loads((BENCH / "labels.json").read_text(encoding="utf-8"))


def git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True
    )
    assert result.returncode == 0, f"git {' '.join(args)}: {result.stderr}"


@pytest.fixture(scope="module")
def base_repo(tmp_path_factory) -> Path:
    repo = tmp_path_factory.mktemp("bench-base")
    shutil.copytree(BENCH / "app", repo / "app")
    for doc in ("security-policy.md", "api-spec.md", "README.md"):
        shutil.copy(BENCH / doc, repo / doc)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@t.local")
    git(repo, "config", "user.name", "T")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    return repo


class TestLabels:
    def test_case_counts_and_balance(self):
        cases = LABELS["cases"]
        assert len(cases) == 36
        assert sum(1 for c in cases if c["category"] == "sqli") == 24
        assert sum(1 for c in cases if c["category"] == "authz") == 12
        assert sum(1 for c in cases if c["expected_verdict"] == "vulnerable") == 18
        assert sum(1 for c in cases if c["expected_verdict"] == "safe") == 18
        assert sum(1 for c in cases if c["origin"] == "owasp-derived") == 12

    def test_patch_files_exist(self):
        for case in LABELS["cases"]:
            assert (BENCH / case["patch_file"]).is_file(), case["id"]

    def test_vulnerable_cases_have_lines(self):
        for case in LABELS["cases"]:
            if case["expected_verdict"] == "vulnerable":
                assert case["vulnerable_lines"], case["id"]

    def test_cwes_valid(self):
        allowed = {"CWE-89", "CWE-639", "CWE-862", "CWE-863"}
        assert {c["cwe"] for c in LABELS["cases"]} <= allowed

    def test_dev_eval_split_balanced(self):
        from collections import Counter

        counts = Counter(
            (c["split"], c["expected_verdict"]) for c in LABELS["cases"]
        )
        # 9 vulnerable + 9 safe in each split
        assert all(counts[(s, v)] == 9 for s in ("dev", "eval")
                   for v in ("vulnerable", "safe"))


@pytest.mark.parametrize("case", LABELS["cases"], ids=lambda c: c["id"])
def test_patch_applies_cleanly(base_repo, case):
    patch = BENCH / case["patch_file"]
    result = subprocess.run(
        ["git", "-C", str(base_repo), "apply", "--check", str(patch)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "case",
    [c for c in LABELS["cases"] if c["expected_verdict"] == "vulnerable"],
    ids=lambda c: c["id"],
)
def test_vulnerable_lines_point_at_added_code(base_repo, case, tmp_path):
    """Applying the patch, the labeled lines must exist in the changed file."""
    work = tmp_path / "work"
    shutil.copytree(base_repo, work)
    git(work, "apply", str(BENCH / case["patch_file"]))
    content = (work / case["file"]).read_text(encoding="utf-8").splitlines()
    for line_no in case["vulnerable_lines"]:
        assert 1 <= line_no <= len(content), f"{case['id']}: line {line_no} out of range"
