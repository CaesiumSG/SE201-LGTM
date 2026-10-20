"""Integration guards for the benchmark: every patch must apply cleanly and
labels.json must stay consistent with the patch files."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
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


GENERATOR = BENCH / "tools" / "generate_cases.py"

SAMPLE = (
    "import os\n\n\ndef f():\n    x = 1\n    y = 2\n    z = 3\n    return x\n"
)
FIXTURE_FILES = {
    "app/sample.py": SAMPLE,
    "app/legacy.py": "def old():\n    return 1\n",
    "app/other.py": "a = 1\n",
    "app/padded.py": "p = 1\n\n\n",
}


@pytest.fixture
def gen(monkeypatch):
    name = "generate_cases_under_test"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bench(tmp_path, gen, monkeypatch) -> Path:
    root = tmp_path / "bench"
    shutil.copytree(BENCH / "app", root / "app")
    for doc in ("security-policy.md", "api-spec.md", "README.md"):
        shutil.copy(BENCH / doc, root / doc)
    for name, content in FIXTURE_FILES.items():
        (root / name).write_text(content, encoding="utf-8", newline="\n")
    monkeypatch.setattr(gen, "BENCH", root)
    return root


@pytest.fixture
def repo(tmp_path, gen, bench) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    gen.build_base_repo(path)
    return path


def make_case(gen, **overrides):
    fields = dict(
        id="authz_99_vulnerable",
        category="authz",
        expected_verdict="vulnerable",
        cwe="CWE-862",
        file="app/sample.py",
        replacements=[("    y = 2\n", "    y = 20\n    y2 = 21\n"),
                      ("    z = 3\n", "    z = 30\n")],
    )
    fields.update(overrides)
    return gen.Case(**fields)


def status(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        capture_output=True, text=True, check=True,
    ).stdout


def changed_lines(diff: str) -> list[str]:
    return [
        ln for ln in diff.splitlines()
        if ln[:1] in "+-" and not ln.startswith(("+++", "---"))
    ]


def generate(gen, monkeypatch, cases):
    monkeypatch.setattr(gen, "CASES", cases)
    gen.main()
    return json.loads((gen.BENCH / "labels.json").read_text(encoding="utf-8"))["cases"]


class TestDiffContext:
    def test_context_controls_unchanged_lines_around_hunk(self, gen, repo):
        one = make_case(gen, replacements=[("    y = 2\n", "    y = 20\n")], context=1)
        default = make_case(gen, replacements=[("    y = 2\n", "    y = 20\n")])
        context_of = lambda d: [ln for ln in d.splitlines() if ln.startswith(" ")]
        assert len(context_of(gen.apply_case(repo, one))) == 2
        assert len(context_of(gen.apply_case(repo, default))) == 5


class TestFileEnd:
    def test_main_file_end_untouched_without_append(self, gen, repo):
        case = make_case(
            gen, file="app/padded.py", replacements=[("p = 1", "p = 2")],
            expected_verdict="safe",
        )
        assert changed_lines(gen.apply_case(repo, case)) == ["-p = 1", "+p = 2"]

    def test_extra_file_end_untouched_without_append(self, gen, repo):
        case = make_case(
            gen,
            edits=[{"file": "app/padded.py", "replacements": [("p = 1", "p = 2")]}],
        )
        diff = gen.apply_case(repo, case)
        start = diff.index("diff --git a/app/padded.py")
        end = diff.find("diff --git", start + 1)
        padded = diff[start:] if end < 0 else diff[start:end]
        assert changed_lines(padded) == ["-p = 1", "+p = 2"]


class TestExtraEdits:
    def test_edits_modify_additional_files_with_optional_append(self, gen, repo):
        case = make_case(
            gen,
            edits=[{
                "file": "app/other.py",
                "replacements": [("a = 1", "a = 2")],
                "append": "\n\ndef extra():\n    return 3\n",
            }],
        )
        diff = gen.apply_case(repo, case)
        assert "diff --git a/app/sample.py b/app/sample.py" in diff
        assert "diff --git a/app/other.py b/app/other.py" in diff
        assert "+a = 2" in diff
        assert "+def extra():" in diff
        assert status(repo) == ""


class TestDeletedAndNewFiles:
    def test_deleted_file_appears_as_deletion_and_repo_is_restored(self, gen, repo):
        case = make_case(gen, delete_files=["app/legacy.py"])
        diff = gen.apply_case(repo, case)
        assert "deleted file mode" in diff
        assert "diff --git a/app/legacy.py b/app/legacy.py" in diff
        assert (repo / "app/legacy.py").is_file()
        assert status(repo) == ""

    def test_new_file_appears_as_addition_and_repo_is_cleaned(self, gen, repo):
        case = make_case(gen, new_files={"app/fresh.py": "z = 1\n"})
        diff = gen.apply_case(repo, case)
        assert "new file mode" in diff
        assert "+z = 1" in diff
        assert not (repo / "app/fresh.py").exists()
        assert status(repo) == ""

    def test_moved_content_is_not_reported_as_rename(self, gen, repo):
        case = make_case(
            gen,
            delete_files=["app/legacy.py"],
            new_files={"app/moved.py": FIXTURE_FILES["app/legacy.py"]},
        )
        diff = gen.apply_case(repo, case)
        assert "rename from" not in diff
        assert "deleted file mode" in diff
        assert "new file mode" in diff
        assert status(repo) == ""


class TestVulnerableLocations:
    def test_old_and_new_side_markers_resolve_to_separate_ranges(
        self, gen, bench, monkeypatch
    ):
        loc = {"file": "app/sample.py", "old_markers": ["y = 2", "z = 3"],
               "new_markers": ["z = 30", "y2 = 21"]}
        labels = generate(gen, monkeypatch, [make_case(gen, location_markers=[loc])])
        assert labels[0]["vulnerable_locations"] == [
            {"file": "app/sample.py", "old_range": [6, 7], "new_range": [7, 8]}
        ]
        assert list(labels[0]["vulnerable_locations"][0]) == [
            "file", "old_range", "new_range"]

    def test_side_without_markers_has_null_range(self, gen, bench, monkeypatch):
        old_only = {"file": "app/sample.py", "old_markers": ["y = 2"]}
        new_only = {"file": "app/sample.py", "new_markers": ["y2 = 21"]}
        labels = generate(
            gen, monkeypatch,
            [make_case(gen, location_markers=[old_only, new_only])],
        )
        assert labels[0]["vulnerable_locations"] == [
            {"file": "app/sample.py", "old_range": [6, 6], "new_range": None},
            {"file": "app/sample.py", "old_range": None, "new_range": [7, 7]},
        ]

    def test_locations_alone_satisfy_vulnerable_case(self, gen, bench, monkeypatch):
        loc = {"file": "app/sample.py", "new_markers": ["z = 30"]}
        labels = generate(gen, monkeypatch, [make_case(gen, location_markers=[loc])])
        assert labels[0]["vulnerable_lines"] == []
        assert labels[0]["vulnerable_locations"] == [
            {"file": "app/sample.py", "old_range": None, "new_range": [8, 8]}
        ]

    def test_old_markers_ignore_added_lines(self, gen, bench, monkeypatch):
        wrong_side = {"file": "app/sample.py", "old_markers": ["y2 = 21"]}
        monkeypatch.setattr(
            gen, "CASES", [make_case(gen, location_markers=[wrong_side])]
        )
        with pytest.raises(RuntimeError):
            gen.main()

    def test_unmatched_marker_names_case_and_marker(self, gen, bench, monkeypatch):
        loc = {"file": "app/sample.py", "new_markers": ["no such line"]}
        monkeypatch.setattr(gen, "CASES", [make_case(gen, location_markers=[loc])])
        with pytest.raises(RuntimeError) as err:
            gen.main()
        assert str(err.value) == (
            "authz_99_vulnerable: location marker not found: no such line"
        )

    def test_vulnerable_case_without_lines_or_locations_is_rejected(
        self, gen, bench, monkeypatch
    ):
        monkeypatch.setattr(gen, "CASES", [make_case(gen)])
        with pytest.raises(RuntimeError):
            gen.main()


class TestLabelFields:
    def test_optional_fields_follow_description_only_when_set(
        self, gen, bench, monkeypatch
    ):
        loc = {"file": "app/sample.py", "old_markers": ["y = 2"]}
        both = make_case(gen, id="authz_97_vulnerable", location_markers=[loc],
                         diff_shape="removed_auth_decorator")
        shape_only = make_case(gen, id="authz_98_safe", expected_verdict="safe",
                               diff_shape="removed_auth_decorator")
        plain = make_case(gen, id="authz_99_safe", expected_verdict="safe")
        labels = generate(gen, monkeypatch, [both, shape_only, plain])
        by_id = {c["id"]: c for c in labels}
        assert list(by_id["authz_97_vulnerable"])[-3:] == [
            "description", "diff_shape", "vulnerable_locations"]
        assert by_id["authz_97_vulnerable"]["diff_shape"] == "removed_auth_decorator"
        assert list(by_id["authz_98_safe"])[-2:] == ["description", "diff_shape"]
        assert "vulnerable_locations" not in by_id["authz_98_safe"]
        assert list(by_id["authz_99_safe"])[-1] == "description"
        assert "diff_shape" not in by_id["authz_99_safe"]

    def test_existing_cases_regenerate_to_committed_labels_and_patches(
        self, gen, bench, monkeypatch
    ):
        for name in FIXTURE_FILES:
            (bench / name).unlink()
        gen.main()
        normalize = lambda p: p.read_bytes().replace(b"\r\n", b"\n")
        assert normalize(bench / "labels.json") == normalize(BENCH / "labels.json")
        for case in LABELS["cases"]:
            assert normalize(bench / case["patch_file"]) == normalize(
                BENCH / case["patch_file"]
            ), case["id"]


class TestSplitRule:
    @pytest.mark.parametrize(
        "pair,expected",
        [(1, "dev"), (3, "dev"), (4, "eval"), (6, "eval"),
         (7, "dev"), (8, "dev"), (9, "dev"),
         (10, "eval"), (11, "eval"), (12, "eval"),
         (13, "dev"), (14, "eval")],
    )
    def test_pair_number_determines_split(self, gen, pair, expected):
        case = make_case(gen, id=f"authz_{pair:02d}_safe", expected_verdict="safe")
        assert case.split == expected
