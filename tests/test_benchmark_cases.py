"""Integration guards for the benchmark: every patch must apply cleanly and
labels.json must stay consistent with the patch files."""

from __future__ import annotations

import importlib.util
import json
import re
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
                assert (
                    case.get("vulnerable_lines") or case.get("vulnerable_locations")
                ), case["id"]

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
    labelled = work / case["file"]
    if not labelled.is_file():
        assert not case.get("vulnerable_lines"), case["id"]
        return
    content = labelled.read_text(encoding="utf-8").splitlines()
    for line_no in case.get("vulnerable_lines", []):
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


PAIRS = {
    7: dict(split="dev", cwe="CWE-639", shape="deletion_only"),
    8: dict(split="dev", cwe="CWE-863", shape="shared_helper"),
    9: dict(split="dev", cwe="CWE-639", shape="decorator_outside_hunk"),
    10: dict(split="eval", cwe="CWE-862", shape="deleted_file"),
    11: dict(split="eval", cwe="CWE-639", shape="oversized_diff"),
    12: dict(split="eval", cwe="CWE-639", shape="cross_file_move"),
    13: dict(split="dev", cwe="CWE-863", shape="renamed_route"),
    14: dict(split="eval", cwe="CWE-862", shape="removed_auth_decorator"),
}
LABELLED_FILE = {
    7: "app/routes/users.py", 8: "app/auth.py", 9: "app/routes/orders.py",
    10: "app/auth/__init__.py", 11: "app/routes/users.py",
    12: "app/ownership.py", 13: "app/routes/admin.py",
}
EXPECTED_SIDES = {
    10: {("app/auth.py", "old"), ("app/auth/__init__.py", "new")},
    11: {("app/routes/users.py", "new")},
    12: {("app/auth.py", "old"), ("app/ownership.py", "new")},
    13: {("app/routes/admin.py", "new")},
}
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
ROUTE_RE = re.compile(r"route\(\s*[\"']([^\"']+)[\"']")

BOTH = pytest.mark.parametrize("kind", ["vulnerable", "safe"])
PAIR = pytest.mark.parametrize("pair", sorted(PAIRS))


def label_for(pair: int, kind: str) -> dict:
    case_id = f"authz_{pair:02d}_{kind}"
    matches = [c for c in LABELS["cases"] if c["id"] == case_id]
    assert len(matches) == 1, f"{case_id} missing from labels.json"
    return matches[0]


def patch_text(pair: int, kind: str) -> str:
    label = label_for(pair, kind)
    path = BENCH / label["patch_file"]
    assert path.is_file(), f"{label['id']}: patch file missing"
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def parse_patch(text: str) -> list[dict]:
    files = []
    for block in re.split(r"(?m)^(?=diff --git )", text):
        if not block.startswith("diff --git "):
            continue
        old = new = None
        hunks = []
        for ln in block.split("\n"):
            if ln.startswith("--- ") and not hunks:
                old = None if ln == "--- /dev/null" else ln[6:]
            elif ln.startswith("+++ ") and not hunks:
                new = None if ln == "+++ /dev/null" else ln[6:]
            elif ln.startswith("@@"):
                a, b, c, d = HUNK_RE.match(ln).groups()
                hunks.append(dict(
                    old=(int(a), int(a) + int(b if b is not None else 1) - 1),
                    new=(int(c), int(c) + int(d if d is not None else 1) - 1),
                    body=[],
                ))
            elif hunks:
                hunks[-1]["body"].append(ln)
        files.append(dict(old=old, new=new, hunks=hunks))
    return files


def file_body(f: dict) -> list[str]:
    return [ln for h in f["hunks"] for ln in h["body"]]


def hunk_bodies(text: str) -> list[str]:
    return [ln for f in parse_patch(text) for ln in file_body(f)]


def is_decorator(ln: str) -> bool:
    return ln[1:].lstrip().startswith("@")


def overlaps(a, b) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


class TestNewAuthzPairLabels:
    @PAIR
    @BOTH
    def test_pair_label_metadata(self, pair, kind):
        label = label_for(pair, kind)
        spec = PAIRS[pair]
        assert label["category"] == "authz"
        assert label["origin"] == "custom"
        assert label["split"] == spec["split"]
        assert label["cwe"] == spec["cwe"]
        assert label["expected_verdict"] == kind
        assert label["patch_file"] == f"cases/authz/case_{pair:02d}_{kind}.patch"
        assert label["diff_shape"] == spec["shape"]
        if pair in LABELLED_FILE:
            assert label["file"] == LABELLED_FILE[pair]

    @PAIR
    @BOTH
    def test_locations_overlap_real_hunks_and_have_contract_shape(self, pair, kind):
        label = label_for(pair, kind)
        locations = label.get("vulnerable_locations")
        assert locations, f"{label['id']}: vulnerable_locations missing"
        files = parse_patch(patch_text(pair, kind))
        for loc in locations:
            assert list(loc) == ["file", "old_range", "new_range"]
            assert loc["old_range"] or loc["new_range"]
            for key, side in (("old_range", "old"), ("new_range", "new")):
                rng = loc[key]
                if rng is None:
                    continue
                assert isinstance(rng, list) and len(rng) == 2
                assert all(isinstance(n, int) for n in rng)
                assert 1 <= rng[0] <= rng[1]
                spans = [h[side] for f in files if f[side] == loc["file"]
                         for h in f["hunks"]]
                assert any(overlaps(rng, s) for s in spans), (
                    f"{label['id']}: {key} {rng} in {loc['file']} overlaps no hunk"
                )

    @pytest.mark.parametrize("pair", sorted(EXPECTED_SIDES))
    @BOTH
    def test_locations_cover_the_changed_region_per_side(self, pair, kind):
        sides = set()
        for loc in label_for(pair, kind).get("vulnerable_locations") or []:
            if loc["old_range"]:
                sides.add((loc["file"], "old"))
            if loc["new_range"]:
                sides.add((loc["file"], "new"))
        assert EXPECTED_SIDES[pair] <= sides

    @BOTH
    def test_pair_14_locations_are_old_ranges_of_removed_decorator(self, kind):
        locations = label_for(14, kind).get("vulnerable_locations") or []
        assert locations and all(loc["old_range"] for loc in locations)

    @pytest.mark.parametrize("pair", [7, 8, 14])
    def test_vulnerable_twin_relies_on_locations_not_lines(self, pair):
        label = label_for(pair, "vulnerable")
        assert label["vulnerable_lines"] == []
        assert label.get("vulnerable_locations")


class TestNewAuthzPairDiffShapes:
    @BOTH
    def test_deletion_only_has_no_added_lines_and_no_decorator(self, kind):
        body = hunk_bodies(patch_text(7, kind))
        assert any(ln.startswith("-") for ln in body)
        assert not [ln for ln in body if ln.startswith("+")]
        assert not [ln for ln in body if is_decorator(ln)]

    @BOTH
    def test_shared_helper_touches_only_auth_module(self, kind):
        paths = {p for f in parse_patch(patch_text(8, kind))
                 for p in (f["old"], f["new"]) if p}
        assert paths == {"app/auth.py"}

    @BOTH
    def test_decorator_outside_hunk_shows_neither_decorator_nor_def(self, kind):
        body = hunk_bodies(patch_text(9, kind))
        assert body
        assert not [ln for ln in body if is_decorator(ln)]
        assert not [ln for ln in body if "def my_orders" in ln]

    @BOTH
    def test_deleted_file_marks_deletion(self, kind):
        text = patch_text(10, kind)
        assert "deleted file mode" in text
        assert "+++ /dev/null" in text

    @BOTH
    def test_oversized_diff_is_large_with_marker_in_final_tenth(self, kind):
        text = patch_text(11, kind)
        assert len(text) > 18000
        marker = text.rfind("/users/<id>/export")
        assert marker >= len(text) * 0.9

    @BOTH
    def test_cross_file_move_defines_function_in_two_files(self, kind):
        text = patch_text(12, kind)
        assert "new file mode" in text
        files = parse_patch(text)

        def files_with(prefix, side):
            return {f[side] for f in files for ln in file_body(f)
                    if ln.startswith(prefix) and "def is_owner_or_admin" in ln}

        removed, added = files_with("-", "old"), files_with("+", "new")
        assert removed and added
        assert not (removed & added)

    @BOTH
    def test_renamed_route_swaps_path_in_admin_routes(self, kind):
        admin = [f for f in parse_patch(patch_text(13, kind))
                 if f["new"] == "app/routes/admin.py"]
        assert admin
        body = file_body(admin[0])

        def paths(prefix):
            return {m.group(1) for ln in body if ln.startswith(prefix)
                    for m in [ROUTE_RE.search(ln)] if m}

        old_paths, new_paths = paths("-"), paths("+")
        assert old_paths and new_paths and not (old_paths & new_paths)

    def test_vulnerable_twin_removes_decorator_without_adding_one(self):
        body = hunk_bodies(patch_text(14, "vulnerable"))
        assert [ln for ln in body if ln.startswith("-") and is_decorator(ln)]
        assert not [ln for ln in body if ln.startswith("+") and is_decorator(ln)]
