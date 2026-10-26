"""Unit tests: a citation of removed lines reads the removed code from the base snapshot."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lgtm.agents.base import EvidenceItem
from lgtm.validation import evidence as ev
from lgtm.validation.evidence import EvidenceValidator

BENCH = Path(__file__).resolve().parent.parent / "benchmark"
BASE_SHA = "b" * 40
PR_SHA = "a" * 40

BASE = [
    "def get(thread, user):",
    "    thread = load(thread)",
    "    if thread.owner_id != user.id:",
    "        raise Forbidden()",
    "    return thread",
]
PR = ["def get(thread, user):", "    thread = load(thread)", "    return thread", ""]
PR_SHORT = ["def get(thread, user):", "    thread = load(thread)"]
REMOVED = "if thread.owner_id != user.id: raise Forbidden()"
REMOVED_CODE = BASE[2:4]


def _validator(monkeypatch, files: dict[str, list[str]]) -> EvidenceValidator:
    def blob_lines(repo, sha, path, timeout):
        return files.get(f"{sha}:{path}")

    monkeypatch.setattr(ev, "_committed_blob_lines", blob_lines)
    return EvidenceValidator(
        "repo", "main", shas={"base": BASE_SHA, "pr": PR_SHA}
    )


def _snapshots(pr: list[str]) -> dict[str, list[str]]:
    return {f"{BASE_SHA}:app.py": BASE, f"{PR_SHA}:app.py": pr}


class TestReadCitedCodeRemovedLines:
    @pytest.mark.parametrize("pr", [PR, PR_SHORT], ids=["pr-lines-exist", "pr-lines-past-end"])
    def test_unlabelled_removed_line_citation_returns_removed_code(self, monkeypatch, pr):
        validator = _validator(monkeypatch, _snapshots(pr))
        item = EvidenceItem(file="app.py", lines=[3, 4], content=REMOVED)

        assert validator.read_cited_code(item).splitlines() == REMOVED_CODE

    def test_unlabelled_added_line_citation_returns_pr_code(self, monkeypatch):
        validator = _validator(monkeypatch, _snapshots(PR))
        item = EvidenceItem(file="app.py", lines=[3, 3], content="return thread")

        assert validator.read_cited_code(item) == "    return thread"

    def test_unlabelled_context_line_citation_returns_the_line(self, monkeypatch):
        validator = _validator(monkeypatch, _snapshots(PR))
        item = EvidenceItem(file="app.py", lines=[2, 2], content="thread = load(thread)")

        assert validator.read_cited_code(item) == "    thread = load(thread)"

    def test_unlabelled_citation_matching_neither_snapshot_keeps_pr_read(self, monkeypatch):
        validator = _validator(monkeypatch, _snapshots(PR))
        item = EvidenceItem(file="app.py", lines=[3, 3], content="nowhere in either file")

        assert validator.read_cited_code(item) == "    return thread"

    def test_labelled_citations_read_their_own_snapshot(self, monkeypatch):
        validator = _validator(monkeypatch, _snapshots(PR))

        base = EvidenceItem(file="app.py", lines=[3, 4], content=REMOVED, snapshot="base")
        pr = EvidenceItem(file="app.py", lines=[3, 3], content="x", snapshot="pr")

        assert validator.read_cited_code(base).splitlines() == REMOVED_CODE
        assert validator.read_cited_code(pr) == "    return thread"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def ce():
    return _load("rl_citation_export", BENCH / "citation_export.py")


@pytest.fixture
def export(ce, monkeypatch, tmp_path):
    def run(pr: list[str], evidence: dict) -> dict:
        files = {f"{BASE_SHA}:app.py": BASE, f"{PR_SHA}:app.py": pr}

        def fake_run(cmd, **kwargs):
            text = files.get(cmd[-1]) if "show" in cmd else None
            if text is None:
                return SimpleNamespace(returncode=1, stdout=b"")
            return SimpleNamespace(returncode=0, stdout="\n".join(text).encode())

        monkeypatch.setattr(ce, "_resolve", lambda repo, sha, snapshot: sha)
        monkeypatch.setattr(ce.subprocess, "run", fake_run)
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        record = {
            "id": "case_a", "base_sha": BASE_SHA, "pr_sha": PR_SHA,
            "findings": [{"explanation": "claim", "evidence": [evidence]}],
        }
        (run_dir / "case_a.json").write_text(json.dumps(record), encoding="utf-8")
        out = tmp_path / "export.json"
        ce.export_run(run_dir, {"case_a": tmp_path}, out)
        return json.loads(out.read_text(encoding="utf-8"))["units"][0]

    return run


class TestCitationExportRemovedLines:
    def test_unlabelled_added_line_citation_exports_pr_code(self, export):
        unit = export(PR, {"file": "app.py", "lines": [3, 3], "content": "return thread"})

        assert unit["code"] == "    return thread"
        assert unit["snapshot"] is None

    def test_unlabelled_citation_matching_neither_snapshot_exports_pr_head(self, export):
        unit = export(PR, {"file": "app.py", "lines": [3, 3], "content": "nowhere in either file"})

        assert unit["code"] == "    return thread"

    def test_labelled_base_citation_exports_base_code(self, export):
        unit = export(PR, {"file": "app.py", "lines": [3, 4], "content": REMOVED, "snapshot": "base"})

        assert unit["code"].splitlines() == REMOVED_CODE
