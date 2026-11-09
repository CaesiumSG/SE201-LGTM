"""Docs name the real-world set as the development set and the synthetic eval split as the held-out check."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
REAL_README = ROOT / "benchmark" / "real_world" / "README.md"
REAL_EVAL = ROOT / "docs" / "real-world-eval.md"
BENCH_README = ROOT / "benchmark" / "README.md"
DOCS = [README, REAL_README, REAL_EVAL, BENCH_README]

HELD_OUT = re.compile(r"held[- ]out", re.I)
REAL_WORLD = re.compile(r"real[- ]world|advisor|\bCVEs?\b", re.I)
SYNTHETIC = re.compile(r"synthetic|shoply|eval split|--split eval", re.I)
# The real-PR benchmark (benchmark/real_prs/heldout.json) is a genuine held-out
# set of advisories; only the 12-case real-world CVE set must not be called held out.
REAL_PRS = re.compile(r"real PRs?\b|introduc|heldout\.json", re.I)
NEGATED = re.compile(r"\b(not|no longer|isn't|never)\b[^.]{0,20}held|held[- ]out[^.]{0,20}\b(not|no longer)\b", re.I)
DEV_SET = re.compile(r"development[- ]set|dev(?:elopment)? set", re.I)
LIST_START = re.compile(r"^\s*(?:[-*+]\s|\d+\.\s|\||#)")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _blocks(text: str) -> list[str]:
    blocks: list[list[str]] = [[]]
    for line in text.splitlines():
        if not line.strip():
            blocks.append([])
        elif LIST_START.match(line):
            blocks.append([line])
        else:
            blocks[-1].append(line)
    return [" ".join(b) for b in blocks if b]


def _sentences(text: str) -> list[str]:
    out: list[str] = []
    for block in _blocks(text):
        out.extend(s for s in re.split(r"\.\s+", block) if s.strip())
    return out


def _sections(text: str) -> list[str]:
    sections: list[list[str]] = [[]]
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
        if not in_fence and re.match(r"#{1,6}\s", line):
            sections.append([])
        sections[-1].append(line)
    return ["\n".join(s) for s in sections]


def _held_out_real_world_sentences(path: Path, whole_file_is_real_world: bool) -> list[str]:
    bad = []
    for s in _sentences(_text(path)):
        if not HELD_OUT.search(s) or SYNTHETIC.search(s) or NEGATED.search(s):
            continue
        if not whole_file_is_real_world and REAL_PRS.search(s):
            continue
        if whole_file_is_real_world or REAL_WORLD.search(s):
            bad.append(s.strip())
    return bad


@pytest.mark.parametrize(
    ("path", "whole_file"),
    [(README, False), (REAL_README, True), (REAL_EVAL, True)],
    ids=["README", "real_world_README", "real-world-eval"],
)
def test_no_statement_calls_the_real_world_set_held_out(path, whole_file):
    assert _held_out_real_world_sentences(path, whole_file) == []


@pytest.mark.parametrize("path", [README, REAL_README, REAL_EVAL], ids=["README", "real_world_README", "real-world-eval"])
def test_real_world_set_is_stated_as_the_development_set(path):
    hits = [s for s in _sentences(_text(path)) if DEV_SET.search(s) and REAL_WORLD.search(s) and not NEGATED.search(s)]
    assert hits, f"{path.name} never states the real-world set is the development set"


@pytest.mark.parametrize("path", [README, REAL_README], ids=["README", "real_world_README"])
def test_synthetic_eval_split_is_stated_as_the_held_out_check(path):
    hits = [
        s
        for s in _sentences(_text(path))
        if HELD_OUT.search(s) and re.search(r"synthetic|eval split|--split eval", s, re.I) and not NEGATED.search(s)
    ]
    assert hits, f"{path.name} never states the synthetic eval split is the held-out check"


def test_batch_command_with_resume_and_bundle_is_documented():
    sections = [s for p in DOCS for s in _sections(_text(p))]
    hits = [
        s
        for s in sections
        if re.search(r"python\S*\s+benchmark/real_world/batch\.py", s)
        and "bundle.json" in s
        and re.search(r"resum|next unrun|continu", s, re.I)
    ]
    assert hits, "no section gives `python benchmark/real_world/batch.py`, its resume behavior, and bundle.json"


def test_guard_command_is_documented():
    hits = [s for p in DOCS for s in _sections(_text(p)) if re.search(r"python\S*\s+benchmark/guard\.py", s)]
    assert hits, "no doc gives `python benchmark/guard.py`"


def _loop_blocks() -> list[str]:
    marker = re.compile(r"benchmark/guard\.py|real_world/batch\.py|bundle\.json|development[- ]set", re.I)
    return [b for p in DOCS for b in _blocks(_text(p)) if marker.search(b)]


IDENTIFYING = [
    r"[A-Za-z]:[\\/]+Users",
    r"/Users/\w+",
    r"/home/\w+",
    r"\b(?!127\.0\.0\.1\b|0\.0\.0\.0\b)\d{1,3}(?:\.\d{1,3}){3}\b",
    r"\b[\w.+-]+@[\w-]+\.\w+",
    r"\bsk-\w{8,}",
    r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+",
]
RATIONALE = [r"\bDEC-\d+", r"\bAC-US\d", r"\bCON-\d+", r"\bCT-[\w-]+", r"\bbecause\b", r"\brationale\b", r"\bwe (?:decided|chose)\b", r"\bpreviously\b", r"\boriginally\b"]


@pytest.mark.parametrize("pattern", IDENTIFYING)
def test_loop_documentation_identifies_no_machine_user_or_credential(pattern):
    offenders = [b for b in _loop_blocks() if re.search(pattern, b)]
    assert offenders == []


@pytest.mark.parametrize("pattern", RATIONALE)
def test_loop_documentation_carries_no_design_rationale_or_plan_references(pattern):
    offenders = [b for b in _loop_blocks() if re.search(pattern, b, re.I)]
    assert offenders == []


@pytest.mark.parametrize("path", DOCS, ids=["README", "real_world_README", "real-world-eval", "benchmark_README"])
def test_internal_only_modes_statement_is_kept(path):
    hits = [
        b
        for b in _blocks(_text(path))
        if "sast-only" in b and "lgtm-no-sast" in b and re.search(r"internal", b, re.I)
    ]
    assert hits, f"{path.name} lost the sast-only/lgtm-no-sast internal-only statement"
