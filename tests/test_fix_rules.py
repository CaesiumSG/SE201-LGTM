"""Fix-rule checks against the base commit (PR #24 head): no benchmark case
identifiers in agent-design text, the LLM-only control, labels and scoring
unchanged, and model conditions unchanged.

Rule functions are pure and proven on synthetic inputs; the repository checks
read the base with `git show` only."""

from __future__ import annotations

import ast
import difflib
import json
import re
import subprocess
import sys
import tomllib
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
BASE = "0e878e66e65ffcd70cdfe2490d75f8f8fbaec8fa"

PROMPTS = "src/lgtm/agents/prompts.toml"
AGENT_DESIGN_TEXT = [
    PROMPTS,
    "src/lgtm/config.py",
    "src/lgtm/validation/judge.py",
    *sorted(p.relative_to(REPO).as_posix() for p in (REPO / "src/lgtm/agents").glob("*.py")),
]
CONTROL_FILES = ["src/lgtm/agents/plain_reviewer.py"]
LABEL_FILES = ["benchmark/labels.json", "benchmark/real_world/cases.json"]
SCORING_FUNCTIONS = [
    "outcome_for", "outcome_for_label", "_relevant_verdicts", "_verdict_label",
    "_findings_label", "_target_sections", "_target_files", "_scan_failed",
    "derive_case_labels", "score_case", "finding_verdict", "predict_case_verdict",
    "kev_metrics", "alarms_outside_target", "estimate_tokens", "coverage_summary",
    "summarize",
]
MIN_IDENTIFIER_LEN = 5


def _norm(text: str) -> str:
    return text.replace("\r\n", "\n")


def _in_git_checkout() -> bool:
    proc = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=REPO, capture_output=True, text=True)
    return proc.returncode == 0 and Path(proc.stdout.strip()).resolve() == REPO


# The submission snapshot is a `git archive` with no history, so these
# comparisons with the base commit cannot run there. In a git checkout
# (including CI) they still run, and an unreadable base commit still fails.
needs_git_history = pytest.mark.skipif(
    not _in_git_checkout(), reason="not a git checkout (e.g. the submission snapshot): base commit unavailable"
)


def base_text(path: str) -> str | None:
    proc = subprocess.run(["git", "show", f"{BASE}:{path}"], cwd=REPO, capture_output=True)
    return _norm(proc.stdout.decode("utf-8")) if proc.returncode == 0 else None


def current_text(path: str) -> str:
    return _norm((REPO / path).read_text(encoding="utf-8"))


def added_lines(base: str | None, current: str) -> list[str]:
    old = (base or "").splitlines()
    new = current.splitlines()
    return [d[2:] for d in difflib.ndiff(old, new) if d.startswith("+ ")]


def case_identifiers(real_cases: list[dict], synthetic_cases: list[dict], patches: list[str]) -> set[str]:
    ids: set[str] = set()
    for c in real_cases:
        ids |= {c["id"], c["id"].split("_")[0], c["file"], Path(c["file"]).name}
        ids |= set(c.get("touched_files", [])) | {Path(f).name for f in c.get("touched_files", [])}
        ids |= {c.get("ghsa"), c.get("cve"), c.get("base_ref"), c.get("pr_ref")} | set(c.get("fix_commits", []))
        if c.get("repo_url"):
            ids.add(c["repo_url"].rstrip("/").split("/")[-1])
    for c in synthetic_cases:
        ids |= {c["id"], c["file"], Path(c["file"]).name}
    for patch in patches:
        for line in patch.splitlines():
            if not line.startswith("+") or line.startswith("+++"):
                continue
            body = line[1:].strip()
            ids |= set(re.findall(r"\b(?:def|class)\s+(\w+)", body))
            ids |= set(re.findall(r"route\(\s*[\"']([^\"']+)[\"']", body))
            ids |= set(re.findall(r"__tablename__\s*=\s*[\"'](\w+)[\"']", body))
            if len(body) >= 40:
                ids.add(body)
    return {i for i in ids if i and len(i) >= MIN_IDENTIFIER_LEN}


def identifier_hits(lines: list[str], identifiers: set[str]) -> set[str]:
    text = "\n".join(lines)
    return {
        i for i in identifiers
        if re.search(rf"(?<![\w]){re.escape(i)}(?![\w])", text, re.IGNORECASE)
    }


def drifted_functions(base_src: str, current_src: str, names: list[str]) -> list[str]:
    def segments(src: str) -> dict[str, str]:
        return {
            n.name: ast.get_source_segment(src, n)
            for n in ast.parse(src).body
            if isinstance(n, ast.FunctionDef) and n.name in names
        }

    old, new = segments(base_src), segments(current_src)
    return sorted(n for n in names if old.get(n) != new.get(n))


def model_conditions(config_src: str) -> dict:
    mod = types.ModuleType("fix_rules_config_probe")
    sys.modules[mod.__name__] = mod
    try:
        exec(compile(config_src, "config.py", "exec"), mod.__dict__)
        cfg = mod.LGTMConfig()
        return {
            "ollama_model": cfg.ollama_model,
            "reasoning": cfg.reasoning,
            "judge_model": cfg.judge_model,
            "gpu_models": {k: (v.tag, v.reasoning) for k, v in mod.GPU_MODELS.items()},
        }
    finally:
        del sys.modules[mod.__name__]


def toml_table(text: str, table: str) -> dict:
    return tomllib.loads(text)[table]


# --- rule functions detect violations ---------------------------------

CASES_REAL = [{
    "id": "acmeproj_sqli_vulnerable", "file": "src/acmeproj/core/store_layer.py",
    "touched_files": ["src/acmeproj/core/store_layer.py"], "ghsa": "GHSA-aaaa-bbbb-cccc",
    "cve": "CVE-2099-0001", "base_ref": "1" * 40, "pr_ref": "2" * 40, "fix_commits": ["3" * 40],
    "repo_url": "https://github.com/acme/acmeproj",
}]
CASES_SYN = [{"id": "widget_07_vulnerable", "file": "app/routes/gadgets.py"}]
PATCH = "\n".join([
    "+++ b/app/routes/gadgets.py",
    '+@gadgets_bp.route("/<int:gadget_id>/archive", methods=["POST"])',
    "+def archive_gadget_record(gadget_id: int):",
    '+    rows = session.execute(text("SELECT * FROM gadget_table WHERE id=" + str(gadget_id)))',
])
IDENTIFIERS = case_identifiers(CASES_REAL, CASES_SYN, [PATCH])


@pytest.mark.parametrize("leak", [
    "Always check store_layer.py first.",
    "Projects like acmeproj need extra care.",
    "See GHSA-aaaa-bbbb-cccc.",
    "Look at widget_07_vulnerable.",
    "The /<int:gadget_id>/archive route is risky.",
    "Call archive_gadget_record carefully.",
    'rows = session.execute(text("SELECT * FROM gadget_table WHERE id=" + str(gadget_id)))',
    "Inspect gadgets.py for authorization.",
], ids=lambda s: s[:30])
def test_identifier_scan_flags_each_kind_of_case_identifier(leak):
    assert identifier_hits([leak], IDENTIFIERS)


def test_identifier_scan_accepts_general_agent_design_text():
    text = ["Check ownership on every endpoint that reads a record by id.", "Quote the exact lines you cite."]
    assert identifier_hits(text, IDENTIFIERS) == set()


def test_added_lines_returns_only_new_lines():
    assert added_lines("a\nb\n", "a\nb\nc\n") == ["c"]
    assert added_lines(None, "x\ny\n") == ["x", "y"]


def test_drift_check_flags_a_changed_scoring_function_and_ignores_others():
    base = "def score(x):\n    return x + 1\n\ndef other():\n    return 0\n"
    changed = "def score(x):\n    return x + 2\n\ndef other():\n    return 5\n"
    assert drifted_functions(base, changed, ["score"]) == ["score"]
    assert drifted_functions(base, base, ["score", "other"]) == []
    assert drifted_functions(base, "def other():\n    return 0\n", ["score"]) == ["score"]


def test_model_condition_probe_reads_each_setting():
    src = (
        "from dataclasses import dataclass\n"
        "@dataclass(frozen=True)\nclass GpuModel:\n    tag: str\n    reasoning: object\n"
        "GPU_MODELS = {'m': GpuModel('m:1', False)}\n"
        "@dataclass\nclass LGTMConfig:\n    ollama_model: str = 'm:1'\n    reasoning: object = False\n"
        "    judge_model: str = 'j'\n"
    )
    base = model_conditions(src)
    assert base == {"ollama_model": "m:1", "reasoning": False, "judge_model": "j", "gpu_models": {"m": ("m:1", False)}}
    assert model_conditions(src.replace("reasoning: object = False", "reasoning: object = True")) != base
    assert model_conditions(src.replace("judge_model: str = 'j'", "judge_model: str = 'k'")) != base
    assert model_conditions(src.replace("GpuModel('m:1', False)", "GpuModel('m:2', False)")) != base


# --- repository checks against the base commit ------------------------

@needs_git_history
def test_base_commit_is_readable():
    assert base_text(PROMPTS)


def test_AC_US5_1_agent_design_text_changed_since_base_has_no_benchmark_case_identifiers():
    real = json.loads(current_text("benchmark/real_world/cases.json"))["cases"]
    labels = json.loads(current_text("benchmark/labels.json"))["cases"]
    patches = [current_text(f"benchmark/{c['patch_file']}") for c in labels if c.get("patch_file")]
    identifiers = case_identifiers(real, labels, patches)
    assert identifiers
    added = [
        line
        for path in AGENT_DESIGN_TEXT
        for line in added_lines(base_text(path), current_text(path))
    ]
    assert identifier_hits(added, identifiers) == set()


@needs_git_history
@pytest.mark.parametrize("path", CONTROL_FILES + LABEL_FILES)
def test_AC_US5_4_control_and_labels_identical_to_base(path):
    assert current_text(path) == base_text(path)


@needs_git_history
def test_AC_US5_4_llm_only_prompt_identical_to_base():
    assert toml_table(current_text(PROMPTS), "plain_reviewer") == toml_table(base_text(PROMPTS), "plain_reviewer")


@needs_git_history
def test_AC_US5_4_scoring_functions_identical_to_base():
    path = "benchmark/evaluate.py"
    assert drifted_functions(base_text(path), current_text(path), SCORING_FUNCTIONS) == []


@needs_git_history
def test_AC_US5_5_reviewer_thinking_and_judge_models_equal_base():
    path = "src/lgtm/config.py"
    assert model_conditions(current_text(path)) == model_conditions(base_text(path))
