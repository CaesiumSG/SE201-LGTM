"""Registry shipping, Python floor, import order, and absence of inline model-visible text."""

from __future__ import annotations

import ast
import fnmatch
import re
import subprocess
import sys
import tomllib
from importlib import resources
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "lgtm"
REGISTRY = SRC / "agents" / "prompts.toml"
TABLES = {
    "shared",
    "tools",
    "retriever",
    "sast_triage",
    "authz_reviewer",
    "plain_reviewer",
    "investigator",
}
TOUCHED = sorted(p for p in (SRC / "agents").glob("*.py") if p.name != "__init__.py") + [
    SRC / "rag" / "retriever.py"
]
ENGLISH_RUN = re.compile(r"[A-Za-z]{2,}(?:\s+[A-Za-z]{2,}){2,}")


def _has_text(node) -> bool:
    if isinstance(node, dict):
        return any(_has_text(v) for v in node.values())
    return isinstance(node, str) and bool(node)


def test_registry_has_a_non_empty_table_per_owner():
    registry = tomllib.loads(REGISTRY.read_text(encoding="utf-8"))
    assert TABLES <= set(registry)
    assert all(_has_text(registry[name]) for name in TABLES)


def test_registry_ships_inside_the_lgtm_package():
    assert resources.files("lgtm.agents").joinpath("prompts.toml").is_file()
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = data.get("tool", {}).get("setuptools", {}).get("package-data", {})
    shipped = any(
        fnmatch.fnmatch("prompts.toml" if package != "lgtm" else "agents/prompts.toml", pattern)
        for package, patterns in package_data.items()
        if package in ("lgtm", "lgtm.agents", "*")
        for pattern in patterns
    )
    assert shipped, "pyproject.toml package-data must include the registry"


def test_python_floor_is_3_13_in_pyproject_readme_and_prompt_doc():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["requires-python"] == ">=3.13"
    for name in ("README.md", "docs/claude-prompt.md"):
        floors = re.findall(r"Python\s+3\.(\d+)\+", (ROOT / name).read_text(encoding="utf-8"))
        assert floors, f"{name} states no Python floor"
        assert set(floors) == {"13"}, f"{name} states a Python floor other than 3.13+"


def test_retriever_imports_first_in_a_fresh_interpreter():
    done = subprocess.run(
        [sys.executable, "-I", "-c", "import lgtm.rag.retriever"],
        env={"PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr


def _in_logging_or_raise(node: ast.AST, parents: dict) -> bool:
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.Raise):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"logger", "logging"}
        ):
            return True
    return False


def _inline_model_text(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            "tool" in ast.unparse(d) for d in node.decorator_list
        ):
            if ast.get_docstring(node, clean=False):
                found.append(f"tool docstring of {node.name}")
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if isinstance(parents.get(node), ast.Expr):
                continue
            if ENGLISH_RUN.search(node.value) and not _in_logging_or_raise(node, parents):
                found.append(node.value[:60])
    return found


@pytest.mark.parametrize("path", TOUCHED, ids=lambda p: p.name)
def test_no_model_visible_literal_or_tool_docstring_remains_outside_the_registry(path):
    assert _inline_model_text(path) == []


@pytest.mark.parametrize("path", TOUCHED, ids=lambda p: p.name)
def test_no_unused_import_or_private_constant_remains(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
    }
    unused = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                continue
            for alias in node.names:
                name = (alias.asname or alias.name).split(".")[0]
                if name not in used:
                    unused.append(name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and re.fullmatch(r"_[A-Z_]+", target.id)
                    and target.id not in used
                ):
                    unused.append(target.id)
    assert unused == []
