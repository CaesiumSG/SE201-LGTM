"""Deterministic static facts handed to the LLM agents.

Small local models misread code they could have been told about for free:
run 1 saw qwen2.5-coder call ``"... %s" % user_id`` "parameterized", and
flag admin-only endpoints for missing ownership checks. These helpers parse
the PR version of a file with ``ast`` and state such facts plainly, so the
agent reasons from them instead of re-deriving them. They never decide a
verdict themselves.
"""

from __future__ import annotations

import ast

SQL_CALLS = {"execute", "executemany", "exec_driver_sql", "text"}


def _parse(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _resolve(arg: ast.expr, scope: ast.AST | None, before_line: int) -> ast.expr:
    """Follow ``q = <expr>; execute(q)`` one step back within the function."""
    if not isinstance(arg, ast.Name) or scope is None:
        return arg
    latest = None
    for node in ast.walk(scope):
        if (
            isinstance(node, ast.Assign)
            and node.lineno < before_line
            and any(isinstance(t, ast.Name) and t.id == arg.id for t in node.targets)
            and (latest is None or node.lineno > latest.lineno)
        ):
            latest = node
    return latest.value if latest is not None else arg


def describe_query_construction(expr: ast.expr) -> str:
    """How a SQL string expression is built, in one phrase."""
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return "a constant string literal (no interpolation)"
    if isinstance(expr, ast.JoinedStr):
        names = [
            ast.unparse(v.value) for v in expr.values if isinstance(v, ast.FormattedValue)
        ]
        return f"an f-string interpolating {', '.join(names) or 'expressions'}"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return f"%-string formatting with {ast.unparse(expr.right)} (string interpolation, NOT a bound parameter)"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        parts = []
        stack = [expr]
        while stack:
            node = stack.pop()
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                stack.extend([node.right, node.left])
            elif not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                parts.append(ast.unparse(node))
        return f"string concatenation with {', '.join(parts) or 'expressions'}"
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "format"
    ):
        return "str.format() interpolation"
    if isinstance(expr, ast.Call) and _call_name(expr) == "text" and expr.args:
        return "text(" + describe_query_construction(expr.args[0]) + ")"
    return f"the expression `{ast.unparse(expr)[:80]}`"


def _names_in(expr: ast.expr) -> list[str]:
    return list(dict.fromkeys(
        n.id for n in ast.walk(expr) if isinstance(n, ast.Name) and n.id.islower()
    ))


def _input_facts(name: str, scope: ast.AST, before_line: int) -> list[str]:
    """Where ``name`` comes from, and whether it is allowlist-checked."""
    facts: list[str] = []
    for node in ast.walk(scope):
        if (
            isinstance(node, ast.Assign)
            and node.lineno < before_line
            and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
        ):
            src = ast.unparse(node.value)
            origin = "user-controlled request data" if "request." in src else "not request data"
            facts.append(f"`{name}` is assigned from `{src[:80]}` (line {node.lineno}: {origin})")
        if (
            isinstance(node, ast.Compare)
            and node.lineno < before_line
            and isinstance(node.left, ast.Name)
            and node.left.id == name
            and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
        ):
            container = ast.unparse(node.comparators[0])[:60]
            facts.append(
                f"`{name}` is membership-checked against `{container}` (line {node.lineno})"
            )
    return facts


def sql_sink_facts(source: str, line: int) -> str:
    """Facts about SQL calls on (or spanning) ``line`` of ``source``."""
    tree = _parse(source)
    if tree is None:
        return ""
    functions = [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    facts: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node) not in SQL_CALLS:
            continue
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        if not (node.lineno - 1 <= line <= end + 1) or not node.args:
            continue
        scope = next(
            (f for f in functions if f.lineno <= node.lineno <= (f.end_lineno or f.lineno)),
            None,
        )
        query = _resolve(node.args[0], scope, node.lineno)
        has_params = len(node.args) > 1 or any(k.arg in ("parameters", "params") for k in node.keywords)
        facts.append(
            f"- line {node.lineno}: `{_call_name(node)}()` receives a query built from "
            f"{describe_query_construction(query)}; separate bound-parameter "
            f"argument passed: {'yes' if has_params else 'NO'}."
        )
        if scope is not None and not isinstance(query, ast.Constant):
            for name in _names_in(query):
                facts.extend(f"  - {f}" for f in _input_facts(name, scope, node.lineno))
    return "\n".join(dict.fromkeys(facts))
