# Re-review 2: reviewer-reach repair diff (59a878b..ebe9dff)

Verdict: CLEAN. final-03 is resolved. The repair adds one new Medium (final-04), which does not block.

Scope: only the repair diff. That is `_enclosing_functions` in src/lgtm/agents/authz_reviewer.py, which now returns qualified names, plus one new test in tests/test_agents.py. I also checked the dedup in `_enclosing_block` that uses those names.

Acceptance criteria checked:
- AC-S2-1 (corrected wording: every changed line, including removed lines; a hunk spanning several functions contributes each). Met for the final-03 shape.

## Status of earlier findings
- final-03: resolved (reproduced).
  - `_enclosing_functions` now walks the AST recursively and carries a dotted class and function prefix. `_enclosing_block` dedups on `(rel, qualified name)`.
  - A direct run on a two-class source returned `A.get`, `B.get`, `B.get.inner`, and `g` for an async function nested under a module-level `if`. So the two same-named methods no longer collide. Nested functions still resolve to the innermost one, and functions inside non-def blocks keep the outer prefix.
  - The new test adds a line in `A.get` and deletes one in `B.get`, then asserts both appear. Against 59a878b it would fail: the base `B.get` is dropped there because its bare name `get` matches a PR function. repair-5 reports seeing that failure.
  - A modified function has the same qualified name in both snapshots, so the dedup that shows it once still holds.

## Findings

### final-04 Medium (reproduced): the new recursive walk raises RecursionError on deep ASTs that `ast.parse` accepts
- Location: src/lgtm/agents/authz_reviewer.py, `_enclosing_functions`, the nested `visit`. It recurses once per AST level. The old `ast.walk` was iterative.
- Trigger: a changed `.py` file containing an expression with about 2000 chained binary operators, for example `x = 1+1+...+1`.
- Expected: no error. The function returns the enclosing span, as `ast.walk` did, and in any case does not crash. The function's own contract is to return `[]` when it cannot parse.
- Actual:
  - With 500 terms it returns `[(1, 3, 'f')]`.
  - With 2000 terms, `ast.parse` succeeds and then `visit` raises `RecursionError: maximum recursion depth exceeded`.
  - Nothing catches the error between there and `_enclosing_block`, which is called from the initial-input build at line 245.
  - With 10000 terms, `ast.parse` itself raises RecursionError. That predates this diff: the except clause catches only SyntaxError and ValueError.
- Realistic exposure is low: authorization code rarely has expressions nested 1000 or more levels deep, and generated code would need an unusual shape.
- Smallest correction: wrap both the parse and the walk so that RecursionError returns `[]`. For example, add `RecursionError` to the except tuple and move `visit(tree, "")` inside the try. An explicit stack also works.
- Recommendation: resolve (it is a one-line change), or defer as a follow-up. Either is acceptable, because it does not block.

## Plan check
- No contradictions. AC-S2-1's corrected wording is satisfied for the final-03 shape. No `minor` or `needs-replan` items.

## Coverage
- Axes:
  - correctness: qualified names for classes, nested functions, functions inside if-blocks, async functions; dedup interaction.
  - tests as evidence: the new test, by inspection.
  - robustness: recursion depth.
  - architecture: no new imports; the change stays inside the existing function.
  - Security and performance are unchanged by this diff.
- Checks run: one throwaway script in build/reviewer-reach/tmp/final/, run with the main checkout's venv interpreter (`-I`, PYTHONDONTWRITEBYTECODE=1) and the worktree `src` first on sys.path. It covered the depth cases (500, 2000 and 10000 terms) and the qualified-name case.
- Not run: the full suite (the change-verifier owns it) and the new repo test itself.
- Cleanup: an exit trap removed the throwaway folder, and I verified it is gone. The worktree was not modified. HEAD is ebe9dff.
