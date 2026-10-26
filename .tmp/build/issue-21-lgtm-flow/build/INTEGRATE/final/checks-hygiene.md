# INTEGRATE whole-feature checks: dependencies, README, hygiene

Head 84bece67c8708217d1f8f6b0293178fd43ee1466 vs base bad831d. Worktree clean (git status empty).
Diff size: 93 files changed, 14416 insertions(+), 1201 deletions(-).

## 1. CON-2 no new dependency: PASSED (one note)
- pyproject.toml and requirements.txt: no diff between bad831d and HEAD. No other requirements*/lock file exists.
- New third-party imports in added lines: click (declared), pytest (declared), flask, requests, yaml.
  - flask: already imported at bad831d in benchmark/app/*, benchmark/tools/generate_cases.py (benchmark sample app, not declared at bad831d either). Not a new pattern.
  - requests and yaml: appear only at benchmark/kev_support/fixtures.py:300 and :316, inside authored fixture source strings (not executed imports). Not dependencies.
- Finding (Info): no new dependency. Note the declared set still omits flask (pre-existing).

## 2. CON-3 README documents exit code and outputs: 1 gap (Medium), rest PASSED
Changed exit codes found:
- `lgtm review` (src/lgtm/cli.py, review docstring + final lines): 1 supported and not not_real or baseline vulnerable; 2 not judged/agent error; else 0. Documented at README.md:114-119 (matches code). Also in `--help` docstring. PASS.
- benchmark/real_world/evaluate_real.py:522 and :538 `return 4 if aborted else 0` (git cannot start twice in a row). NOT documented in README.md, benchmark/README.md, or benchmark/real_world/README.md (grep for exit/abort/4 finds nothing). Additive (previously 0), but CON-3 requires documenting changed outputs. 
- benchmark/judge_eval.py / kev_support/runner.py exit 0/1: new entry points, documented at benchmark/README.md:257-258, :273.
- benchmark/evaluate.py, run_injection_bench.py, generate_cases.py: no exit-code change in diff.
New outputs:
- Per-case traces `run_records` (evaluate.py:603): benchmark/README.md:406. PASS.
- Summary fields `not_judged_cases`, `kev` metrics, `requests_over_8192_input_tokens`: benchmark/README.md:155, :434-437. PASS.
- Injection bench `not_judged_cases` key (run_injection_bench.py, new "Excluded: candidates not judged"): README.md has no mention specific to the injection bench output (benchmark/README.md:155 describes it for evaluate.py only). Low gap; verify wording.
- Judge outputs (supported/unsupported/not judged in report.json/report.md; new `--judge-endpoint/--judge-model/--judge-timeout` flags): README.md:52-55, :112-113 cover findings; the three new CLI flags are not mentioned in README.md (grep: no match) but appear in `lgtm review --help`. Low.
- judge_eval.py outputs: benchmark/README.md:190-205, :440-455. PASS.

## 3. Hygiene
- H1 (Low) docs/project-proposal.md:23: `git diff --check` trailing whitespace on added line ("**Scope**  "; may be an intentional markdown line break). Only whitespace error.
- No conflict markers in added lines.
- No real secrets. benchmark/kev_support/fixtures.py:142 `API_KEY = "sk_live_51H8x2exampleKey"` is an intentional fake in an authored vulnerable fixture (Info; may trip secret scanners).
- No absolute/home paths, usernames or real emails in added lines. Placeholders only: model/.env.example:9 `NOTIFY_EMAIL=<username>@computing.smu.edu.sg`, fixtures `bench@example.invalid`. model/deploy/*.sh reference `$LLM_SERVE_ROOT` (env var). 
- No debug prints in src/; prints in benchmark scripts are CLI output.
- Artifacts: no __pycache__, .venv, .codegraph, logs, or binaries tracked (git ls-files pycache count 0; a local ignored `__pycache__` exists in the worktree, untracked). Largest added file 88.9 KB (a test). PDFs >200 KB under docs/ pre-date base.
- H2 (Low/Info) benchmark/runs/kev-support-20261023/{README.md,report.json}: committed run output (204 lines). benchmark/runs/ already tracks field_trial results and runs/README.md, so consistent with repo convention; confirm intended. benchmark/kev_model_labels.json (81 lines) is data, intended.
- Generated files: tests/model_input_lock/expected.json changed (126 lines): lock file, expected to change with prompts.

## Summary
Critical 0, High 0, Medium 1 (evaluate_real exit code 4 undocumented), Low 3 (injection-bench output and judge flags undocumented in README; trailing whitespace), Info 2.
Not run: pytest and CLI command runs (outside this assignment).
