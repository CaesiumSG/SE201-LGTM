# Repo survey

- Repository name: SE201-LGTM (Python package `lgtm`)
- Default branch: main
- Head SHA of main: ff110c3b8ec194ee8bb8bd831d24c86bc7e7159e
- Primary root: `.`
- Notable sub-projects: `benchmark/` (evaluation harness and Shoply fixture app, run from the repo root), `src/lgtm/` (package), `tests/`, `model/`, `docs/`

## Commands (README.md, benchmark/README.md, pyproject.toml)

- Install: `python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]" semgrep` (Python >= 3.10; extras `dev` = pytest, pytest-mock; `sast` = semgrep). `requirements.txt` also lists dependencies.
- Full pipeline needs Ollama and Semgrep installed.
- CLI: `lgtm index --repo <path>`; `lgtm review --repo <path> --base main --pr <branch>` (modes `--mode sast-only|llm-only|lgtm-no-sast`)
- Test: `pytest` (testpaths `tests`, pythonpath `src`; marker `requires_codegraph` needs the real codegraph binary)
- Benchmark (sub-project `benchmark/`): `python benchmark/evaluate.py --mode lgtm|sast-only|llm-only|lgtm-no-sast` with `--split dev|eval`, `--cases <ids>`, `--rescore`, `--resume`
- Prompt-injection benchmark: `python benchmark/injection/run_injection_bench.py`
- Real-world benchmark: `python benchmark/real_world/fetch.py --policies`; `python benchmark/real_world/evaluate_real.py --modes sast-only lgtm`
- Regenerate benchmark cases: `python benchmark/tools/generate_cases.py`
- Build: no documented command (setuptools backend via `pip install -e .`)
- Lint: none documented, no config
- Type-check: none documented, no config
- E2E: none documented as a separate command (benchmark runs serve as end-to-end evaluation)
- Dev server: none; no Makefile
- CI workflows: none (no `.github/workflows`)
- CONTRIBUTING: none

## Design system / components / tokens

None (no frontend).
