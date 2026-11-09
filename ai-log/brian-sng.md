# AI Use Log: Brian Sng

## 2026-10-18 · Prompt injection red-teaming and mitigations
- **Tool (model):** Google Antigravity (Gemini Flash 3.8)
- **Files:** docs/prompt-injection.md, benchmark/injection/generate_injection_cases.py, benchmark/injection/run_injection_bench.py, src/lgtm/diff/sanitizer.py, src/lgtm/pipeline.py, src/lgtm/config.py, src/lgtm/cli.py, src/lgtm/sast/semgrep_runner.py, benchmark/evaluate.py, src/lgtm/agents/base.py, tests/test_sanitizer.py, docs/checkpoint.md, docs/ai-use-log.md
- **Outcome:** Changed

### What I asked for
Threat model documentation for a malicious PR author attempting prompt injection to mask SQLi (CWE-89) and broken authorization (CWE-639/862/863); an injection benchmark generator producing 6 injected patch variants (developer comments, malicious docstrings, fake JSON findings, variable names, non-Python files) without hand-editing patches; an injection benchmark evaluation harness comparing `sast-only`, `llm-only`, and `lgtm` modes; two mitigation strategies behind configurable flags (diff comment/docstring stripping and reviewer-directed injection detection); Windows compatibility fixes for Semgrep executable resolution; and comprehensive unit tests and documentation in `docs/prompt-injection.md` and `docs/checkpoint.md`.

### How I checked it
Ran full test suite (`pytest tests/ -q` - all 198 tests passing, including 5 new sanitizer unit tests in `tests/test_sanitizer.py`). Validated that `sast-only` AST analysis is inherently immune to comment/docstring prompt injections (ASR = 0.0%). Evaluated empirical attack success against unmitigated `lgtm`, observing downgrades from `vulnerable` to `possible` via comments and fake JSON, and complete bypass (`safe`) via docstrings. Verified that mitigations cleanly strip comments and docstrings from LLM diff contexts while preserving raw code for Semgrep, and that the injection detector flags attack strings as high-severity findings. Verified that mitigation flags default to `False` to maintain baseline benchmark reproducibility.

### What I kept or changed
Kept the AST-unaware diff comment/docstring stripper and rule-based heuristic detector. Fixed Windows executable resolution (`semgrep.exe`) in `semgrep_runner.py`. Tuned Ollama client timeouts (`keep_alive="24h"`, `timeout=config.llm_timeout`) to handle remote cluster latencies and disconnections gracefully. Added error handling around single-case evaluation in `run_injection_bench.py`.


## 2026-11-06 · Tests and fixes for safe_markdown
- **Tool (model):** Google Antigravity (Gemini Flash 3.8)
- **Files:** demo/github_app.py, tests/test_safe_markdown.py, docs/ai-use-log.md, ai-log/brian-sng.md
- **Outcome:** Changed

### What I asked for
Implementation of Task 2 ("Tests for safe_markdown (small)") from `teammate-tasks.md`: write unit tests for `safe_markdown(text, own_owner)` in `demo/github_app.py` covering @mentions, emails, cross-repository references, full GitHub URLs, code blocks/spans, and Markdown links. Identify and fix any missed cases.

### How I checked it
Wrote unit tests in `tests/test_safe_markdown.py` first to expose existing flaws (defanging email addresses, corrupting code blocks/spans with word joiners and replacements, broken markdown links with double parentheses, and greedy trailing punctuation consumption). In code-span and markdown link handling, verified against CommonMark/GFM rules that escaped backticks (`\`@alice\``), mid-line `~~~`, and backtick spans crossing blank lines render as text on GitHub and must be defanged, and that Markdown links with titles `[x](url "t")` defang without breaking syntax into `[x]((link removed) "t")`. Ran the 37 unit tests in `tests/test_safe_markdown.py` and ran existing test suites (`tests/test_sanitizer.py`, `tests/test_diff.py`, `tests/test_facts.py`, `tests/test_report.py`).

### What I kept or changed
Kept the word joiner (`\u2060`) defanging technique for `@mentions` and cross-repo references. Changed the implementation to recognize fenced code blocks only at line start (indented up to 3 spaces), restrict inline backtick code spans to not cross blank lines or unescaped backtick boundaries, allow escaped backslashes before backticks, support Markdown link titles in `[label](url "title")`, ensure email addresses are not defanged by enforcing non-word character lookbehind on `@`, handle Markdown link syntax cleanly as `label (link removed)` or `(link removed)`, and prevent eating trailing sentence punctuation in bare URLs.

## Reflection

### What I learned about using these tools effectively
I learned to prioritize iterative verification over trust. Model outputs often look plausible on the surface, but they should only be treated as initial working drafts. Running the actual automated test suite, inspecting edge cases manually, and testing against concrete specifications are essential before accepting any generated code.

### Where the tools were strong, and where they were weak
The tools were strong at rapid test generation and threat exploration, helping craft injection attack vectors and broad unit test suites quickly. However, they were weak at nuanced specification details—such as CommonMark parsing corner cases and regex boundary constraints—as well as platform-specific quirks like Windows binary resolution and path handling.

### What went wrong, and what I would do differently
Platform differences and network assumptions caused friction: Windows-specific executable discovery (`semgrep.exe`) and Ollama client timeouts when communicating with remote GPU cluster tools required unexpected debugging. Next time, I would standardize and validate the cross-platform environment and timeout configurations earlier in the project lifecycle.

