# Intake: issue 21

Title: Benchmark run of #20: problems found in the LGTM review flow
URL: https://github.com/CaesiumSG/SE201-LGTM/issues/21
Labels: none. Comments: none. Design links or images: none in the issue.

The issue lists problems only (no proposed solutions). Data it cites (cluster job 337363, commit 460d9b3): `results/evaluate/`, `results/evaluate-real/<mode>/`, `kev-bench-20261024T133035/report.json`, `judged-bench.log`. None of these are in the checkout.

## Issue body (verbatim)

This issue lists the problems found in the benchmark results of #20 (cluster job 337363, commit `460d9b3`). It lists problems only.

## Background

**What LGTM is meant to do.** LGTM has two jobs:

1. **Check Semgrep's SQL injection warnings.** Semgrep is a tool that scans code for risky patterns. It often raises false alarms, so LGTM's AI agent reads the flagged code and decides whether each warning is a real problem.
2. **Find access-control bugs that Semgrep cannot see.** Examples: a user can read another user's order by changing an ID in the URL, or an admin-only page has no admin check. These are called *authorization* (authz) bugs.

Anything outside these two jobs is out of scope.

**How a review works.**
- The *investigator* agent splits the pull request (PR) into sections.
- The *reviewer* agent reads each section and reports possible bugs, called *candidates*. It can call tools such as "read this file" or "search the repo", up to a fixed number of times.
- **Kev** is a small judge model. For each candidate it answers two separate questions:
  - **Supported:** does the code the agent quoted actually show what the agent claims?
  - **Verdict:** is this a real vulnerability (`real` or `not_real`)?
  - It also gives a severity.

**Words used below.**

| Term | Meaning |
|---|---|
| TP (true positive) | Vulnerable case, and LGTM flagged it |
| FP (false positive) | Safe case, but LGTM flagged it (a false alarm) |
| FN (false negative) | Vulnerable case, but LGTM missed it |
| TN (true negative) | Safe case, and LGTM stayed quiet |
| UNCREDITED | Safe case that LGTM never explicitly cleared |
| F1 | One score from 0 to 1 that combines "how many alarms were right" with "how many real bugs were caught". Higher is better |

**Benchmarks.**
- **Shoply:** 52 hand-made cases.
- **Real-world:** 12 cases built from real CVEs in open-source projects (aegra, alerta, langflow, litellm, postgraas, pyload).
- **llm-only:** a baseline that sends only the diff to the model, with no tools, no Semgrep and no judge.

## A. The reviewer misses bugs or raises false alarms

**A1. On real-world code, LGTM does worse than the simple baseline.**

| Mode | F1 |
|---|---|
| llm-only | 1.0 |
| lgtm | 0.727 |
| lgtm-no-sast | 0.667 |
| lgtm-policy | 0.571 |
| lgtm-no-sast-policy | 0.571 |

The extra machinery (tools, sections, judge) is not helping on real code yet. With only 12 cases the gap could partly be chance: llm-only catches 6/6 vulnerable cases and lgtm 4/6, which gives a Fisher exact test p ≈ 0.45.

**A2. Bugs caused by deleting code are always missed.**
- `aegra_authz_vulnerable` deletes 19 lines and adds none. The deleted lines were the check that a user owns a thread.
- `alerta_sqli_vulnerable` deletes 114 lines and adds 7, replacing a safe parameterized query with string building.
- In both cases the investigator names the bug in the section title ("Remove per-thread ownership (user_id) authorization checks…", "Replace parameterized to_sql() with repr()-based SQL string interpolation").
- The reviewer still reports nothing. This happens in every lgtm mode. llm-only finds both bugs from the diff alone.

**A3. The reviewer runs out of tool calls.**
- The reviewer may make 5 tool calls and 8 reasoning steps per section. On most real-world cases it uses all of them and is then forced to answer.
- On `aegra_authz_vulnerable` this happened 4 times on a single section, and the final answer was an empty list.
- The investigator also hits its limit (16 steps) on most real-world cases. What that does to the results has not been checked.

**A4. The reviewer starts with very little code.**
- It is shown only the changed lines plus a few lines around them.
- `read_file` returns at most 200 lines per call.
- So most tool calls go to just finding the function that was changed, which leaves few calls for following how the code behaves.

**A5. The review is not limited to the PR's own changes.**
- The tools can read and search anywhere in the repository.
- Nothing requires a reported bug to be in, or caused by, the changed code.
- The validator records a `grounded_in_pr` flag, but nothing uses it, and it can never be true for deleted lines.

**A6. False alarm on a bug that was already there before the PR.** In `litellm_authz_safe` the reported weakness already existed. The agent's own explanation says "the existing max_budget guard had the same pattern". Kev rated it `real`.

**A7. False alarms from reading the security policy too strictly.**
- `authz_06_safe`: a new report endpoint protected by an API-key scope is flagged as an access-control bug.
- `authz_09_safe`: a filter that hides cancelled orders, added to a query that already only returns the user's own orders, is flagged.

**A8. Giving LGTM the project's security policy makes results worse.** Both policy modes score F1 0.571, against 0.727 without a policy. `aegra_authz_safe` becomes a false alarm.

**A9. The same code gives different answers on different runs.**
- Between run 1 (`5e5676d`) and run 2 (`460d9b3`), `authz_03_safe` changed from FP to TN and `authz_06_safe` changed from TN to FP.
- The reviewer, section and pipeline code is identical in both commits. The model runs at temperature 0, yet its answers still vary.

## B. Some benchmark cases test things LGTM is not meant to do

**B1. These cases fall outside LGTM's scope:**

| Case | Problem |
|---|---|
| `alerta_sqli` pair (real-world) | Semgrep raises no warning on either side, so there is nothing for LGTM to check |
| `postgraas_sqli_safe` (real-world) | Semgrep raises no warning, so it is UNCREDITED on every run. Its vulnerable twin has 4 warnings and is in scope |
| `sqli_04_safe`, `sqli_07_safe`, `sqli_11_safe` (Shoply) | Semgrep raises no warning, although the README describes these as safe code that *does* trigger Semgrep. These are the 3 UNCREDITED Shoply cases |

**B2. `lgtm-no-sast` tests SQL injection detection without Semgrep.** In this mode a simple pattern check in LGTM replaces Semgrep, so its SQL injection results measure something outside the scope.

**B3. The README and `docs/project-proposal.md` never state the scope.** They describe what LGTM does but not what it leaves out.

**B4. Semgrep warns on only 2 of the 6 real-world SQL injection cases** (`postgraas_sqli_vulnerable`, `pyload_sqli_vulnerable`).

## C. Kev (the judge)

**C1. Kev's two answers are not measured separately.**
- "Supported" and "verdict" are separate questions, but the score and the exit code of `lgtm review` use only "supported".
- Example: in `authz_09_safe` Kev says the claim is supported but `not_real`, and the case is still counted as a false alarm.
- "Verdict" has no accuracy number in any benchmark.

**C2. Nothing measures Kev on LGTM's real output.**
- No candidate in Shoply or the real-world set has a correct-answer label.
- The judge-eval labels file is empty, so its accuracy numbers are based on 0 examples.
- The real-world candidates need labels before Kev can be measured on them.

**C3. Kev is weakest on the most realistic test cases.** On Kev's own 90-case test set, the `live_shaped` cases (closest to real agent output) get the "supported" question right only 3/10 (with examples in the prompt) and 4/10 (without). Every other kind scores 9/10 or better.

**C4. Kev's severity is unreliable.**
- Exactly right on only 8/20 (with examples) and 7/20 (without) cases.
- Changing the order of the answer options changes the severity in 36 and 46 of 90 cases.

**C5. Kev accepted every false alarm in the real-world set.**

**C6. Two quotes point at code that does not exist.** In `authz_10_vulnerable` and `authz_12_vulnerable` the quoted lines are not in the PR version of the file. It is not known whether the agent quoted the wrong place or the test repository was rebuilt differently.

**C7. Kev mostly agrees with the agent instead of checking it.**
- Kev rejected 22 candidates on safe cases (Shoply plus the real-world `lgtm` and `lgtm-no-sast` runs). 18 of these come from the Semgrep-checking agent, whose own explanation already says the code is safe ("uses bound parameters", "the value is strictly validated"). That agent has no verdict field, so it writes its conclusion into the explanation, and Kev agrees with it.
- When an agent says there *is* a bug, Kev disagreed with only 2 distinct claims: the litellm "bulk users path" claim and `authz_14_safe`.
- It accepted the other 3 wrong bug claims: `authz_06_safe`, the aegra "bypassable check" and the litellm "spend guard". On `authz_09_safe` it said `not_real` but still answered "supported", so the case was counted as a false alarm.
- Kev's "supported" and "verdict" answers disagree on only 3 of about 170 candidates, so in practice they behave like one answer.

## D. Gaps in how results are measured

- **D1. Too few real-world cases.** With 12 cases, one case moves F1 by about 0.1.
- **D2. Each setup is run once.** Given A9, one run cannot tell a real one-case change from random variation.
- **D3. The reviewer's work is not saved.** Results do not keep the reviewer's tool calls or its raw answer, so A2 could only be explained from log warnings.
- **D4. Bugs in the "wrong" category are ignored by the scorer.** For example, an access-control bug reported in an SQL injection case is not counted or checked.
- **D5. The real-world set is held out.** `benchmark/runs/README.md` marks it "held-out: no tuning", so its cases cannot be used as targets while fixing these problems.

## Data

Run outputs from job 337363: `results/evaluate/` (Shoply), `results/evaluate-real/<mode>/` (real-world), the Kev bench report `kev-bench-20261024T133035/report.json`, and `judged-bench.log`.

## Distinct problems and current code

Issue items A1-D5 grouped into five distinct problems.

### 1. Reviewer misses bugs, especially deletion-only changes; its context and budget are thin (A1, A2, A3, A4)

Quotes: "The reviewer still reports nothing. This happens in every lgtm mode. llm-only finds both bugs from the diff alone." / "The reviewer may make 5 tool calls and 8 reasoning steps per section. On most real-world cases it uses all of them and is then forced to answer." / "It is shown only the changed lines plus a few lines around them."

Current code:
- `src/lgtm/config.py`, `LGTMConfig`: `max_tool_calls = 5`, `max_agent_iterations = 8`, `investigator_max_tool_calls = 12`, `investigator_max_iterations = 16`, `investigator_max_sections = 12`, `section_max_chars = 12000`, `max_sections = 24`, `llm_temperature = 0.0`. Per-agent caps on tool calls and reasoning-loop iterations.
- `src/lgtm/agents/base.py`, `run_tool_loop`: manual tool loop; stops when the model answers with no tool calls, when the iteration cap is hit, or when the invalid-tool-input cap is hit, after which the model is forced to answer. Non-JSON final answers are re-asked up to `max_answer_reasks` (`request_valid_answer`).
- `src/lgtm/agents/tools.py`, `AgentToolbox.charge` / `reset_budget`: every tool attempt spends one slot; once spent, tools return `BUDGET_MESSAGE`. `MAX_READ_LINES = 200` caps each `read_file_impl` result. `read_file`, `grep_repo`, `search_policy` and `investigate_*_code` share one budget.
- `src/lgtm/agents/authz_reviewer.py`, `AuthzReviewerAgent.review_section`, `SECTION_SYSTEM_PROMPT`, `SECTION_USER_PROMPT`, `_context_block`: reviews one `Section`; hunks are rendered as +/-/space-prefixed lines, plus the investigator's context pointers (path, line range, snapshot, why).
- `src/lgtm/diff/git_diff.py`, `get_pr_diff`: runs `git diff --unified=3`, so each hunk carries 3 context lines; `LineChange.kind` is add, del or context.
- `src/lgtm/agents/investigator.py`, `run_investigator`: proposes sections using the toolbox budget `investigator_max_tool_calls` and loop cap `investigator_max_iterations`.
- `src/lgtm/review/sections.py`, `Section`, `HunkRef`, `plan_sections`: sections hold hunks, including deletion-only hunks.
- `src/lgtm/pipeline.py`, `ReviewPipeline._review` (about lines 139-140): `scan_diffs = get_pr_diff(...)`; `diffs = [d for d in scan_diffs if d.status != "deleted"]` (fully deleted files are dropped from the diffs used for Semgrep triage); `_review_sections` runs the investigator and then the reviewer per section.
- `src/lgtm/agents/plain_reviewer.py`, `PlainLLMReviewer.review`: llm-only baseline; one model call over the diff, no tools.

### 2. Review is not limited to the PR's changes; pre-existing and policy-strict false alarms; policy mode lowers results (A5, A6, A7, A8)

Quotes: "Nothing requires a reported bug to be in, or caused by, the changed code. The validator records a `grounded_in_pr` flag, but nothing uses it, and it can never be true for deleted lines." / "the existing max_budget guard had the same pattern" / "Both policy modes score F1 0.571, against 0.727 without a policy."

Current code:
- `src/lgtm/agents/tools.py`, `read_file_impl`, `grep_repo_impl`, `_investigate`: read or search any path in the base or PR snapshot; only paths escaping the repository are rejected (`relative_path`, `_ESCAPE`).
- `src/lgtm/validation/evidence.py`, `EvidenceValidator.validate`, `_grounds_pr`: computes a local `grounded` boolean (a code evidence item with `snapshot == "pr"`, or, without snapshots, a snippet found in `_diff_added`). Its only use: if `finding.pr_graph_ok is False` and the verdict is `vulnerable` and not grounded, the verdict is downgraded to `possible` and `PR_GROUNDING_CAP_MARKER` is appended. No field named `grounded_in_pr` exists in this checkout. `_diff_added` is built from `FileDiff.added_text`, which contains no deleted lines.
- `src/lgtm/agents/authz_reviewer.py`, `_policy_context`, `POLICY_EXCERPT_CHARS = 5000`, `ROLE_GUIDANCE`: when a retriever exists, policy excerpts are pre-retrieved into the prompt; `config.authz_role_guidance` (default off) adds role-versus-ownership guidance.
- `src/lgtm/rag/retriever.py`, `PolicyRetriever.retrieve` / `format_results`: policy lookup used by the prompt and by the `search_policy` tool.
- `benchmark/real_world/evaluate_real.py` (variants `own` and `policy`; `policies/<project>.md` copied in as `security-policy.md`): defines the `*-policy` modes.

### 3. Run-to-run nondeterminism (A9)

Quote: "The reviewer, section and pipeline code is identical in both commits. The model runs at temperature 0, yet its answers still vary."

Current code:
- `src/lgtm/config.py`, `LGTMConfig.llm_temperature = 0.0`.
- `src/lgtm/agents/base.py`, `build_llm`, `invoke_with_retry`: builds the chat model from config (temperature, timeout, `llm_max_output_tokens`, reasoning flag); no seed was seen.
- `benchmark/evaluate.py` (`main`, `evaluate_case`) and `benchmark/real_world/evaluate_real.py` (`main`, `run_unit`): each case and mode is run once per invocation.

### 4. Benchmark cases and modes outside LGTM's scope; scope undocumented (B1, B2, B3, B4)

Quotes: "`alerta_sqli` pair (real-world) | Semgrep raises no warning on either side" / "These are the 3 UNCREDITED Shoply cases" / "`lgtm-no-sast` tests SQL injection detection without Semgrep." / "The README and `docs/project-proposal.md` never state the scope."

Current code:
- `src/lgtm/pipeline.py`, `SQL_SINK_RE`, `ReviewPipeline._heuristic_sql_findings` (rule id `lgtm-no-sast.sql-sink-heuristic`, one finding per hunk) and the `lgtm-no-sast` branch of `_review` (about line 198): a regex over added lines replaces Semgrep as the source of SQL candidates passed to `SASTTriageAgent.triage`.
- `src/lgtm/pipeline.py`, `_run_sast`, `filter_to_diff`: Semgrep findings are kept only when inside the diff; each is triaged by `SASTTriageAgent` (`src/lgtm/agents/sast_triage.py`). With no Semgrep finding there is no SQL candidate.
- `benchmark/evaluate.py`, `outcome_for_label`, `PREDICTED_BY_LABEL`, `derive_case_labels`: a safe case whose label is neither `explicit_safe` nor `detected_vulnerability` (and not `missing_review` or `scan_failure`) is `UNCREDITED`.
- `benchmark/real_world/cases.json`, `benchmark/labels.json`, `benchmark/cases/`, `benchmark/README.md`: case definitions and descriptions.
- `README.md` (authz section near line 206) and `docs/project-proposal.md`: feature descriptions; no out-of-scope statement was found by search.

### 5. Kev judge: answers not scored separately, not measured on real output, mostly agrees with the agent (C1-C7)

Quotes: "the score and the exit code of `lgtm review` use only \"supported\"" / "The judge-eval labels file is empty, so its accuracy numbers are based on 0 examples." / "Kev's severity is unreliable." / "Kev mostly agrees with the agent instead of checking it."

Current code:
- The Kev judge implementation is not on the checked-out branch. Under `src/lgtm/validation/` only `evidence.py` and an untracked `judge_examples.py` exist; `judge_examples.py` holds an `EXAMPLES` dict of worked examples for the questions `supported`, `verdict`, `severity`, `provenance_confidence`. Other local branches (names beginning `build/kev-support-bench/`) and a `.tmp/build/kev-support-bench/` work area exist.
- `src/lgtm/cli.py`, `review`: exits 1 when any finding has `verdict == "vulnerable"`, otherwise 0 (2 on exception). The verdicts are the agent finding verdicts (vulnerable, possible, insufficient_evidence, safe).
- `src/lgtm/validation/evidence.py`, `EvidenceValidator.validate_all`, `_validate_code_item`, `_snippet_in_text` (fuzzy threshold `FUZZY_THRESHOLD`): sets `evidence_valid` and `evidence_issues` by matching quoted snippets against the base file, a snapshot or the PR diff.
- `benchmark/evaluate.py`, `predict_case_verdict`, `_relevant_verdicts`, `score_case`: the grounded option downgrades a `vulnerable` finding without `evidence_valid` to `possible`; TP/FP/FN/TN/UNCREDITED derive from that. No verdict-accuracy metric exists in this file.
- `src/lgtm/agents/sast_triage.py`, `SASTTriageAgent.triage`, `SYSTEM_PROMPT`, `USER_PROMPT`: produces an `AgentFinding` per Semgrep finding.

### Measurement gaps (D1-D5), by code

- D1: `benchmark/real_world/cases.json` holds the 12 real-world cases.
- D2: see problem 3.
- D3: `AgentToolbox.call_log` keeps tool name and args in memory and is reset by `reset_budget`; `src/lgtm/review/coverage.py` `SectionResult` stores status, verdicts, finding ids and error only. Whether `call_log` or the raw model answer reaches per-case result JSON was not checked.
- D4: `benchmark/evaluate.py` `_relevant_verdicts` and `predict_case_verdict` keep only findings whose `category` equals the case category, `""`, `"sast"` or None.
- D5: `benchmark/runs/README.md` marks the `real_world/` row "Held-out: no tuning".

## Questions and gaps

- Which branch holds the Kev judge code, labels file and bench report referenced in C1-C7? It is not in this checkout.
- The issue names a `grounded_in_pr` flag; no such field was found here (problem 2). It may exist at the benchmarked commit.
- Cluster outputs (job 337363) are not in the repository; cited numbers were not verified.
