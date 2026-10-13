# LGTM — Checkpoint Report (due 18 Oct 2026)

Team **"wo men ai AI"** · SE201 AI-Driven Software Engineering, AY2026-27 T1

This report covers the four checkpoint requirements in the project
specification:

- architecture in place, with stubs documented;
- a working core feature;
- the AI technique working;
- the checkpoint document itself: test results, progress against targets,
  scope changes, and the AI use log.

The detailed experiment history, with every failure we hit and how we fixed
it, is in [`evaluation-log.md`](evaluation-log.md).

## Summary

- **Status:** all architecture components are built, connected and
  evaluated.
- **Final results** (36 cases; held-out eval split in brackets):

  | Mode | F1 |
  |---|---|
  | **LGTM** | **0.94** (0.89) |
  | LLM-only baseline | 0.75 (0.75) |
  | SAST-only baseline | 0.62 (0.63) |

- **What the AI adds:**
  - Without the security policy, the bare LLM catches 0 of 6
    authorization flaws; LGTM catches all 6.
  - Semgrep wrongly flags 75% of safe parameterized SQL; LGTM's triage
    brings that to 0%.
- **What doesn't work yet:**
  - The authz agent raises ownership warnings on 22 of 24 endpoints in the
    SQLi cases, which case-level scoring doesn't count.
  - The 7B model doesn't use its tools unless forced, and forcing costs
    6.6× latency for no gain.
  - Verdicts can flip on irrelevant prompt changes.
- **Not met:** commit history from every team member, and per-member AI
  use entries. These are team actions.


## 1. Architecture: in place and connected

All five stages from the proposal (Figure 1) are implemented and run end to
end from one command (`lgtm review`):

| Stage | Component | Status |
|---|---|---|
| 1. Context building | `diff/git_diff.py` (git diff), `sast/semgrep_runner.py` (Semgrep CE, bundled CWE-89 rules), `rag/` (ChromaDB index of policy docs + source code) | ✅ working |
| 2. SAST triage agent | `agents/sast_triage.py` — CWE-89 true/false positive | ✅ working |
| 3. Authorization agent | `agents/authz_reviewer.py` — CWE-639/862/863 against the retrieved policy | ✅ working |
| Agent tools | `agents/tools.py` — `read_file`, `grep_repo`, `search_policy`, `search_code`; read-only, base branch only, 5-call budget | ⚠️ implemented, but rarely used by the model (see below) |
| 4. Evidence validator | `validation/evidence.py` — cited files/lines/snippets/policy text must exist | ✅ working (2 bugs fixed this week) |
| 5. Report builder | `reporting/report_builder.py` — `report.json` + `report.md`, CWE, evidence, suggested fix | ✅ working |
| Baselines | `--mode sast-only` (A), `--mode llm-only` (B), plus ablation `--mode lgtm-no-sast` | ✅ working |
| Benchmark harness | `benchmark/evaluate.py` — 36 cases, dev/eval split, all proposal metrics | ✅ working |

### Simplified or stubbed components (honest list)

- **Tool use is effectively unused.** The tools work: they are unit-tested,
  and we fixed a parsing bug so that text-form tool calls are executed. But
  `qwen2.5-coder:7b` answers from the pre-retrieved context and almost never
  calls them. We tested forcing tool use as an experiment (see the evaluation
  log). The "agentic workflow" claim should be read with this in mind.
- **SAST is SQL-injection only**, using 4 hand-written pattern rules. These
  are not Semgrep taint-mode rules, and not the Semgrep registry, so the tool
  works offline.
- **Endpoint detection is pattern-based**: Flask/FastAPI route decorators
  only.
- **Suggested fixes are prose, not patches.** The proposal said "propose a
  patch"; we output a textual fix suggestion. Patch generation is not built.
- **No GitHub integration.** LGTM is a CLI over two git refs; it does not
  post PR comments. A CLI is acceptable per the spec.
- **"Tokens per PR" is an estimate** (characters ÷ 4 of the findings), not
  the model's real token count.
- **The benchmark is synthetic**: one small Flask app (Shoply) with 18
  generated vulnerable/safe PR pairs. It is not mined from real-world PRs.

## 2. Core feature demonstration

```bash
# one-time: index the target repo's docs and code
lgtm index --repo /path/to/repo
# review a PR branch against its base
lgtm review --repo /path/to/repo --base main --pr feature --output lgtm-output
```

The exit code is 1 when a `vulnerable` finding is reported, so the tool can
gate CI. Sample outputs for every benchmark case (all findings, verdicts,
evidence and validation results) are committed in `benchmark/runs/`.

## 3. AI technique working

- **RAG:** the security policy, API spec and README are chunked into
  ChromaDB. The authorization agent's prompt is seeded with the top
  policy chunks for the endpoint under review. Without this context the
  bare LLM detects **0 of 6** authorization flaws; with it, LGTM detects
  them (see results). This is the clearest evidence that the retrieval
  stage does real work.
- **SAST integration:** Semgrep findings on the changed lines seed the
  triage agent.
- **Structured output + guardrails:** every finding is JSON with a verdict
  from four options, a CWE, evidence and a fix. Malformed model JSON is
  repaired. Every citation is validated after the fact.
- **Tool calling:** implemented, but under-used (see §1).

## 4. Progress against the proposal's checkpoint targets

| Target (from proposal §6) | Status | Notes |
|---|---|---|
| Runnable end-to-end CLI on an authorization PR | ✅ Met | `lgtm review` from git diff to JSON finding |
| Semgrep integration | ✅ Met | Bundled offline rules; scans PR-ref file contents |
| Policy retrieval | ✅ Exceeded | Vector retrieval (ChromaDB) rather than the keyword fallback we allowed for |
| Working LLM reviewer (CWE + remediation) | ✅ Met | Two agents, structured JSON |
| Evidence validation | ✅ Met | Two validator bugs found and fixed during evaluation |
| Connected architecture, stubs documented | ✅ Met | §1 above |
| Benchmark: base repo + ≥4 seeded cases | ✅ Exceeded | 36 cases (18 pairs), balanced dev/eval split |
| Initial evaluation round | ✅ Exceeded | Five rounds + a final clean run; see `evaluation-log.md` |
| README + setup instructions | ✅ Met | `README.md` |
| Contribution history from all five members | ❌ **Not met** | Almost every commit is from one account so far. Each member must commit their own work before 18 Oct (see §7) |
| Progress / scope-change notes | ✅ Met | This document |
| AI-use disclosure log | ⚠️ Partial | [`ai-use-log.md`](ai-use-log.md): entries reconstructed from git history; every member still needs to add their own |

## 5. Changes to scope, design and technology since the proposal

| Change | Why |
|---|---|
| Benchmark grew from 24 to **36 cases** (added 6 OWASP-Benchmark-derived SQLi pairs) | Instructor feedback: dataset too small; positives and negatives stay balanced |
| Held-out set grew from "4 pairs" to a **balanced 9 vulnerable + 9 safe eval split** | Instructor feedback; a fixed dev/eval protocol to stop us tuning on test data |
| Added a `search_code` tool (semantic RAG over the source) | Instructor feedback: retrieve code, not only docs |
| **ChromaDB** chosen over FAISS; embedding model `all-MiniLM-L6-v2` | Persistent local store with metadata (line numbers) for citations |
| Model is **`qwen2.5-coder:7b`** (proposal: "Qwen via Ollama") | Best local tool-capable model on our hardware; `qwen2.5:7b` was not available |
| Flask only (proposal: Flask/FastAPI) | One benchmark app was enough; the endpoint extractor still recognises FastAPI routes |
| **LLM-only baseline rebuilt** (13 Oct) to match the proposal: no SAST, no RAG, no tools | The first version gave the baseline the same RAG and tools as LGTM, so the comparison could not show what they add. The old setup is kept as the ablation `lgtm-no-sast` |
| Added "grounded" metrics and an off-category false-alarm metric | Proposal success criterion 3 requires detections *with appropriate evidence*; case-level scoring was hiding authz false alarms on SQLi cases |
| Added experimental flags `static_facts` and `require_tool_use` | Fixes for failures found in evaluation (see the evaluation log) |

## 6. Responsible AI: risks and mitigations so far

| Risk | Mitigation in LGTM | Residual risk observed |
|---|---|---|
| Hallucinated evidence | Evidence validator checks every cited file, line, snippet and policy quote; results are reported with and without ungrounded findings | The model still invents policy file names (e.g. `security_policy.md`) and documentation URLs; the validator cannot check *relevance*, only existence |
| Over-confident verdicts | Four-way verdict scheme including `possible` / `insufficient_evidence` | With context, the model almost never hedges (0 `possible` in LGTM runs) |
| Prompt injection from PR content | PR diff is labelled untrusted; tools read only the base branch; tools are read-only and capped | Not adversarially tested yet: no benchmark case contains an injection attempt |
| Privacy / IP | Model runs locally via Ollama, so no code leaves the machine | None for local use |
| Automation bias | LGTM reports and never auto-fixes; a human decides | Users may still over-trust a confident "safe" |
| Non-determinism | Temperature 0; identical prompts gave identical verdicts across runs | Verdicts flip when *irrelevant* prompt text changes (a file path in a rule ID flipped one); see the evaluation log |

## 7. Actions before the 18 Oct submission

1. **Every member commits their own work** to the shared repo. The spec
   checks for "a commit history showing contributions from every team
   member".
2. **Every member adds their AI-tool usage** to `docs/ai-use-log.md`.
3. Confirm the instructor has read access to `CaesiumSG/SE201-LGTM`.
