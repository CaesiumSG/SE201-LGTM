# Evaluation Log: what worked, what didn't, what we learned

This is the running record of every benchmark round: what we ran, what went
wrong, why, what we changed, and what we learned. The aim of the project is
to *learn* where an LLM helps pre-merge security review, so failures are
recorded as carefully as successes.

- **Setup for all rounds:** `qwen2.5-coder:7b` on Ollama (local, temperature
  0), Semgrep CE with the bundled rules, and the Shoply benchmark. The
  benchmark has 36 cases (12 SQLi pairs + 6 authz pairs), split 50/50 into
  dev and eval sets.
- **Scoring:** a case counts as "flagged" iff a finding *in the case's own
  category* says `vulnerable`.
- **Raw data:** every round's per-case JSON and `summary.json` live in
  [`benchmark/runs/`](../benchmark/runs/) (index in its README).
- **Re-scoring:** `python benchmark/evaluate.py --mode <m> --rescore --output
  <dir>` re-applies the current scoring rules to a saved run without calling
  the model.

## Headline (final, 13 Oct)

| | sast-only (A) | llm-only (B) | lgtm-no-sast (ablation) | **lgtm (C)** |
|---|---|---|---|---|
| F1, all 36 | 0.62 | 0.75 | 0.92 | **0.94** |
| F1, held-out eval (18) | 0.63 | 0.75 | 0.89 | **0.89** |
| SQLi F1 / FP rate | 0.73 / 0.75 | 0.92 / 0.17 | 0.92 / 0.08 | **0.96 / 0.00** |
| Authz F1 | 0.00 | 0.00 | 0.92 | **0.92** |
| Off-category false alarms | 0 | 0 | 21 / 36 | 22 / 36 |

**Proposal success criteria:**

1. *Beat SAST-only and LLM-only on authz F1:* ✅ (0.92 vs 0.00 and 0.00).
2. *Match or reduce SAST false positives on SQLi without losing true
   positives:* ✅ for false positives (75% → 0%). ⚠️ For true positives,
   11/12 vs SAST's 12/12; the miss is a triage error that flips between
   runs.
3. *At least 80% of vulnerabilities found with appropriate evidence:* ✅ on
   all 36 (grounded recall 0.89). ⚠️ On the eval split alone, grounded
   recall is 0.78.

Biggest open weakness: ownership false alarms on most SQLi-case endpoints
(see rounds 4–5).


---

## Round 1: original pipeline (10 Oct)

**What we ran:** `sast-only`, `lgtm`, and what was then called `llm-only`,
on all 36 cases.

**Reported at the time:** sast-only F1 0.58 · lgtm 0.90 · llm-only 0.92.
LGTM looked slightly *worse* than the LLM-only baseline.

### Problems found when reviewing round 1 (13 Oct)

| # | Problem | Type | How we found it |
|---|---|---|---|
| 1.1 | **The "LLM-only" baseline wasn't LLM-only.** It got the same policy RAG, the same tools, and a regex SQL detector in place of Semgrep. The proposal defines Baseline B as "without SAST output or business-document RAG or tools". So the comparison could not show what RAG and tools add, and on authz the two modes ran *identical* code paths (both authz F1 = 0.923). | Experimental-design bug | Read `pipeline.py` against proposal §5 line by line |
| 1.2 | **The scorer credited the wrong agent.** If a case had no finding in its own category, `predict_case_verdict` fell back to *all* findings. `sqli_07_vulnerable` was scored a TP only because the authz agent complained about the endpoint; no SQLi finding existed. Two SQLi-safe cases were FPs for the same reason. | Evaluation bug | Rescoring after the fix changed 3 outcomes |
| 1.3 | **Semgrep missed `sqli_07_vulnerable`.** The rule `$CUR.execute("..." + $X, ...)` does not match `"... = '" + x + "'"`, which parses as `("..." + x) + "'"`. | SAST rule gap | Subagent root-cause analysis; reproduced with semgrep |
| 1.4 | **The agents never used their tools.** `tool_calls_used == 0` on all 124 findings. `qwen2.5-coder` writes tool calls as JSON *text* (`{"name": "read_file", "arguments": ...}`) instead of native tool calls, so the loop treated them as final answers. Live probing also showed that, given the pre-retrieved policy, the model usually doesn't *try* to use tools at all. | Pipeline bug + model behaviour | Per-finding audit; direct probe of the model |
| 1.5 | **The evidence validator rejected 3 correct citations.** Its fuzzy matcher stepped through the file in half-window strides and skipped the aligned offset, so a near-verbatim snippet with one elided line (similarity 0.90) failed. It also didn't strip `#anchor` / `:symbol` suffixes from cited paths. | Validator bug | Re-validated all 13 "ungrounded" findings by hand |
| 1.6 | **Ungrounded detections counted as hits.** The validator only *labels* findings; a `vulnerable` verdict with fabricated evidence still counted as a TP. The proposal's success criterion requires detections "with appropriate evidence". | Metric gap | Spec review |
| 1.7 | **Hidden authz false alarms.** The authz agent said `vulnerable` for **22 of the 24** endpoints in SQLi cases, almost always "doesn't verify ownership", on endpoints already guarded by `@require_role("admin")`. Case-level scoring could not see this, because those cases are scored on SQLi only. | Model reasoning error, invisible to the metric | Per-finding audit |
| 1.8 | **The model never hedges.** 0 `possible` and 0 `insufficient_evidence` across 124 findings; confidence was always 0.9–1.0. | Model behaviour | Per-finding audit |
| 1.9 | Stale docs: README said 105 tests / 24 cases; default model `qwen2.5:7b` (not installed); sast-only summary recorded a model name. | Docs | Review |

### Learning

> **A benchmark result is only as good as the scorer and the baselines.**
> Two of our three headline numbers came from evaluation bugs, not from the
> system. Neither was caught by unit tests, because the tests encoded the
> same assumptions as the code. The fixes came from re-reading the
> implementation against the written proposal and auditing *individual
> findings* rather than aggregate F1.

---

## Round 2: a real LLM-only baseline (13 Oct)

**Change:** rebuilt `llm-only` exactly as the proposal defines it
(`agents/plain_reviewer.py`): one tool-free LLM call over the diff, with no
Semgrep, no RAG and no tools. The old setup is kept as an *ablation*,
`lgtm-no-sast`. Also fixed problem 1.2 (scorer) and added grounded and
off-category metrics (1.6, 1.7). Round 1 was re-scored with the fixed scorer.

| Mode | P | R | F1 | SQLi F1 | Authz F1 | FP rate (safe) | Grounded F1 |
|---|---|---|---|---|---|---|---|
| sast-only | 0.55 | 0.61 | 0.58 | 0.69 | 0.00 | 0.50 | 0.58 |
| **llm-only (new, correct)** | 0.86 | 0.67 | **0.75** | **0.92** | **0.00** | 0.11 | 0.71 |
| lgtm (round 1, re-scored) | 0.94 | 0.89 | 0.91 | 0.91 | 0.92 | 0.06 | 0.91 |
| lgtm-no-sast (round 1, re-scored) | 0.90 | 0.94 | 0.92 | 0.92 | 0.92 | 0.11 | 0.94 |

### What worked / what didn't

- ✅ **This is the result the project needed.** Without the security policy,
  the bare LLM caught **0 of 6** authorization flaws. Without context it
  can't confirm a violation: it answered `possible` on all 6 vulnerable
  authz PRs, but also on 5 of the 6 *safe* ones. Even if `possible` counted
  as a detection, it can't separate safe from vulnerable. Policy retrieval
  is what makes authz review work.
- ⚠️ **On SQL injection, the bare LLM is already strong** (12/12 detected,
  2 false alarms on 12 safe cases). On this benchmark, a 7B code model
  recognises string-built SQL by itself. SAST adds less than we expected
  for SQLi; LGTM's real advantage is on the policy-dependent class.
- ✅ The four-way verdict scheme did its job for the first time: `possible`
  appeared exactly where the model lacked context.

---

## Round 3: bug fixes, all modes (13 Oct)

**Changes (bug fixes only, no prompt tuning, so the eval split is still
clean):**

1. Text-form tool calls are now parsed and executed (`agents/base.py`,
   `parse_text_tool_calls`). Fixes 1.4.
2. Validator: stride-1 matching, and `#anchor` / `:symbol` stripping
   (`validation/evidence.py`). Fixes 1.5; re-validating the round-1 false
   alarms now passes all 3.
3. Semgrep rule for concatenation ending in a literal
   (`sast/rules/sql-injection.yaml`). Fixes 1.3: Semgrep SQLi recall goes
   from 11/12 to 12/12 with **no** new false positives. `sqli_07` is a dev
   case, so this is legitimate tuning.
4. Default model `qwen2.5-coder:7b`; docs corrected. Fixes 1.9.

Regression tests were added for every fix: `tests/test_baselines.py`,
`test_facts.py`, and the new cases in `test_agents.py`,
`test_validation.py` and `test_semgrep.py`.

**Results (all 36 cases, `benchmark/runs/run3-bugfixes/`):**

| Mode | P | R | F1 | SQLi F1 | Authz F1 | FP rate (safe) | Grounded F1 | Grounding | Off-category alarms | Median latency |
|---|---|---|---|---|---|---|---|---|---|---|
| A: sast-only | 0.57 | 0.67 | 0.62 | 0.73 | 0.00 | 0.50 (SQLi 0.75) | 0.62 | 1.00 | 0 | 1.8s |
| B: llm-only | 0.86 | 0.67 | 0.75 | 0.92 | 0.00 | 0.11 | 0.75 | 0.78 | 0 | 11.9s |
| ablation: lgtm-no-sast | 0.90 | 0.94 | 0.92 | 0.92 | 0.92 | 0.11 | 0.89 | 0.90 | 21 / 36 | 20.5s |
| **C: lgtm** | **0.95** | **1.00** | **0.97** | **1.00** | **0.92** | **0.06** | 0.94 | 0.96 | 22 / 36 | 20.7s |

Held-out eval split only (n = 18): sast-only 0.63 · llm-only 0.75 ·
lgtm-no-sast 0.89 · **lgtm 0.95**.

### What worked / what didn't

- ✅ **LGTM is the best mode on every headline metric.** It's the only mode
  with perfect SQLi (12/12 caught, 0/12 false alarms). Semgrep finds every
  candidate sink and the triage agent dismisses all 9 parameterized
  controls Semgrep wrongly flags. That meets the proposal's second success
  criterion: SAST false positives fall from 75% to 0% with no loss of true
  positives.
- ✅ **What Semgrep adds over the regex detector (ablation):** the
  no-SAST ablation misses `sqli_04_vulnerable` and false-alarms on
  `sqli_03_safe`. SAST seeding is worth about one SQLi case per pair-set
  here: small, but consistent across rounds 1 and 3.
- ❌ **The one remaining case-level error, `authz_06_safe`**, is an
  API-key-scoped report endpoint (`@require_api_key_scope("reports:read")`)
  that returns every user's orders. The model applies the per-user
  ownership rule (§3) to a machine-integration endpoint that §6 explicitly
  allows. It fails the same way in every round and every mode with RAG.
- ❌ **Tools are still never used** (0 calls on all 67 findings). The parsing
  fix works (unit-tested), but the model doesn't attempt calls when the
  prompt already holds the diff and policy.
- ❌ **Off-category false alarms are unchanged** (22 of 36). This is the
  largest real weakness: on a real codebase, developers would see an
  ownership warning on most endpoints that touch user data.
- ⚠️ **A verdict flipped for an irrelevant reason.** `sqli_04_vulnerable`
  went from FN (round 1) to TP (round 3) with *no* prompt change. Root
  cause: Semgrep prefixes rule IDs with the **absolute path of the rules
  directory** (`Users.<name>.projects...lgtm-python-sqli-format`), that ID
  is pasted into the prompt, and round 3 ran from a different directory.
  Fixed (`semgrep_runner._short_rule_id`, with a regression test). Rule IDs
  are now path-free, which also stops the user's home path leaking into
  prompts and reports. The committed run files were sanitized the same
  way.

### Learning

> **Same input → same output, but tiny irrelevant changes flip verdicts.**
> At temperature 0, re-running an identical prompt was perfectly
> reproducible: `llm-only` and `lgtm-no-sast` matched their earlier runs
> case for case. But changing only a file path inside the prompt flipped a
> security verdict. A 7B model's decision boundary is fragile, so a single
> case flipping is noise, not progress. With 18 eval cases, one flip moves
> F1 by about 0.05.

---

## Round 4: improvement experiments, dev split only (13 Oct)

Two problems were left: the authz agent's **off-category false alarms**
(1.7) and **unused tools** (1.4, second half). Fixing them means changing
prompts and context. Doing that while looking at the eval split would leak
the held-out cases, so both changes sit behind config flags and were
measured on the **dev split only**. Round 3's dev split (flags off) is the
control.

- **`static_facts`:** deterministic AST facts in the prompt
  (`analysis/facts.py`). For triage, e.g. "line 54: `execute()` receives a
  query built from %-string formatting with user_id (NOT a bound
  parameter); bound-parameter argument passed: NO". For authz, e.g.
  "decorators applied: `@require_role('admin')`". Triage also gets the
  policy excerpt the authz agent already received.
- **`require_tool_use`:** if the agent answers before using any tool, push
  back once and ask it to verify against the repository.

All arms ran from one frozen code snapshot (after the rule-ID fix), so the
only difference between arms is the flag. Data:
`benchmark/runs/run4-dev-experiments/`. A planned fourth arm (both flags
together) was dropped once the first two results were in; round 5
replaces it.

| Arm (dev, n = 18) | Case F1 | Off-category alarms | Grounding | Tool calls per finding | `possible` verdicts | Median latency |
|---|---|---|---|---|---|---|
| control (flags off) | 1.00 | 11 / 18 | 0.91 | 0 | 0 | 18.6s |
| `static_facts` | 0.94 (new FN: `sqli_03_vulnerable`) | 11 / 18 | **1.00** | 0 | 2 | 25.2s |
| `require_tool_use` | 1.00 | 10 / 18 | 0.97 | **6–7 (every finding)** | 1 | **122.3s** |

### What worked / what didn't

- ⚠️ **The dev split is saturated.** The control already scores F1 = 1.00
  on dev, so case-level F1 can't show improvement there; it can only show
  harm. The off-category alarm count and grounding were the only metrics
  that could move. Lesson: once a benchmark is saturated, tune on the
  metric that still has headroom, and grow the dataset.
- ✅/❌ **Static facts made citations perfectly grounded (1.00), but did not
  touch the false alarms**, and they introduced a new miss.
  - Telling the authz agent "decorators applied: `@require_role('manager')`"
    did not stop it claiming that "any manager can view other users'
    orders". The model *had* the fact; its error is in **reading the
    policy**, not in seeing the code.
  - The new miss: with the policy's allowlist rule now in its context,
    triage hedged to `possible` on `sqli_03_vulnerable` ("`sort_by` could be
    user-controlled… no evidence of a whitelist"). The assignment
    `sort_by = request.args.get(...)` was in the diff. **More context made
    the model less decisive**, the opposite of what we expected.
- ❌ **Forcing tool use is expensive and barely helps.** Once pushed, the
  model calls tools *until the budget runs out* on every finding: 12 runs
  hit the iteration cap, and latency rose 6.6×. Grounding improved a
  little; off-category alarms fell by one, which is within noise. A 7B
  model can't judge when it has gathered enough evidence. We keep
  `require_tool_use` off by default.

### Learning

> **Context is not free.** Pre-retrieved policy plus code facts gave
> grounded citations, but did not fix reasoning errors, and sometimes
> pushed the model from a correct `vulnerable` to a hedged `possible`.
> Every added prompt section needs its own measurement.

---

## Round 5: targeting the two round-4 failure modes, dev split only (13 Oct)

**Changes (both behind flags, run together as one arm):**

- **Facts v2** (`static_facts`): the SQL facts now also say where each
  interpolated variable comes from (e.g. "`sort_by` is assigned from
  `request.args.get(...)`: user-controlled request data") and whether it
  is membership-checked against an allowlist. This targets the round-4
  `sqli_03` hedge.
- **Role-scope guidance** (`authz_role_guidance`): a 4-step instruction
  for the authz agent. Identify the required role, find what the policy
  allows *that role* to access, report CWE-639 only if the policy
  restricts the data to its owner for that role, and if ambiguous say
  `possible`. This targets the off-category alarms.

Data: `benchmark/runs/run5-dev-role-guidance/`.

| Arm (dev, n = 18) | Case F1 | SQLi F1 | Authz recall | Off-category alarms | Grounding |
|---|---|---|---|---|---|
| control (round 4) | 1.00 | 1.00 | 3 / 3 | 11 / 18 | 0.91 |
| facts v2 + role guidance | **0.80** | 1.00 | **0 / 3** | **7 / 18** | 0.89 |

### What worked / what didn't

- ✅ **Facts v2 fixed the SQLi hedge.** `sqli_03_vulnerable` is caught again
  and SQLi stays perfect.
- ✅ **The guidance cut off-category alarms from 11 to 7.** The model now
  writes "the endpoint requires the 'manager' role, which is allowed to
  list all orders according to the policy" on 5 endpoints it used to flag.
- ❌ **It over-corrected and destroyed authz recall (3/3 → 0/3).**
  - Rule 4 ("if ambiguous, use `possible`") made the model hedge on *clear*
    violations. It correctly said authz_01 "does not check if the user is
    authorized to access the specific order", then labelled it `possible`.
  - "Identify the required role" led it to accept a bare `@require_auth`
    as sufficient for *deleting users* (authz_02: "requires authentication
    via `@require_auth`, which enforces access control").
- 🔍 **New failure mode found: category bleed.** Of the 7 remaining alarms,
  5 are on the *vulnerable* twin of a SQLi pair. In 3 pairs (`sqli_01`,
  `02`, `07`), the *safe* twin's identical endpoint and decorators were
  judged authz-safe, while the vulnerable twin was flagged. The SQL flaw in
  the diff leaks into the authorization judgment. The model reviews "is this code bad",
  not "is this specific property violated".

**Decision:** rejected. Per the dev/eval protocol, a configuration that
loses on dev is never run on the eval split. Both flags stay off by
default.

### Learning

> **A prompt fix for false positives is a recall risk.** The instruction
> that removed four false alarms also removed every true detection. With a
> small model, guidance that "relaxes" a judgment relaxes it everywhere.
> Without a dev split and per-category metrics, we would have shipped this
> change because it reduced the false alarms we were looking at.

---

## Final run: shipped configuration, clean (13 Oct)

All flags off; the code includes every round-3 fix plus the path-free
Semgrep rule IDs. Data: `benchmark/runs/run6-final/`.

| Mode | P | R | F1 | Eval F1 | SQLi F1 | Authz F1 | FP rate | Grounded F1 (eval) | Off-category alarms | Median latency |
|---|---|---|---|---|---|---|---|---|---|---|
| lgtm | 0.94 | 0.94 | 0.94 | 0.89 | 0.96 | 0.92 | 0.06 | 0.91 (0.82) | 22 / 36 | 21.3s |

The only difference from round 3 is `sqli_04_vulnerable`: TP in round 3,
FN here. Round 3's prompt carried the snapshot's file path in the rule ID;
this one doesn't. That confirms the round-3 diagnosis: the round-3 TP was
an accident of an irrelevant prompt string, and **0.94 / 0.89 is the
honest number**, not 0.97 / 0.95. The two remaining errors (`sqli_04`
triage, `authz_06_safe`) are both eval cases, so per protocol we leave
them as known failures rather than tuning on them.

---

## Cross-cutting lessons

1. **Audit the evaluator before trusting the system.** Our first headline
   result (LGTM slightly *worse* than LLM-only) came from a baseline that
   didn't match its definition, plus a scorer that credited the wrong
   agent. Fixing the evaluation, not the system, changed the conclusion.
2. **Retrieval of project-specific knowledge is the core value.** A bare
   7B model finds SQL injection on its own (92% F1) but has 0% recall on
   authorization flaws, which depend on the project's documented policy.
   Policy RAG raises that to 92% F1. This is the clearest justification
   for the LLM + RAG design.
3. **SAST and the LLM complement each other on SQLi.** Semgrep gives
   deterministic recall, now 12/12, and triage removes its false positives
   (75% → 0%). The regex-seeded ablation is close but consistently one case
   worse.
4. **Aggregate F1 hides the most important failure.** The authz agent
   raised ownership alarms on about 60% of SQLi-case endpoints, which a
   developer would experience as noise on most PRs. Only a per-finding
   audit and the off-category metric exposed it.
5. **Small local models don't use tools well.** Left alone, the model
   never called a tool; forced, it used all of them every time at 6.6×
   latency for no accuracy gain. For a 7B model, *pre-retrieving* context
   (RAG in the prompt) works better than letting it fetch context itself.
6. **Determinism is not robustness.** Identical prompts gave identical
   verdicts, but an irrelevant file path in the prompt flipped one. Treat
   single-case changes as noise; report variance; grow the eval set.
7. **Keep a strict dev/eval protocol.** Every failure we diagnosed in
   round 1 was on the *eval* split. Fixing them directly would have made
   the "held-out" numbers meaningless. We fixed only genuine bugs on eval
   cases, and tuned prompts on dev only. Two of three prompt experiments
   then turned out to be harmful on dev.
8. **The benchmark needs to grow.** Dev is saturated (F1 1.00), eval has
   18 cases (one flip = ±0.05 F1), and the SQLi cases were never labelled
   for authz, so we can't tell which off-category alarms are wrong without
   reading each one. Next: label every endpoint for both categories, add
   real-world (CVE-linked) PRs, and add prompt-injection cases.

## Open problems (not fixed)

| Problem | Why not fixed yet | Idea |
|---|---|---|
| Off-category authz alarms (~60%) | The guidance prompt that reduced them destroyed recall (round 5) | Separate "which rule applies to this role" retrieval from the verdict step; or a second-pass verifier that only reviews `vulnerable` authz findings |
| `authz_06_safe` false positive (API-key report endpoint) | Same root cause as above; it is an eval case, so we must not tune on it | Fixing the general role/scope reasoning should fix it |
| Category bleed (SQL flaw influences the authz verdict) | Found in round 5 | Give the authz agent only route, decorators and policy, not the SQL body; measure on dev |
| The validator checks existence, not relevance | A real policy line quoted for the wrong reason passes | Check that the cited policy chunk is among the chunks retrieved for this endpoint |
| Ungrounded detections still count as detections in the main score | We report grounded metrics alongside; making them the default changes the headline | Decide as a team which score is primary for the final presentation |
