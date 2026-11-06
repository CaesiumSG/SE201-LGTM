# Component benchmark results

*November 2026. Benchmark design and label formats: [`component-bench.md`](component-bench.md).*

## 1. What is being tested

LGTM reviews a pull request (PR) for two kinds of security bug:

- **SQL injection (SQLi):** user input is pasted into an SQL string instead of being passed as a bound parameter.
- **Broken authorization (authz):** an endpoint lets a user read or change something they don't own, for example a missing ownership check.

The review is a pipeline of separate parts. The benchmark scores the four AI parts:

| Component | What it does | Model |
| --- | --- | --- |
| **SAST triage** | Semgrep, a pattern-matching scanner, flags suspicious SQL lines. An LLM agent then investigates each flagged line and gathers evidence. | `qwen3.8:27b` |
| **Authz reviewer** | Reads one section of the PR and reports any authorization bug. | `qwen3.8:27b` |
| **SQLi reviewer** | Reads one section and reports SQL injection. It doesn't wait for Semgrep to flag a line. | `qwen3.8:27b` |
| **Kev judge** | Reads each finding with its cited code and decides whether the finding is real and how severe it is. | Kev-4B (fine-tuned 4B model) |

The LLM agents can use **tools** while they work:

- `read_file` opens a file.
- `grep_repo` searches the repository text.
- `search_policy` looks up the project's security policy.
- `investigate_base_code` and `investigate_pr_code` query **CodeGraph**, an index of every function and who calls it, for the code before and after the PR.

Each agent gets the same toolbox it has in production. SAST triage doesn't use CodeGraph.

A **component benchmark** tests each part on its own, with the right inputs handed to it. So a bad score points to one component, not to the pipeline as a whole.

## 2. How it was tested

### Test cases

There are 25 cases. Each one is a real open-source project at a specific pair of commits: before the PR and after it.

- **12 real-world cases:** 6 projects, each in two versions. One version introduces the bug (*vulnerable*); the other is the fixed code (*safe*).
  - SQLi: pyload, postgraas, alerta.
  - Authz: aegra, langflow, litellm.
- **13 development cases:** real PRs that introduced a vulnerability upstream.
  - 4 SQLi: superset, litellm, redash, django.
  - 9 authz: sqladmin, weblate, wger, pretix, two airflow cases, redash, zulip, paperless.

Each project is cloned locally and checked out at the exact commits. The tools read that real code.

### Answer keys ("gold labels")

Each component has an answer key: for each input, what a correct component should output. For example, "this flagged line is a real injection, keep it" or "this line is safely parameterized, drop it".

### Scoring terms

Most components make a yes/no call ("is this a real bug?"). Each call falls into one of four buckets:

| | Really a bug | Not a bug |
| --- | --- | --- |
| **Component said "bug"** | True positive (TP) | False positive (FP): a false alarm |
| **Component said "no bug"** | False negative (FN): a miss | True negative (TN) |

From these counts:

- **Precision** = TP / (TP + FP): of the things it flagged, how many were real. Low precision means many false alarms.
- **Recall** = TP / (TP + FN): of the real bugs, how many it caught. Low recall means many misses.
- **F1** = the harmonic mean of the two, as one summary number. It is high only when both are high.

A test unit can also end as an **error**, for example when a service timed out. Errors are left out of the scores, not counted as wrong. A unit marked **not scored** has no valid answer key for that input.

### Setup

The agents use `qwen3.8:27b` and the judge is Kev-4B. Both ran on one A40 GPU on the SCIS Origami cluster, as a Slurm batch job. The laptop reached them through SSH tunnels.

## 3. Results at a glance

| Component | What we measure | Precision | Recall | F1 |
| --- | --- | --- | --- | --- |
| SAST triage (+ Kev) | Keep the real flagged lines, drop the false alarms | 0.60 | 0.86 | **0.71** |
| Authz reviewer | Find the authz bug, stay quiet on fixed code | 0.89 | 0.80 | **0.84** |
| SQLi reviewer | Find the injection in a section | 1.00 | 1.00 | **1.00** |
| Kev judge | Real or not real; how severe | 89% verdicts correct, 55% severities correct | | |

## 4. Results by component

### 4.1 SAST triage + Kev judge

**Test.** The benchmark gives the triage agent one Semgrep-flagged line plus that file's PR diff. Each case has two flagged lines:

- **Gold line:** the real injection, which should be **kept**.
- **Decoy ("distractor") line:** a similar-looking SQL line that is actually safe, which should be **dropped**.

The agent investigates with its tools and returns an explanation plus quoted evidence. That is checked and passed to Kev, exactly as in production. The finding is **kept** if Kev says it is supported. If the agent cites no evidence at all, it is dropped without asking Kev.

**How it is scored.** Only the final keep/drop decision is scored. The triage agent gives no verdict of its own by design: its prompt says Kev decides.

**Results** (18 flagged lines scored):

| Real bugs kept (TP) | Real bugs missed (FN) | False alarms (FP) | Correctly dropped (TN) | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| 6 | 1 | 4 | 7 | 0.60 | 0.86 | 0.71 |

**What it means.**

- **It catches most real injections:** 6 of 7.
- **The false alarms follow a pattern.** All 4 are decoy lines inside PRs that really are vulnerable (pyload, postgraas, alerta, superset). Every decoy inside a safe PR was correctly dropped.
  - The likely cause is that the agent sees the real bug elsewhere in the diff and attaches it to the line it was handed.
  - In practice the PR would be flagged anyway, but the report would point at the wrong line.
- **The one miss** is django: Kev rejected the real finding.
- **litellm is not scored.** The upstream PR's commits no longer exist on GitHub, so that development case can't be rebuilt.

### 4.2 Authz reviewer

**Test.** The reviewer gets the section of the PR that contains the bug, plus its tools.

- On a **vulnerable** case, a finding counts as a hit (TP) if it lands in the same function as the known bug location. No report there is a miss (FN), and a report anywhere else is a false alarm (FP).
- On a **safe** case, silence is correct (TN) and any report is a false alarm.

**Results** (13 cases scored):

| TP | FN | FP | TN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
| 8 | 2 | 1 | 3 | 0.89 | 0.80 | 0.84 |

**What it means.**

- **Few false alarms.** It stayed quiet on the fixed versions of aegra, langflow and litellm.
- **Two misses:**
  - **redash dashboard fork:** no finding at all.
  - **paperless share links:** it found a real-looking problem (objects with no owner pass the permission check) but not the labelled bug location. So it counts as both a miss and a false alarm.
- **Two errors, both airflow cases:** CodeGraph couldn't finish indexing the very large airflow repository within its time limit. Those units are excluded, not marked wrong.

The reviewer made 14 CodeGraph queries, 12 policy searches, 36 file reads and 23 searches.

### 4.3 SQLi reviewer

**Test.** Same as authz, but for SQL injection, on the 10 SQLi cases. Each hit is also tagged with how it was found:

- **`sast_also`:** Semgrep had already flagged that line.
- **`reviewer_only`:** only the reviewer found it.

**Results** (9 cases scored):

| Hits | False alarms | Precision | Recall | F1 | Found only by the reviewer |
| --- | --- | --- | --- | --- | --- |
| 6 / 6 | 0 | 1.00 | 1.00 | 1.00 | 2 (postgraas, litellm) |

**What it means.**

- The reviewer found every injection with no false alarms.
- It found 2 that Semgrep did not flag.
- alerta (vulnerable) is not scored: its bug section has no SQL keywords, so the pipeline would never send it to the SQLi reviewer.

### 4.4 Kev judge

**Test.** Kev gets 29 candidate findings, each with a claim, a CWE (weakness type) and the cited code expanded to its whole enclosing function. It answers:

- **Verdict:** is this real?
- **Severity:** low, medium, high or critical.

Where more than one answer is defensible, the answer key accepts all of them. One candidate's key is "undetermined", so 28 are scored.

**Results:**

| Verdict correct | On real findings | On not-real findings | Severity correct (real findings only) |
| --- | --- | --- | --- |
| 25 / 28 = **0.89** | 21 / 23 = 0.91 | 4 / 5 = 0.80 | 0.55 |

**What it means.** Kev is good at real-versus-not-real but weak at severity.

- **Verdict misses (3):**
  - **alerta:** missed an unchecked sort field that reaches an f-string.
  - **superset:** missed the `where_in` filter.
  - **langflow:** called the *fixed* delete-key route real, while also answering "not supported".
- **Severity misses:** most are Kev saying "high" where the key expects another level, on the newer authz cases.
