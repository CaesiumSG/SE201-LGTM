# AI Use Log: Hsu Yati Ko

## 2026-10-17 · Diff reader hardening
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** src/lgtm/diff/git_diff.py, tests/test_diff.py
- **Outcome:** Kept

### What I asked for
Fixes for the git diff reader so a review does not crash on real PRs:
decode git output as UTF-8 with replacement, so files that are not valid
UTF-8 no longer crash the review, and unquote file paths that git puts in
quotes.

### How I checked it
Read the change myself. Added 142 lines of tests in `tests/test_diff.py`
for non-UTF-8 content and quoted paths, and checked that normal diffs give
the same result as before. Ran the full test suite. Merged through PR #5.

### What I kept or changed
Kept as generated.


## 2026-10-18 · Checkpoint and README update
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** README.md, docs/checkpoint.md, docs/checkpoint.pdf, docs/ai-use-log.md
- **Outcome:** Changed

### What I asked for
Updates to the checkpoint report and the README so that they describe the
three benchmarks (Shoply, real-world CVEs, prompt injection) separately,
with the question, cases, script and metric for each, and add the
prompt-injection results.

### How I checked it
Read the text myself and checked every number against the committed run
files and the prompt-injection write-up, not against the AI's output.

### What I kept or changed
Edited the wording before committing.


## 2026-11-06 · Full git history in CI
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** .github/workflows/tests.yml
- **Outcome:** Kept

### What I asked for
Why the fix-rule tests failed in CI but passed locally, and a fix.

### How I checked it
The AI found that CI checked out only the latest commit, so the tests could
not read their base commit. I read the change (`fetch-depth: 0` on the
checkout step) and checked that the tests passed in CI after it. Merged
through PR #36.

### What I kept or changed
Kept as generated.


## 2026-11-09 · RAG pipeline review and base-branch policy fix
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** src/lgtm/rag/indexer.py, src/lgtm/rag/retriever.py, src/lgtm/pipeline.py, src/lgtm/cli.py, src/lgtm/validation/evidence.py, src/lgtm/reporting/report_builder.py, tests/test_policy_base.py, tests/test_rag.py, README.md
- **Outcome:** Changed

### What I asked for
I reviewed the RAG pipeline by reading the code in detail. I used the AI to
explain parts I was unsure about and to confirm or reject flaws I suspected.
Then I asked it to fix the flaws I found: the policy index could be built
from the PR's own docs or the working tree, so a PR could change the policy
it was judged against.

### How I checked it
Checked each flaw myself in the code before accepting it. The fix indexes
docs from a given commit (`lgtm index --ref`), uses the index only when it
was built from the base commit, and stops the evidence check reading docs
from the working tree. I read the change and the new tests
(`tests/test_policy_base.py`, `tests/test_rag.py`) and ran the full test
suite.

### What I kept or changed
Changed the fix after review before committing.


## 2026-11-09 · One-command run script and README update
- **Tool (model):** Claude Code (Claude Opus 5.5)
- **Files:** run-lgtm.sh, README.md
- **Outcome:** Changed

### What I asked for
`run-lgtm.sh`, a script that runs a whole review with one command: install,
GPU job, tunnels, index and review. Then a way to test it with a sample
repo, a README section about the script, and updates to the Architecture
section and the Project layout so that they match the code.

### How I checked it
Read the new Architecture text against `pipeline.py` and `cli.py`. This
showed that the first draft of the exit codes was wrong: a crashed review
also exits with 2, and a policy doc change only gives 2 when
`fail_on_policy_change` is on. Checked the Project layout against the files
in the repo. Checked the script with `bash -n`, and tested the "report is
newer than the start of the review" check on its own with an old file, a
new file and a missing file.

### What I kept or changed
Corrected the exit-code text before committing. Checking the exit codes also
found a bug in the script: after a crash it printed "read the report" and a
report path when no report had been written. Fixed it so the script now
reports the crash and exits with 3. The commits for this work
(`77364fd`, `66a9dec`, `8294e61`) were pushed without an attribution
trailer; this entry records the AI use instead.


## Reflection

### What I learned about using these tools effectively
I learned to check what the AI writes against the code. When I did, I found
real mistakes. The first draft of the exit codes in the README was wrong.
I read the code myself first. I used the AI to explain parts I did not
understand and to confirm or reject flaws I suspected, not to find the
flaws for me. I also asked it to guide me step by step while I ran the
commands myself, so I understood the work and it stayed mine. Asking it to
give file and line references made its answers quick to check, and that is
how I caught its mistakes.

### Where the tools were strong, and where they were weak
The tools were strong at explaining unfamiliar code quickly, such as the
Semgrep filter, the context budget, the investigator and the judge. They
were also good at finding the cause of a confusing failure. For example,
it found that our tests failed only in CI because CI checked out just the
latest commit. They were weak in three ways. First, they stated wrong
details with confidence. For example, it first told me that SAST triage
decides whether a bug is real, and only later found from the prompt that
it does not. Second, they missed edge cases. The first version of
`run-lgtm.sh` printed "read the report" after a crash, when no report had
been written. Third, some of the explanations were hard to understand.

### What went wrong, and what I would do differently
None of my commits have an `Assisted-by` trailer. Next time I would add it
to every AI-assisted commit as I go. I also wrote most of my log entries
afterwards, not with the work. Next time I would write each entry when I
commit the work it describes.
