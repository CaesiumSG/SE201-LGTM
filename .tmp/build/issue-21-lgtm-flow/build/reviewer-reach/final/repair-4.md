# repair-4: tests for final-01, final-02 (Unit, reviewer-reach)

File written: tests/test_agents.py only. `_initial_input` gained an optional `config` argument. Three tests were added to `TestEnclosingDefinitionInInitialInput`.

## New tests
- test_one_hunk_removing_from_one_function_and_adding_to_another_brings_both (final-01). Base has `view` and `other`. One hunk deletes a line in `view` (base snapshot) and adds a line in `other` (PR snapshot). Asserts DEL_TOP, DEL_BOTTOM, OTH_TOP and OTH_BOTTOM all appear.
- test_one_hunk_adding_to_two_functions_brings_both (final-01). One hunk has added lines in two functions. Asserts both bodies appear.
- test_enclosing_definition_omits_comments_when_strip_comments_is_on (final-02). `LGTMConfig(strip_comments=True)`, with a comment line inside the enclosing function. Asserts the function still renders and the comment marker is absent.

The tests use the existing fake-model and `run_git` snapshot fixtures. Nothing else is mocked.

## Run
Command: `.venv/Scripts/python.exe -m pytest tests/test_agents.py -k "one_hunk_removing or one_hunk_adding or strip_comments_is_on" -q`

- First run: 3 failed.
  - Two-function-add test: failed on `TWO_TOP` not in the prompt. The behavior was absent, as final-01 says.
  - Strip-comments test: failed because COMMENT_MARKER was in the enclosing block. The behavior was absent, as final-02 says.
  - Mixed removed/added test: it failed, but I did not read its assertion message.
- Second run, minutes later: 3 passed. `git status` shows `src/lgtm/agents/authz_reviewer.py` modified by the concurrent developer between the runs. The passes reflect their fix, not a test defect.
- I ran only these three tests. No full suite, lint or type check.

## Limits
- The mixed test's first-run failure cause is not confirmed.
- The tests are not checked against the final production diff beyond the passing run.
- Not covered:
  - Same-name dedup (a modified function shown only once).
  - strip_comments with the base snapshot (removed code).
