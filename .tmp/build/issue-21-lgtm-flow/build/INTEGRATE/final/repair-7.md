# repair-7

Nothing run or verified.

- final-01: src/lgtm/validation/evidence.py read_cited_code: unlabelled item (no conflict, strict mode) reads from the first of pr, base where _validate_code_item on a snapshot-labelled copy has no issues; falls back to pr, base as before. Labelled and null-shas paths unchanged. benchmark/citation_export.py export_run: null snapshot reads pr, then base when the pr read does not contain the quoted content (whitespace/case-insensitive); falls back to the pr read. New helper _holds. Labelled units unchanged.
- Follow-up: benchmark/citation_export.py change reverted to the original (null snapshot reads PR head only; unreadable when absent there), as tests/test_judge_eval.py:1567-1586 require. final-01 is not applied in the export: a recorded null snapshot cannot distinguish a removed-line citation from a PR-head one. evidence.py read_cited_code is unchanged by this: the null-shas path reads as before, and the pr-then-base choice applies only when shas exist and pr fails validation while base passes.
- final-02: src/lgtm/cli.py: the `verdict == "vulnerable"` clause counts only when mode is not lgtm/lgtm-no-sast. README.md exit-code paragraph names the baseline modes (sast-only, llm-only).
- final-03: benchmark/real_world/README.md documents evaluate_real.py exit 4 (git cannot start for two units in a row) and exit 0 otherwise.

Notes
- final-02: an injection finding in lgtm mode now yields exit 0, or exit 2 if it carries not_judged_reason. Not checked whether it carries one. A test for the cli rule is not written.
- citation_export with null snapshot and no pr_sha now reads base where it previously gave unreadable.
- Existing tests asserting the old cli verdict count in judged modes may need updating.
