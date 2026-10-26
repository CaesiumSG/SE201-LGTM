# tests-unit-repair-1 (scope-rule, Unit, H1)

Fixed: tests/test_graph_prompts.py, TestSectionReviewScopeRule. Six lines (396, 400, 406, 407, 415, 427) held literal 0x08 bytes inside raw strings where `\b` was meant; replaced each with the two characters `\b`. Patterns otherwise unchanged; assertions not weakened. 0 bytes of 0x08 remain.

Run: `.venv/Scripts/python.exe -m pytest tests/test_graph_prompts.py -q` -> 168 passed in 58.98s.

Production files untouched. Note: intermediate edits in this run were corrected before the final run; only the final state was tested.
