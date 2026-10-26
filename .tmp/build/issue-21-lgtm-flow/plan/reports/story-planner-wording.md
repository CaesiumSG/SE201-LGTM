# story-planner-wording

Edited `plan/stories.md`, three acceptance criteria only.

- AC-S2-2: "up to 150 lines" removed. Now: a single file read returns, without truncation, a whole function longer than the `read_file` line cap at 7f642e1. Observable, no new number (DEC-6); consistent with AC-S2-5.
- AC-S4-1: now states the scope statement appears in both `README.md` and `docs/project-proposal.md` (DEC-12).
- AC-S4-7: kept; added the clause that the benchmark measures LGTM's value over SAST on safe code SAST flags (DEC-11).

Hand-offs
- `plan/decisions.md` ends at DEC-10; DEC-11 and DEC-12 are cited from the assignment and not recorded there.
- The `stories.md` header still reads "DEC-1..DEC-10"; not changed (out of the three edits).
- Nothing else under the run dir was read.
