# Benchmark results shown by the dashboard and the viewer

A copy of the result files that the dashboard (accuracy page, imported history) and `viewer/` read, so a fresh
clone shows them without re-running anything. One JSON file per case and mode, plus each mode's `summary.json`.

| Folder | What | Modes |
|---|---|---|
| `heldout_v21/` | 17 held-out advisories, v2.1 (section SQL-injection reviewer on) | lgtm, llm-only |
| `heldout_v20/` | the same 17, v2.0 (before the SQL-injection reviewer) | lgtm |
| `real_prs_sqli/` | the 4 SQL-injection development advisories, v2.1 | lgtm |
| `real_prs/` | 13 development advisories, v2.0 | lgtm, llm-only, sast-only |
| `diffs/<project>/<base>..<head>.patch` | each case's diff (Python files, `git diff -U4 --find-renames`), so the dashboard and viewer can show it without the multi-GB clone cache | |

Reviewer Qwen 3.8 27B with the Kev-4B judge, 5 November 2026. Case definitions: `benchmark/real_prs/cases.json`
(development) and `benchmark/real_prs/heldout.json` (held-out). The final evaluation (6 and 7 November, 33 runs)
is reported separately in `docs/`.

Deliberately not here: live-hunt results and field-trial records. Most live-hunt leads are undisclosed, and the
field trial contains an unreported finding; neither may be published.
