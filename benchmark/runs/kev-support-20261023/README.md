# Kev request-format run, 2026-10-23

Model: Kev-4B. Cluster job: 336292. Each request was sent once, repeated once on the plain route, and sent once through the permute route. `report.json` holds the per-kind counts.

Each format was evaluated on 30 incorrect findings (6 for each of 5 kinds) and 15 correct controls, 45 cases per format. No evidence failures; no judge errors.

| Format | Correct controls kept (of 15) | Incorrect findings rejected (of 30) | Unstable | Order-sensitive | Errors | Evaluated |
|---|---|---|---|---|---|---|
| current | 14 | 28 | 0 | 0 | 0 | 45 |
| short_claim | 12 | 27 | 0 | 0 | 0 | 45 |
| code_first | 12 | 27 | 0 | 2 | 0 | 45 |
| code_only | 12 | 21 | 0 | 3 | 0 | 45 |
