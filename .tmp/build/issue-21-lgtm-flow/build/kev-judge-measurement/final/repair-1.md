# Repair 1: blind relabel of Kev candidates (B-1, B-2)

Model ID: `claude-opus-5-5` (Claude Opus 5.5, as DEC-8 requires). This resolves B-2 for these labels.

Output: `build/kev-judge-measurement/tmp/blind/labels.json`. Each unit has `supported`, `verdict`, `severity` and `rationale`.

## Method
- The only input read was `tmp/blind/candidates.json` (74 units). I did not read `kev_model_labels.json`, `benchmark/runs/`, fixtures, patches, `tmp/blind-map/` or test expectations.
- Each unit was judged only on its own claim and quoted code, following `docs/kev-labeling-criteria.md`. The agent's stated conclusions in the claim text were ignored. Other units were not used as context, even when they quote the same endpoint.
- `supported`:
  - `yes` when the quote shows the mechanism the claim's conclusion rests on. Wrong secondary details are noted in the rationale (U013, U016, U056).
  - `no` when the quote omits that mechanism, contradicts it, or lacks code the claim names (for example, `:idN` placeholders not visible in U035, U048 and U065).
- `verdict`:
  - `not_real` when the unit is unsupported, or when it is supported but the code is guarded or the behavior is not a vulnerability.
  - `real` only when the quote itself shows a reachable source and no guard.
  - `undetermined` when the unit is supported but exploitability depends on code outside the quote: the input's source or validation, a decorator omitted because the quote starts at `def`, an omitted function body, or a policy question about what a role may see. The criteria have no rule for this case, so the task's fallback applies.
- An injection visible in a quote that comes with an authz claim was not counted toward that claim (U008, U040, U058, U066, U074).
- `severity` is set only on `real` units.
- `kind` and `origin` are case metadata, not something a blind reader can derive. They are left for the orchestrator to join from the blind map.

## Counts
- supported: yes 58, no 16
- verdict: real 6, not_real 34, undetermined 34
- severity (real only): high 6
- Real units: U012, U018, U023, U043, U044, U047.

## Undetermined units (34)
- Injection sink shown, but the source or validation is outside the quote: U004, U009, U011, U017, U019, U025, U031, U032, U033, U041, U057, U059, U060, U062, U070, U073.
- Authz claim where the role gate, decorator or body is not quoted: U001, U006, U034, U037, U039, U040, U053, U054, U055, U056, U061, U063, U064, U066, U067, U071.
- Policy-dependent exposure of other users' id and username: U008, U021.

## Criteria gap (not edited)
`kev-labeling-criteria.md` judges a verdict "in the reviewed change", but a unit gives the labeler only a quote. The criteria do not say what to do when the quote shows a sink or a missing check but not the input's source, the decorators or the rest of the function. This produced the 34 undetermined units. Labeling was not blocked, because the task's fallback applied, so I made no edit.

Decision for the orchestrator: either add a rule that judges the verdict from the quote alone (for example, "unsupported or not shown → not_real"), or give labelers the enclosing function. Note that a quote-only rule would turn most of the 34 into `not_real`, so Kev verdict accuracy would then measure quote-reading, not vulnerability detection.

## Observations
- U014's quote contains literal `\"` escapes (`f\"id{i}\"`). The agent's quote may not match the source byte for byte, which is relevant to the exact-substring check in B-3.
- Several authz claims cite a policy rule unrelated to the code (U036 cites the role-change rule for an audit-log delete; U040 and U061 cite the order-viewing rule for order creation).

Nothing was run or verified. Skipped: no comparison against existing labels or case status (by design); `kind` and `origin` not filled.

## Round 2
Input: `tmp/blind/context.json`, which gives the enclosing function and its decorators for the 34 units left undetermined. Context was present for 26 of them; 8 had context null ("quote not found"). The other 40 labels are unchanged.

- Each unit was re-decided from its claim, quote and context.
- Severity for injections:
  - `high` when any authenticated user can reach the endpoint (`@require_auth`, or a cookie the client sets).
  - `medium` when it is gated by `@require_role("manager")`.
  - `low` when it is gated by `@require_role("admin")`.
- An authz claim about listing or bulk operations behind `@require_role("manager")` is `not_real`: it is guarded and no ordinary user reaches it. The full policy text was not available to say whether managers may see all orders and users, so this is a judgment. The orchestrator should confirm it.
- Changes:
  - U039 is now `supported: no`. Its context shows `@require_role("manager")`, which contradicts the claim that the endpoint has no role check.
  - U008 and U021 are now `not_real`. Without the injection, the endpoint is a username directory that returns only id and username.
- The 8 units without context keep `undetermined` with the reason "cited quote not present in reviewed code": U006, U034, U040, U053, U055, U064, U066, U067. Their quotes alone omit the decorators, so they cannot decide the verdict.

Round 2 results for the 34 units: real 18, not_real 8, undetermined 8.
- Real: U004, U009, U011, U017, U019, U025, U031, U032, U033, U037 (critical, self-promotion to admin), U041, U057, U059 (low), U060, U062, U070, U071 (high, any user deletes accounts), U073.
- Not real: U001, U008, U021, U039, U054, U056, U061, U063.

Totals over the 74 units:
- supported: yes 57, no 17
- verdict: real 24, not_real 42, undetermined 8
- severity (real only): critical 1, high 9, medium 13, low 1

Criteria change: `docs/kev-labeling-criteria.md` now states that labelers get the claim, the quote and the enclosing function, and that a unit whose quote is not present in the reviewed code is `undetermined` and excluded from accuracy.

Consistency note: the round 1 `real` labels U018 and U043 (high) were set without context and are unchanged, as instructed. If those endpoints are manager-only, the round 2 severity convention would make them `medium`.
