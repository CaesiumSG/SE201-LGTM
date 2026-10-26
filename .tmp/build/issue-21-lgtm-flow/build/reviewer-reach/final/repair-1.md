# Repair 1

Findings: common-sense M1 (final/review-common-sense.md), structure-02 (final/review-structure.md), behavior Low steps_exhausted stale.

src/lgtm/agents/tools.py: AgentToolbox.__init__ sets steps_exhausted = False; reset_budget clears it.
src/lgtm/agents/base.py: fill_record reads toolbox.steps_exhausted directly.

Note: the first application was discarded by a concurrent reviewer's worktree reset and re-applied.
