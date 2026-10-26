# Common-sense review (integration changes)
CLEAN. High 0, Medium 0, Low 3.
- common-sense-01 (Low) benchmark/evaluate.py:380-397, 685-696; benchmark/README.md:330-343, 374-380: outcome_for_label, PREDICTED_BY_LABEL, the EXCLUDED filter and excluded_on_safe are dead (already dead at bad831d); README still lists EXCLUDED/UNCREDITED rows and excluded_on_safe.
- common-sense-02 (Low) src/lgtm/agents/base.py, tools.py: budget_spent undeclared toolbox attribute read via getattr. Repaired in repair-5.
- common-sense-03 (Low) src/lgtm/agents/base.py:603-609: budget_spent defaulted in two places. Repaired in repair-5.
