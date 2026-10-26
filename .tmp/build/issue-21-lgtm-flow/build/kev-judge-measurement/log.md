# Log

## Removed tests
- New file paths | docs/kev-labeling-criteria.md, benchmark/kev_model_labels.json | build decision inside Scope (test-developer)
- Agent verdict source for agreement | recorded finding["verdict"] (vulnerable=real, safe=not_real, empty excluded); Kev accepted = supported True | build decision (tests-unit.md)
- Four existing Kev-independence tests updated to the supported-but-not_real rule | AC-S5-3, AC-S5-4 | tests-unit.md Round 2
- quote_absence for authz_10_vulnerable/authz_12_vulnerable is empty on run6-final (cases absent from that run) | recorded | edit.md
Scope addition: in-place edits to README.md exit-code rule and benchmark/README.md gating sentence | APPROVED by orchestrator; limited to those lines | orchestrator decision
Labels for judge-eval | relabeled blind by claude-opus-5-5 (DEC-8) from claim, quote, and enclosing function, without case id or status; 24 real, 42 not_real, 8 undetermined | final/repair-1.md
Undetermined units (quote absent from reviewed code) | excluded from all Kev accuracy and agreement measures; listed in report["undetermined"] | final/repair-2.md, docs/kev-labeling-criteria.md
Manager-gated authz listing/bulk claims labeled not_real | labeler judgment, no manager-visibility policy text available | final/repair-1.md
