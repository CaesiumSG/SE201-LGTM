Source: LGT-166 https://linear.app/se201-lgtm/issue/LGT-166/reviewer-reach-deletion-only-changes-are-reviewed-and-the-reviewer
Retrieved: 2026-10-26 (time of day not captured)

# reviewer-reach: Deletion-only changes are reviewed and the reviewer reaches affected code

Outcome: The reviewer reports bugs introduced by deleted code, starts each section with the enclosing definition of every changed hunk (removed-only hunks included), works within raised budgets recorded in the config, and the pipeline result exposes per-section tool calls, raw answers, and limit hits.
Prerequisites: none
Criteria: AC-S1-4, AC-S2-1, AC-S2-2, AC-S2-5   Constraints: CON-1, CON-2, CON-3   Decisions: DEC-3, DEC-6, DEC-9, DEC-10   External: none

## Scope

| Field | Entries |
| -- | -- |
| Owns | Deletion-only and deletion-dominated review in every lgtm mode; enclosing-definition context in the initial input of a section; investigator tool-call and step budgets and the read_file line cap; detection and recording of limit hits |
| Modifies | src/lgtm/review/sections.py, src/lgtm/review/coverage.py, src/lgtm/agents/authz_reviewer.py, src/lgtm/agents/investigator.py, src/lgtm/agents/tools.py, src/lgtm/agents/base.py, src/lgtm/agents/prompt_parts.py, src/lgtm/agents/prompts.toml, src/lgtm/config.py, src/lgtm/review/provenance.py, src/lgtm/diff/git_diff.py, src/lgtm/pipeline.py; tests/test_sections.py, tests/test_coverage.py, tests/test_agents.py, tests/test_investigator.py, tests/test_graph_tools.py, tests/test_graph_prompts.py, tests/test_graph_pipeline.py, tests/test_diff.py |
| Regenerated | tests/model_input_lock/expected.json |
| Consumes | EvidenceItem and AgentFinding in src/lgtm/agents/base.py; Hunk and FileDiff in src/lgtm/diff/git_diff.py; the Shoply dev cases under benchmark/cases/ |
| Resources | Live-model and real-world runs are INTEGRATE only (defer), per DEC-9; tests use fake models |
| Out of scope | Per-case result persistence and AC-S2-3 (benchmark-scope-trace); PR-scope finding rule and grounding of removed-line evidence in src/lgtm/validation/evidence.py (pr-scoped-review); the deletion-only, aegra, and held-out real-world criteria (INTEGRATE) |

## Provides

### CT-reviewer-reach-1 Section run record

Consumers: benchmark-scope-trace
The ReviewResult returned by ReviewPipeline in src/lgtm/pipeline.py carries, for each section review and for the investigator run, a record with section (section identifier; investigator for the investigator run), tool_calls (list of objects with tool and args), raw_answer (final model answer text), and limit_hit (null, "tool_calls", or "steps"; null also when the loop ended at the invalid-tool-input cap). A caller reads the records without re-running the review.

## Packages

| Package | Criteria (tier) | Production files | Test files |
| -- | -- | -- | -- |
| reach | AC-S1-4 (Unit), AC-S2-1 (Unit), AC-S2-2 (Unit), AC-S2-5 (Unit) | src/lgtm/review/sections.py, src/lgtm/review/coverage.py, src/lgtm/agents/authz_reviewer.py, src/lgtm/agents/investigator.py, src/lgtm/agents/tools.py, src/lgtm/agents/base.py, src/lgtm/agents/prompt_parts.py, src/lgtm/agents/prompts.toml, src/lgtm/config.py, src/lgtm/review/provenance.py, src/lgtm/diff/git_diff.py, src/lgtm/pipeline.py | tests/test_sections.py, tests/test_coverage.py, tests/test_agents.py, tests/test_investigator.py, tests/test_graph_tools.py, tests/test_graph_prompts.py, tests/test_graph_pipeline.py, tests/test_diff.py, tests/model_input_lock/expected.json |

AC-S1-1, AC-S1-2, and AC-S2-4 run on real-world cases and belong to INTEGRATE (DEC-9); they are in no package.

## Checks

* `pytest`: unit and fake-model suites for sections, coverage, agents, tools, pipeline, diff, and the model-input lock.
