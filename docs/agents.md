# Agents, registry entries and tools

Every piece of text the agents send to a model, and the finding explanations they report, is read from `src/lgtm/agents/prompts.toml` through `lgtm.agents.registry`. Entries are cited as `<table>.<key>`. The tables are `shared`, `tools`, `retriever`, `sast_triage`, `authz_reviewer`, `plain_reviewer` and `investigator`. Placeholders, conditional fragments and truncation limits stay in code.

`tests/test_agents_doc.py` compares this page with the tools the code registers for each agent and fails when they differ. Output rendered by `lgtm.graph` (graph tool results, file and search envelopes) is not part of the registry.

## Tool offering conditions

Every tool-using agent is offered `read_file`, `grep_repo` and `search_policy`.

The graph tools `investigate_base_code` and `investigate_pr_code` are offered only when all four hold: the agent requests graph tools, snapshot SHAs are present, a graph session exists, and the graph was not missing at startup. Otherwise only the three tools above are offered.

The agent code requests graph tools as follows: `authz_reviewer` and `investigator` request them, `sast_triage` does not, and `plain_reviewer` is given no tools.

## sast_triage

Triages one Semgrep finding. It requests no graph tools.

Tools, always offered:

- `read_file(path, start_line, end_line, snapshot)`
- `grep_repo(pattern, file_glob, snapshot)`
- `search_policy(query)`

Registry entries received:

- Prompts and fragments: `sast_triage.system_prompt`, `sast_triage.user_prompt`, `sast_triage.diff_unavailable`, `sast_triage.static_facts`, `sast_triage.policy_query`, `sast_triage.policy_excerpts`, `sast_triage.failed_explanation`
- Tool section: `shared.tool_section_intro`, `shared.snapshot_argument`, `shared.snapshot_argument_base_only`, `shared.tool_output_notice`, `tools.guidance.read_file`, `tools.guidance.grep_repo`, `tools.guidance.search_policy`
- Tool descriptions: `tools.description.read_file`, `tools.description.grep_repo`, `tools.description.search_policy`
- Tool loop messages: `shared.verify_with_tools`, `shared.text_call_result`, `shared.invalid_tool_input`, `shared.unknown_tool`, `shared.no_tools_available`, `shared.arguments_not_object`, `shared.arguments_location`, `shared.tool_failed`, `shared.reask`, `shared.forced_final`, `shared.unparsable_explanation`, `shared.tool_output_prefixes`, `shared.tool_output_markers`
- Tool results: `tools.budget_exhausted`, `tools.path_escape`, `tools.unknown_snapshot`, `tools.unknown_snapshot_base_only`, `tools.pr_unavailable`, `tools.file_not_present`, `tools.cannot_read_snapshot`, `tools.regex_rejected`, `tools.regex_multiline`, `tools.regex_error`, `tools.start_line_beyond_end`, `tools.grep_truncated`, `tools.grep_no_matches`, `tools.policy_index_unavailable`, `tools.policy_error`
- Retriever framing: `retriever.no_results`, `retriever.chunk_header`, `retriever.chunk_separator`, `retriever.index_missing`

## authz_reviewer

Reviews one PR section against the security policy. It requests graph tools.

Tools, always offered:

- `read_file(path, start_line, end_line, snapshot)`
- `grep_repo(pattern, file_glob, snapshot)`
- `search_policy(query)`

Tools, conditional: `investigate_base_code(query)` and `investigate_pr_code(query)` are offered only when the graph conditions in the section above hold (graph tools requested, snapshot SHAs present, graph session present, graph not missing at startup).

Registry entries received:

- Prompts and fragments: `authz_reviewer.system_prompt`, `authz_reviewer.user_prompt`, `authz_reviewer.section_body`, `authz_reviewer.untrusted_label`, `authz_reviewer.role_guidance`, `authz_reviewer.related_sast`, `authz_reviewer.sibling_notice`, `authz_reviewer.context_block`, `authz_reviewer.context_line`, `authz_reviewer.policy_query`, `authz_reviewer.policy_unavailable`, `authz_reviewer.location`, `authz_reviewer.unparsable_explanation`, `authz_reviewer.failed_explanation`
- Tool section: `shared.tool_section_intro`, `shared.snapshot_argument`, `shared.snapshot_argument_base_only`, `shared.tool_output_notice`, `shared.graph_guidance`, `tools.guidance.read_file`, `tools.guidance.grep_repo`, `tools.guidance.search_policy`, `tools.guidance.investigate_base_code`, `tools.guidance.investigate_pr_code`
- Tool descriptions: `tools.description.read_file`, `tools.description.grep_repo`, `tools.description.search_policy`, `tools.description.investigate_base_code`, `tools.description.investigate_pr_code`
- Tool loop messages: `shared.verify_with_tools`, `shared.text_call_result`, `shared.invalid_tool_input`, `shared.unknown_tool`, `shared.no_tools_available`, `shared.arguments_not_object`, `shared.arguments_location`, `shared.tool_failed`, `shared.reask`, `shared.forced_final`, `shared.unparsable_explanation`, `shared.tool_output_prefixes`, `shared.tool_output_markers`
- Tool results: `tools.budget_exhausted`, `tools.path_escape`, `tools.unknown_snapshot`, `tools.unknown_snapshot_base_only`, `tools.pr_unavailable`, `tools.file_not_present`, `tools.cannot_read_snapshot`, `tools.regex_rejected`, `tools.regex_multiline`, `tools.regex_error`, `tools.empty_query`, `tools.start_line_beyond_end`, `tools.grep_truncated`, `tools.grep_no_matches`, `tools.policy_index_unavailable`, `tools.policy_error`
- Retriever framing: `retriever.no_results`, `retriever.chunk_header`, `retriever.chunk_separator`, `retriever.index_missing`

## plain_reviewer

Reviews the whole PR diff in one call. It is given no tools, no retrieval and no static-analysis output.

Registry entries received:

- Prompts and fragments: `plain_reviewer.system_prompt`, `plain_reviewer.user_prompt`, `plain_reviewer.diff_entry`, `plain_reviewer.unparsable_explanation`, `plain_reviewer.failed_explanation`
- Re-ask message: `shared.reask`
- Evidence filtering: `shared.tool_output_prefixes`, `shared.tool_output_markers`

## investigator

Proposes review sections from the unfiltered PR diff. It requests graph tools.

Tools, always offered:

- `read_file(path, start_line, end_line, snapshot)`
- `grep_repo(pattern, file_glob, snapshot)`
- `search_policy(query)`

Tools, conditional: `investigate_base_code(query)` and `investigate_pr_code(query)` are offered only when the graph conditions in the section above hold (graph tools requested, snapshot SHAs present, graph session present, graph not missing at startup).

Registry entries received:

- Prompts and fragments: `investigator.system_prompt`, `investigator.user_prompt`, `investigator.diff_section`, `investigator.excerpt_label`, `investigator.manifest_file`, `investigator.manifest_hunk`
- Tool section: `shared.tool_section_intro`, `shared.snapshot_argument`, `shared.snapshot_argument_base_only`, `shared.tool_output_notice`, `shared.graph_guidance`, `tools.guidance.read_file`, `tools.guidance.grep_repo`, `tools.guidance.search_policy`, `tools.guidance.investigate_base_code`, `tools.guidance.investigate_pr_code`
- Tool descriptions: `tools.description.read_file`, `tools.description.grep_repo`, `tools.description.search_policy`, `tools.description.investigate_base_code`, `tools.description.investigate_pr_code`
- Tool loop messages: `shared.verify_with_tools`, `shared.text_call_result`, `shared.invalid_tool_input`, `shared.unknown_tool`, `shared.no_tools_available`, `shared.arguments_not_object`, `shared.arguments_location`, `shared.tool_failed`, `shared.reask`, `shared.forced_final`
- Tool results: `tools.budget_exhausted`, `tools.path_escape`, `tools.unknown_snapshot`, `tools.unknown_snapshot_base_only`, `tools.pr_unavailable`, `tools.file_not_present`, `tools.cannot_read_snapshot`, `tools.regex_rejected`, `tools.regex_multiline`, `tools.regex_error`, `tools.empty_query`, `tools.start_line_beyond_end`, `tools.grep_truncated`, `tools.grep_no_matches`, `tools.policy_index_unavailable`, `tools.policy_error`
- Retriever framing: `retriever.no_results`, `retriever.chunk_header`, `retriever.chunk_separator`, `retriever.index_missing`
