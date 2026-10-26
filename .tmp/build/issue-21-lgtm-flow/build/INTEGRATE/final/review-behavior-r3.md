# Behavior review r3: 6d00729 "Keep tool-loop requests within the model context window"
Method: static inspection of diff acfb780..6d00729, base.py run_tool_loop/_close_run/fill_record/build_llm, callers (authz_reviewer, investigator, sast_triage, plain_reviewer, pipeline), config.py, docs/gpu-model-eval.md, and the round checks. No commands run; tmp/behavior not created.

Verdict: the change meets its goal for the normal case. No High findings. Four Medium/Low items, two of them open decisions.

## Confirmed good
- Guard runs after every tool round, so the forced-final request (history + forced_final prompt) is kept under (ctx - output) * 3 chars for rounds of similar size. Findings are preserved: the history is not trimmed, the loop stops early and asks for the verdict.
- Forced-final path reused unchanged (unbound llm, request_valid_answer). Short conversations are untouched (unit test, 3 requests).
- Budget/invalid-cap breaks precede the guard, so their semantics are unchanged. budget_spent flag unchanged.
- Callers: signatures of build_llm and run_tool_loop unchanged; the new config field has a default, so config files and other constructors are unaffected. Non-Ollama: the only LLM is ChatOllama; GPU path (apply_gpu_model) does not touch num_ctx and its served context is already 32768 (docs/gpu-model-eval.md), so GPU behavior matches.

## Findings
1. Medium (inspected, open decision). context_full yields steps_exhausted=False, so fill_record sets record.limit_hit = None (or "tool_calls" if over budget). A run cut short by context is reported as a clean finish: coverage cannot show that the investigation was truncated. Before the change the same situation either overflowed silently (Ollama truncation) or hit iteration cap ("steps"). Journey 1 r2 hit this warning once with no trace in report.json. Decision needed: new limit_hit value (e.g. "context") or treat as "steps". Smallest fix: pass a distinct signal through _close_run and set limit_hit in fill_record.
2. Medium/Low (inspected). num_ctx=32768 is now forced for every build_llm user, including the default local (non-GPU) Ollama model, which previously ran at the server default (docs record 4096 as the prior default). That raises KV-cache memory and latency on small local hardware, and a server with OLLAMA_CONTEXT_LENGTH above 32768 is now lowered to it. Expected behavior in the story is unconfirmed. Smallest fix: keep the default but document it, or leave num_ctx unset when the field is None.
3. Low (inspected). Guard measures only message content chars. It omits AIMessage tool_call args (content may be empty), bind_tools schemas, and the reasoning output. Also the "next round as big as the last" estimate can under-predict (several calls, 8000-char results, MAX_OUTPUT_CHARS). Reserve of 2048 tokens plus 3 chars/token conservatism covers most of it; overflow possible only within a few thousand chars of the limit.
4. Low (inspected). Unguarded paths: (a) the first request when system+user prompts alone exceed the window; (b) request_valid_answer re-asks (up to 3) append another answer plus prompt after the forced-final, but only one output reserve is held back, so a re-ask can exceed the window when history sits at the limit. Ollama then truncates silently. Journey 1 r2 shows two re-asks in a run that also hit the guard, so (b) is reachable, though no failure was observed.

## Coverage
Flows inspected: loop exit ordering, forced-final, _close_run/fill_record, all five build_llm/run_tool_loop callers, config default. Evidence reused: tests-unit.md (6 pass), checks-pytest-r3 (2947 pass), journey-1 r2 (no 500s, completed). Not verified: tokenizer ratio for qwen3.8 on real code; behavior with a non-32768 server. Cleanup: nothing created.
