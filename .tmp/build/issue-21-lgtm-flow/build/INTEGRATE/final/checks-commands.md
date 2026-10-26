# CON-3 Existing commands still run

Revision 84bece67c8708217d1f8f6b0293178fd43ee1466, worktree INTEGRATE, tree clean before and after (`git status --porcelain` empty). No model server reachable (connection refused on localhost:11434). All outputs went to build/INTEGRATE/tmp/cmds/ (fixture repo with a one-line os.system PR, a local Semgrep rule).

| Command | Exit | Class | Key output |
|---|---|---|---|
| `lgtm index --repo <fixture>` | 0 | Passed | "Indexed 0 documentation chunks" |
| `lgtm review --base main --pr feat` (lgtm, no model) | 2 | Passed, needs live model | ConnectError WinError 10061 retried 4x, "Authz section review failed", reports written, "0 findings"; exit 2 matches documented "agent errored", no traceback |
| `lgtm review --mode sast-only --semgrep-config rule.yml` | 1 | Passed | 1 finding, supported 1; exit 1 matches documented baseline-vulnerable code |
| `evaluate.py --mode sast-only --cases sqli_01_vulnerable` | 0 | Passed | scored 1, errors 0, case_labels detected_vulnerability 1 |
| `evaluate.py --mode llm-only --cases sqli_01_vulnerable` | 0 | Needs live model | error "infra failure: plain:sqli, plain:authz", label scan_failure, summary written |
| `evaluate.py --mode lgtm-no-sast --cases sqli_01_vulnerable` | 0 | Needs live model | error "SAST triage failed for 1 hit(s)", scan_failure |
| `evaluate.py --mode lgtm --cases sqli_01_vulnerable` | 0 | Needs live model | error "SAST triage failed for 2 hit(s)", scan_failure |
| `run_injection_bench.py --mode sast-only --cases inj_01_sqli_comment` | 0 | Passed | flagged=True, ASR 0.0%, summary.json written |
| `run_injection_bench.py --mode lgtm --cases inj_01_sqli_comment` | 0 | Needs live model | Connect errors, "Judge failed", "Excluded: candidates not judged", ASR 0/0; no traceback |
| `generate_cases.py` | 0 | Passed | "Generated 24 sqli + 28 authz cases; labels.json updated"; writes tracked files, output identical (status empty), nothing to restore |

No command failed with a traceback from merged code. Nothing is broken.

Notes:
- evaluate.py exits 0 when every case errors (scan_failure); errors show only in the summary. Not compared against main.
- generate_cases.py --help was run once by mistake (ignores arguments, regenerates); tree stayed clean. A stray interactive python was started by a mistaken command; a taskkill was denied, so a leftover python.exe may exist.
- Not covered: llm/lgtm paths with a working model, other splits, README exit-code documentation review (separate check).
- run_injection_bench creates temp repos under the user Temp dir (lgtm-inj-*); not removed by me.
- Cleanup: removal of build/INTEGRATE/tmp/cmds/ contents was denied by the safety check; contents (logs, fixture repo, outputs) remain for the caller to delete.
