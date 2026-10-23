# Claude Prompt: Build LGTM — Context-Aware PR Security Agent

> [!IMPORTANT]
> This is a prompt to pass to Claude (or another LLM coding assistant) to build the full LGTM project end-to-end.

---

## The Prompt

You are building **LGTM**, a Context-Aware PR Security Agent that combines deterministic SAST (Semgrep) with LLM-based agents grounded in repository context to review pull requests for security vulnerabilities. The project is a Python CLI tool.

### High-Level Architecture

The pipeline works as follows:

1. **Context Building**: Read the PR diff (via Git CLI), run Semgrep on the changed files, and retrieve relevant security policy chunks from project documentation using RAG.
2. **SAST Triage Agent**: Examines Semgrep findings (focused on SQL injection / CWE-89) to determine if they are genuine vulnerabilities or false positives (e.g., guarded by parameterized queries). Uses read-only tools to trace data flow and fetch additional context.
3. **Authorization Agent**: Examines changed endpoints against the repository's security policy and project documents (specs, API docs, README) to detect authorization flaws (CWE-639, CWE-862, CWE-863). Uses RAG to retrieve relevant access control rules and permission structures.
4. **Evidence Validator**: Validates every finding — verifies that cited files, line numbers, and policy references actually exist in the repository.
5. **Report Builder**: Produces a structured Markdown and JSON report with CWE IDs, evidence, explanations, and suggested fixes.

### Tech Stack

- **Language**: Python 3.13+
- **LLM**: Qwen (via Ollama) — use `langchain-ollama` for integration. Default model: `qwen2.5:7b` (configurable).
- **Agent Framework**: LangChain for agent orchestration and tool calling.
- **SAST**: Semgrep CE (Community Edition), invoked via CLI subprocess.
- **RAG / Vector Store**: ChromaDB with a local embedding model (e.g., `sentence-transformers/all-MiniLM-L6-v2` via `langchain-huggingface` or `chromadb`'s default embedding function).
- **Git**: Git CLI via subprocess for diff extraction.
- **Output**: JSON findings + Markdown report.

### Project Structure

Build the project with this structure:

```
SE201-LGTM/
├── README.md                    # Setup instructions, usage, architecture overview
├── pyproject.toml               # Project metadata and dependencies (use poetry or pip)
├── requirements.txt             # Pinned dependencies
├── .gitignore
├── docs/
│   └── project-proposal.md      # (already exists)
├── src/
│   └── lgtm/
│       ├── __init__.py
│       ├── cli.py               # CLI entry point (argparse or click)
│       ├── config.py            # Configuration (model name, Semgrep rules, paths, tool call limits)
│       ├── pipeline.py          # Main orchestrator — runs the full review pipeline
│       ├── diff/
│       │   ├── __init__.py
│       │   └── git_diff.py      # Git diff extraction (parse PR branch vs base branch)
│       ├── sast/
│       │   ├── __init__.py
│       │   ├── semgrep_runner.py # Run Semgrep CE on changed files, parse JSON output
│       │   └── rules/           # Custom Semgrep rules (YAML) if needed
│       ├── rag/
│       │   ├── __init__.py
│       │   ├── indexer.py       # Index project docs (security policy, specs, README) into ChromaDB
│       │   └── retriever.py     # Retrieve relevant policy chunks given a query
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── tools.py         # Read-only agent tools: read_file, grep_repo, search_policy
│       │   ├── sast_triage.py   # SAST Triage Agent (SQL injection focus)
│       │   └── authz_reviewer.py # Authorization Reviewer Agent
│       ├── validation/
│       │   ├── __init__.py
│       │   └── evidence.py      # Evidence validator (check file/line/policy references exist)
│       └── reporting/
│           ├── __init__.py
│           └── report_builder.py # Generate JSON findings + Markdown report
├── tests/
│   ├── __init__.py
│   ├── test_diff.py
│   ├── test_semgrep.py
│   ├── test_rag.py
│   ├── test_agents.py
│   ├── test_validation.py
│   └── test_report.py
└── benchmark/                   # Benchmark repository for evaluation
    ├── README.md                # Benchmark setup instructions
    ├── security-policy.md       # Repository security policy document (for RAG)
    ├── api-spec.md              # API specification with roles/permissions
    ├── app/                     # Flask/FastAPI benchmark app
    │   ├── __init__.py
    │   ├── main.py
    │   ├── models.py
    │   ├── auth.py
    │   └── routes/
    │       ├── __init__.py
    │       ├── users.py
    │       ├── orders.py
    │       └── admin.py
    ├── cases/                   # 12 matched PR pairs (24 total cases)
    │   ├── sqli/                # 6 SQL injection pairs
    │   │   ├── case_01_vulnerable.patch   # Raw SQL with string formatting
    │   │   ├── case_01_safe.patch         # Same but parameterized
    │   │   ├── case_02_vulnerable.patch   # ORM raw query injection
    │   │   ├── case_02_safe.patch         # ORM with proper escaping
    │   │   ├── case_03_vulnerable.patch   # Dynamic table/column name
    │   │   ├── case_03_safe.patch         # Whitelist validation
    │   │   ├── case_04_vulnerable.patch   # Stored procedure injection
    │   │   ├── case_04_safe.patch         # Parameterized stored proc
    │   │   ├── case_05_vulnerable.patch   # Search endpoint injection
    │   │   ├── case_05_safe.patch         # Search with proper binding
    │   │   ├── case_06_vulnerable.patch   # Bulk insert injection
    │   │   └── case_06_safe.patch         # Bulk insert parameterized
    │   └── authz/               # 6 authorization pairs
    │       ├── case_01_vulnerable.patch   # Missing ownership check (IDOR)
    │       ├── case_01_safe.patch         # Proper ownership validation
    │       ├── case_02_vulnerable.patch   # Missing role check
    │       ├── case_02_safe.patch         # Proper role-based access
    │       ├── case_03_vulnerable.patch   # Privilege escalation
    │       ├── case_03_safe.patch         # Proper privilege check
    │       ├── case_04_vulnerable.patch   # Horizontal access violation
    │       ├── case_04_safe.patch         # Scoped to user's data
    │       ├── case_05_vulnerable.patch   # Admin bypass
    │       ├── case_05_safe.patch         # Enforced admin check
    │       ├── case_06_vulnerable.patch   # API key scope violation
    │       └── case_06_safe.patch         # Proper API key scoping
    ├── labels.json              # Ground truth labels for all 24 cases
    └── evaluate.py              # Evaluation script: precision, recall, F1, per-task metrics
```

### Detailed Component Specifications

#### 1. CLI (`src/lgtm/cli.py`)

```
Usage: lgtm review --repo <path> --base <branch> --pr <branch> [--model <ollama_model>] [--output <dir>]
       lgtm index --repo <path>    # Index project docs for RAG
```

- `review`: Run the full pipeline on a PR (diff between `--base` and `--pr` branches).
- `index`: Pre-index project documentation into ChromaDB for policy retrieval.
- Output a JSON findings file and a Markdown report to the specified output directory.

#### 2. Git Diff Reader (`src/lgtm/diff/git_diff.py`)

- Run `git diff <base>..<pr>` and parse the output.
- Extract: changed files, added/modified/deleted lines with line numbers, hunks.
- Return structured data: list of `FileDiff` objects with `path`, `hunks` (each hunk has `old_start`, `old_count`, `new_start`, `new_count`, `changes`).

#### 3. Semgrep Runner (`src/lgtm/sast/semgrep_runner.py`)

- Run `semgrep --config auto --json --quiet <changed_files>` via subprocess.
- Parse the JSON output into structured `SemgrepFinding` objects with: `rule_id`, `path`, `start_line`, `end_line`, `message`, `severity`, `cwe` (if available), `matched_code`.
- Filter to only findings in changed files/lines.

#### 4. RAG System (`src/lgtm/rag/`)

- **Indexer**: Recursively find `.md`, `.txt`, `.rst` files in the repo (especially `security-policy.md`, `api-spec.md`, `README.md`). Split into chunks (500-1000 tokens). Embed and store in ChromaDB (persistent, stored in `.lgtm/` within the repo).
- **Retriever**: Given a query (e.g., "access control for orders endpoint"), retrieve top-k relevant chunks with metadata (source file, line range).

#### 5. Agent Tools (`src/lgtm/agents/tools.py`)

Define these read-only LangChain tools for the agents:

- `read_file(path: str, start_line: int = None, end_line: int = None) -> str`: Read a file (or range of lines) from the **base branch** of the repo. Validate path is within repo.
- `grep_repo(pattern: str, file_glob: str = None) -> str`: Search the **base branch** for a regex pattern. Return matching file:line:content. Limit results.
- `search_policy(query: str) -> str`: RAG query against indexed project documentation. Return top-k relevant chunks with source attribution.

All tools operate on the **base branch** only (PR changes are untrusted). Enforce a maximum of **5 tool calls per agent invocation**.

#### 6. SAST Triage Agent (`src/lgtm/agents/sast_triage.py`)

- Input: A single Semgrep finding + relevant diff context.
- Task: Determine if the finding is a **true positive** or **false positive**.
- The agent should use tools to:
  - Read the full function/method containing the finding.
  - Check if user input reaches the vulnerable sink.
  - Check for existing sanitization or parameterization.
- Output (structured JSON):
  ```json
  {
    "finding_id": "...",
    "verdict": "vulnerable | safe | possible | insufficient_evidence",
    "confidence": 0.0-1.0,
    "cwe_id": "CWE-89",
    "explanation": "...",
    "evidence": [
      {"type": "code", "file": "...", "lines": [10, 15], "content": "..."},
      {"type": "policy", "source": "...", "content": "..."}
    ],
    "suggested_fix": "..."
  }
  ```

#### 7. Authorization Reviewer Agent (`src/lgtm/agents/authz_reviewer.py`)

- Input: A changed endpoint/route + diff context + any relevant Semgrep findings.
- Task: Check if the change violates the documented security policy or introduces authorization flaws.
- The agent should use tools to:
  - Retrieve the security policy sections relevant to this endpoint.
  - Read the existing authorization middleware/decorators.
  - Check if role/ownership checks are present and correct.
- Output: Same structured JSON format as the SAST triage agent, but with CWE-639/CWE-862/CWE-863.

#### 8. Evidence Validator (`src/lgtm/validation/evidence.py`)

- For each finding, verify:
  - Cited file paths exist in the repository.
  - Cited line numbers are within the file's range.
  - Cited code snippets match the actual file content (fuzzy match OK).
  - Cited policy references exist in the indexed documents.
- Mark findings with `supported: true/false` and `provenance_confidence`.

#### 9. Report Builder (`src/lgtm/reporting/report_builder.py`)

- Generate two outputs:
  1. **JSON**: Array of validated findings with all metadata.
  2. **Markdown**: Human-readable report with:
     - Summary (total findings, by severity, by CWE).
     - Per-finding sections with: verdict, confidence, explanation, evidence (with file links and code snippets), suggested fix.
     - Evidence grounding statistics.

#### 10. Benchmark (`benchmark/`)

Build a realistic Flask or FastAPI application with:

- User authentication (JWT or session-based).
- Role-based access control (admin, manager, user).
- Database operations using SQLAlchemy (with some raw SQL endpoints).
- Endpoints: user management, orders, admin panel.

Create **12 matched PR pairs (24 cases total)**:

- **6 SQL injection pairs** (CWE-89): Each pair has one vulnerable version (e.g., raw string formatting in SQL) and one safe control (e.g., parameterized query doing the same thing). The safe version should still trigger Semgrep (to test false positive detection).
- **6 authorization pairs** (CWE-639/862/863): Each pair has one vulnerable version (e.g., missing ownership check) and one safe control (e.g., proper ownership validation). These should NOT be detectable by Semgrep alone.

Each `.patch` file should be a valid git diff that can be applied to the benchmark app.

The `labels.json` should contain ground truth:
```json
{
  "cases": [
    {
      "id": "sqli_01_vulnerable",
      "category": "sqli",
      "expected_verdict": "vulnerable",
      "cwe": "CWE-89",
      "vulnerable_lines": [45, 46, 47],
      "patch_file": "cases/sqli/case_01_vulnerable.patch"
    },
    ...
  ]
}
```

The `evaluate.py` script should:
- Run LGTM against each case.
- Compare verdicts to ground truth.
- Calculate: precision, recall, F1 (overall and per-category), false positive rate on safe controls, evidence grounding rate, "insufficient evidence" rate, "possible" rate, median latency, median tokens per PR.
- Support running all three baselines: SAST-only, LLM-only, LGTM (SAST+LLM).

### Configuration (`src/lgtm/config.py`)

Use a dataclass or Pydantic model:

```python
@dataclass
class LGTMConfig:
    ollama_model: str = "qwen2.5:7b"
    ollama_base_url: str = "http://localhost:11434"
    semgrep_config: str = "auto"  # or path to custom rules
    max_tool_calls: int = 5
    rag_chunk_size: int = 500
    rag_top_k: int = 5
    chroma_persist_dir: str = ".lgtm/chroma"
    output_dir: str = "lgtm-output"
```

### Guardrails & Safety

- Agent tools are **read-only** — no write operations.
- All file reads are **restricted to the repository directory**.
- Tool calls are **capped** (default 5 per agent invocation).
- Documentation and code context are retrieved from the **base branch only**.
- PR edits are treated as **untrusted input** — never execute code from the PR.
- The system follows a **human-in-the-loop** approach: it identifies and reports, but doesn't auto-fix.

### Structured Output

Each agent must produce structured JSON output. Use LangChain's structured output capabilities (e.g., `with_structured_output()`) or parse JSON from the LLM response with a fallback parser.

Verdict categories:
- `vulnerable`: Confirmed vulnerability with strong evidence.
- `safe`: Confirmed safe — the suspected issue is properly mitigated (backed by explicit policy/code evidence).
- `possible`: Potential vulnerability — the rule is only implied or evidence is circumstantial.
- `insufficient_evidence`: Cannot determine — not enough context to make a judgment.

### Key Implementation Notes

1. **Error Handling**: Wrap all subprocess calls (git, semgrep) with proper error handling and timeouts.
2. **Logging**: Use Python's `logging` module throughout. The CLI should support `--verbose` for debug output.
3. **Testing**: Write unit tests with mocked LLM responses and mocked subprocess calls. Tests should be runnable without Ollama or Semgrep installed.
4. **Idempotency**: Running the same review twice should produce consistent results (within LLM variance).
5. **README**: Include clear setup instructions (install Ollama, pull Qwen model, install Semgrep, pip install, run `lgtm index`, run `lgtm review`).

### What to Build First

Build in this order:
1. Project scaffolding (pyproject.toml, directory structure, config)
2. Git diff reader
3. Semgrep runner
4. RAG indexer and retriever
5. Agent tools
6. SAST triage agent
7. Authorization reviewer agent
8. Evidence validator
9. Report builder
10. CLI orchestration (pipeline.py + cli.py)
11. Benchmark app and test cases
12. Evaluation script
13. README and documentation
14. Unit tests

Build every component fully. Write real, working code — not stubs or placeholders. Each module should be importable and functional independently.
