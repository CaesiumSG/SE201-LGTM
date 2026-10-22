"""Configuration for the LGTM pipeline."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger(__name__)

GRAPH_OUTPUT_CHARS_CEILING = 6000
GRAPH_EXPORT_FILES_CEILING = 20000
GRAPH_EXPORT_BYTES_CEILING = 200 * 1024 * 1024


@dataclass
class LGTMConfig:
    """Central configuration for all LGTM components."""

    # LLM
    ollama_model: str = "qwen3.8:27b"
    ollama_base_url: str = "http://127.0.0.1:11435"
    llm_temperature: float = 0.0
    llm_timeout: int = 180  # seconds per LLM call
    reasoning: bool | None = False  # None leaves the model's default thinking behaviour
    llm_retries: int = 3
    llm_backoff_seconds: tuple[float, ...] = (2.0, 4.0, 8.0)
    max_invalid_tool_inputs: int = 3
    max_answer_reasks: int = 3
    llm_max_output_tokens: int = 2048  # num_predict: stops runaway generations

    # SAST
    semgrep_config: str = "auto"  # "auto" or a path to custom rules
    semgrep_timeout: int = 300  # seconds for the whole semgrep run

    # Agents
    max_tool_calls: int = 5  # per agent invocation
    max_agent_iterations: int = 8  # hard stop on the reasoning loop
    # Experiments (round 4, off by default — see docs/evaluation-log.md):
    # push back once if an agent answers before using any tool
    require_tool_use: bool = False
    # give agents deterministic AST facts (query construction, decorators)
    # and give SAST triage the same policy pre-retrieval authz gets
    static_facts: bool = False
    # tell the authz agent to judge ownership checks by what the policy lets
    # the endpoint's required role access (round 5)
    authz_role_guidance: bool = False
    # Prompt injection mitigations (off by default)
    strip_comments: bool = False
    detect_prompt_injection: bool = False

    # RAG
    rag_chunk_size: int = 500  # approx tokens per chunk
    rag_chunk_overlap: int = 50
    rag_top_k: int = 5
    embedding_model: str = "all-MiniLM-L6-v2"
    chroma_persist_dir: str = ".lgtm/chroma"
    chroma_collection: str = "lgtm_docs"

    # Git
    git_timeout: int = 60

    graph_binary: str = "codegraph"
    graph_init_timeout_s: int = 120
    graph_query_timeout_s: int = 20
    graph_max_output_chars: int = GRAPH_OUTPUT_CHARS_CEILING
    graph_max_export_files: int = GRAPH_EXPORT_FILES_CEILING
    graph_max_export_bytes: int = GRAPH_EXPORT_BYTES_CEILING

    def __post_init__(self) -> None:
        positive_fields = (
            "graph_init_timeout_s",
            "graph_query_timeout_s",
            "graph_max_export_files",
            "graph_max_export_bytes",
        )
        for key in positive_fields:
            if getattr(self, key) <= 0:
                raise ValueError(f"{key} must be positive")
        if self.graph_max_output_chars < 1024:
            raise ValueError("graph_max_output_chars must be at least 1024")
        self.graph_max_output_chars = min(self.graph_max_output_chars, GRAPH_OUTPUT_CHARS_CEILING)
        self.graph_max_export_files = min(self.graph_max_export_files, GRAPH_EXPORT_FILES_CEILING)
        self.graph_max_export_bytes = min(self.graph_max_export_bytes, GRAPH_EXPORT_BYTES_CEILING)

    # Output
    output_dir: str = "lgtm-output"

    # Pipeline modes: "lgtm" (SAST + LLM), "sast-only", "llm-only", "lgtm-no-sast"
    mode: str = "lgtm"

    # Doc file extensions indexed for RAG
    doc_extensions: tuple[str, ...] = (".md", ".txt", ".rst")

    # Internal
    extra: dict = field(default_factory=dict)

    def chroma_dir_for(self, repo_path: str | Path) -> Path:
        """Resolve the Chroma persistence directory relative to a repo."""
        p = Path(self.chroma_persist_dir)
        if p.is_absolute():
            return p
        return Path(repo_path) / p

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_file(cls, path: str | Path) -> "LGTMConfig":
        """Load config overrides from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__}  # noqa: C401
        kwargs = {k: v for k, v in data.items() if k in known}
        unknown = set(data) - known
        if unknown:
            logger.warning("Ignoring unknown config keys: %s", sorted(unknown))
        return cls(**kwargs)


@dataclass(frozen=True)
class GpuModel:
    tag: str
    base_url: str
    reasoning: bool | None


GPU_MODELS: dict[str, GpuModel] = {
    "qwen3.8-27b": GpuModel("qwen3.8:27b", "http://127.0.0.1:11435", False),
}


def apply_gpu_model(config: LGTMConfig, key: str, base_url: str | None = None) -> None:
    """Set ollama_model, ollama_base_url and reasoning from GPU_MODELS[key]; unknown key raises KeyError."""
    entry = GPU_MODELS[key]
    config.ollama_model = entry.tag
    config.ollama_base_url = base_url or entry.base_url
    config.reasoning = entry.reasoning


def setup_logging(verbose: bool = False) -> None:
    """Configure root logging for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet down noisy third-party loggers unless in verbose mode
    if not verbose:
        for noisy in ("httpx", "chromadb", "urllib3", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
