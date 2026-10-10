"""Configuration for the LGTM pipeline."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class LGTMConfig:
    """Central configuration for all LGTM components."""

    # LLM
    ollama_model: str = "qwen2.5:7b"
    ollama_base_url: str = "http://localhost:11434"
    llm_temperature: float = 0.0
    llm_timeout: int = 180  # seconds per LLM call

    # SAST
    semgrep_config: str = "auto"  # "auto" or a path to custom rules
    semgrep_timeout: int = 300  # seconds for the whole semgrep run

    # Agents
    max_tool_calls: int = 5  # per agent invocation
    max_agent_iterations: int = 8  # hard stop on the reasoning loop

    # RAG
    rag_chunk_size: int = 500  # approx tokens per chunk
    rag_chunk_overlap: int = 50
    rag_top_k: int = 5
    embedding_model: str = "all-MiniLM-L6-v2"
    chroma_persist_dir: str = ".lgtm/chroma"
    chroma_collection: str = "lgtm_docs"

    # Git
    git_timeout: int = 60

    # Output
    output_dir: str = "lgtm-output"

    # Pipeline modes: "lgtm" (SAST + LLM), "sast-only", "llm-only"
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
