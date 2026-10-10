"""Index project documentation into ChromaDB for policy retrieval.

Finds ``.md``/``.txt``/``.rst`` files in a repository (security policies,
API specs, READMEs), splits them into chunks with line-range metadata, and
stores them in a persistent ChromaDB collection.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from lgtm.config import LGTMConfig

logger = logging.getLogger(__name__)

# Directories never worth indexing
SKIP_DIRS = {
    ".git",
    ".lgtm",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}

# Approximation: 1 token ~= 4 characters of English text
CHARS_PER_TOKEN = 4


@dataclass
class DocChunk:
    chunk_id: str
    source: str  # path relative to repo root
    start_line: int
    end_line: int
    content: str


def find_doc_files(
    repo: str | Path, extensions: tuple[str, ...] = (".md", ".txt", ".rst")
) -> list[Path]:
    """Recursively find documentation files in a repository."""
    repo = Path(repo)
    docs: list[Path] = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
            continue
        docs.append(path)
    return docs


def chunk_document(
    text: str,
    source: str,
    chunk_size_tokens: int = 500,
    overlap_tokens: int = 50,
) -> list[DocChunk]:
    """Split a document into chunks of roughly ``chunk_size_tokens`` tokens.

    Splits on line boundaries so each chunk carries an accurate line range
    (needed later by the evidence validator).
    """
    max_chars = chunk_size_tokens * CHARS_PER_TOKEN
    overlap_chars = overlap_tokens * CHARS_PER_TOKEN

    lines = text.splitlines()
    if not lines:
        return []

    chunks: list[DocChunk] = []
    start_idx = 0
    while start_idx < len(lines):
        size = 0
        end_idx = start_idx
        while end_idx < len(lines) and size < max_chars:
            size += len(lines[end_idx]) + 1
            end_idx += 1
        content = "\n".join(lines[start_idx:end_idx]).strip()
        if content:
            chunk_id = hashlib.sha1(
                f"{source}:{start_idx + 1}:{end_idx}".encode()
            ).hexdigest()[:16]
            chunks.append(
                DocChunk(
                    chunk_id=chunk_id,
                    source=source,
                    start_line=start_idx + 1,
                    end_line=end_idx,
                    content=content,
                )
            )
        if end_idx >= len(lines):
            break
        # Step back a few lines for overlap
        back = 0
        overlap_size = 0
        while back < end_idx - start_idx - 1 and overlap_size < overlap_chars:
            back += 1
            overlap_size += len(lines[end_idx - back]) + 1
        start_idx = max(end_idx - back, start_idx + 1)
    return chunks


def index_repo_docs(repo: str | Path, config: LGTMConfig | None = None) -> int:
    """Index all documentation files of ``repo`` into ChromaDB.

    Returns the number of chunks indexed. Re-indexing replaces the existing
    collection so the index never goes stale.
    """
    import chromadb

    config = config or LGTMConfig()
    repo = Path(repo).resolve()
    persist_dir = config.chroma_dir_for(repo)
    persist_dir.mkdir(parents=True, exist_ok=True)

    doc_files = find_doc_files(repo, config.doc_extensions)
    logger.info("Found %d documentation files to index", len(doc_files))

    all_chunks: list[DocChunk] = []
    for doc_path in doc_files:
        rel = str(doc_path.relative_to(repo))
        try:
            text = doc_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Skipping unreadable file %s: %s", rel, exc)
            continue
        chunks = chunk_document(
            text, rel, config.rag_chunk_size, config.rag_chunk_overlap
        )
        all_chunks.extend(chunks)
        logger.debug("Chunked %s into %d chunks", rel, len(chunks))

    client = chromadb.PersistentClient(path=str(persist_dir))
    # Replace any previous index for idempotency
    try:
        client.delete_collection(config.chroma_collection)
    except Exception:  # noqa: BLE001 - collection may not exist yet
        pass
    collection = client.create_collection(
        config.chroma_collection, metadata={"hnsw:space": "cosine"}
    )

    if all_chunks:
        collection.add(
            ids=[c.chunk_id for c in all_chunks],
            documents=[c.content for c in all_chunks],
            metadatas=[
                {
                    "source": c.source,
                    "start_line": c.start_line,
                    "end_line": c.end_line,
                }
                for c in all_chunks
            ],
        )
    logger.info(
        "Indexed %d chunks from %d files into %s",
        len(all_chunks),
        len(doc_files),
        persist_dir,
    )
    return len(all_chunks)
