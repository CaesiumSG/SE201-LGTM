"""Index project documentation into ChromaDB for policy retrieval.

Finds ``.md``/``.txt``/``.rst`` files committed at one commit (security
policies, API specs, READMEs), splits them into chunks with line-range
metadata, and stores them in a persistent ChromaDB collection.

Docs are read from a commit, never from the working tree, and the collection
records that commit. A review uses the index only when it was built from the
PR's base commit, so a PR cannot change the policy it is reviewed against.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from lgtm.config import LGTMConfig
from lgtm.diff.git_diff import GitError, list_files_at_ref, read_file_at_ref, resolve_commit

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

# Collection metadata key holding the commit the docs were read from
COMMIT_KEY = "lgtm_commit"

# Approximation: 1 token ~= 4 characters of English text
CHARS_PER_TOKEN = 4


@dataclass
class DocChunk:
    chunk_id: str
    source: str  # path relative to repo root
    start_line: int
    end_line: int
    content: str


def is_doc_path(
    path: str, extensions: tuple[str, ...] = (".md", ".txt", ".rst")
) -> bool:
    """Whether a repo-relative path is a documentation file LGTM indexes."""
    parts = path.replace("\\", "/").split("/")
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return False
    return Path(parts[-1]).suffix.lower() in extensions


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


def _chunk_files(
    repo: Path, commit: str, files: list[str], config: LGTMConfig
) -> list[DocChunk]:
    chunks: list[DocChunk] = []
    for rel in files:
        try:
            text = read_file_at_ref(repo, commit, rel, config.git_timeout)
        except GitError as exc:
            logger.warning("Skipping unreadable file %s: %s", rel, exc)
            continue
        file_chunks = chunk_document(
            text, rel, config.rag_chunk_size, config.rag_chunk_overlap
        )
        chunks.extend(file_chunks)
        logger.debug("Chunked %s into %d chunks", rel, len(file_chunks))
    return chunks


def _replace_collection(
    client, name: str, chunks: list[DocChunk], commit: str
) -> None:
    """Drop and recreate a collection (idempotent re-index)."""
    try:
        client.delete_collection(name)
    except Exception:  # noqa: BLE001 - collection may not exist yet
        pass
    collection = client.create_collection(
        name, metadata={"hnsw:space": "cosine", COMMIT_KEY: commit}
    )
    # Chroma refuses an add() larger than the backend's max batch size (5461
    # on SQLite builds with a 32766 variable limit), so a big repo's chunks
    # must go in several calls. What is indexed is unchanged.
    try:
        batch = max(1, int(client.get_max_batch_size()))
    except Exception:  # noqa: BLE001 - older clients have no such method
        batch = 5000
    for start in range(0, len(chunks), batch):
        part = chunks[start : start + batch]
        collection.add(
            ids=[c.chunk_id for c in part],
            documents=[c.content for c in part],
            metadatas=[
                {
                    "source": c.source,
                    "start_line": c.start_line,
                    "end_line": c.end_line,
                }
                for c in part
            ],
        )


def index_repo_docs(
    repo: str | Path, config: LGTMConfig | None = None, ref: str = "HEAD"
) -> int:
    """Index the docs committed at ``ref``; uncommitted files are left out."""
    import chromadb

    config = config or LGTMConfig()
    repo = Path(repo).resolve()
    commit = resolve_commit(repo, ref, config.git_timeout)
    persist_dir = config.chroma_dir_for(repo)
    persist_dir.mkdir(parents=True, exist_ok=True)

    doc_files = [
        p
        for p in list_files_at_ref(repo, commit, config.git_timeout)
        if is_doc_path(p, config.doc_extensions)
    ]
    logger.info("Found %d documentation files at %s", len(doc_files), commit[:12])
    doc_chunks = _chunk_files(repo, commit, doc_files, config)

    client = chromadb.PersistentClient(path=str(persist_dir))
    _replace_collection(client, config.chroma_collection, doc_chunks, commit)

    logger.info(
        "Indexed %d doc chunks from %d files at %s into %s",
        len(doc_chunks),
        len(doc_files),
        commit[:12],
        persist_dir,
    )
    return len(doc_chunks)
