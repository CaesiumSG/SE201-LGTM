"""Retrieve relevant policy/documentation chunks from the ChromaDB index."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from lgtm.agents import registry
from lgtm.config import LGTMConfig

logger = logging.getLogger(__name__)


@dataclass
class RetrievedChunk:
    source: str
    start_line: int
    end_line: int
    content: str
    score: float  # similarity in [0, 1], higher is more relevant

    def format(self) -> str:
        return registry.render(
            "retriever.chunk_header",
            source=self.source,
            start_line=self.start_line,
            end_line=self.end_line,
            score=self.score,
            content=self.content,
        )


class PolicyRetriever:
    """Query interface over the indexed project documentation."""

    def __init__(self, repo: str | Path, config: LGTMConfig | None = None):
        self.config = config or LGTMConfig()
        self.repo = Path(repo).resolve()
        self._collections: dict[str, object] = {}

    def _get_collection(self, name: str | None = None):
        name = name or self.config.chroma_collection
        if name not in self._collections:
            import chromadb

            persist_dir = self.config.chroma_dir_for(self.repo)
            if not persist_dir.exists():
                raise FileNotFoundError(
                    registry.render("retriever.index_missing", persist_dir=persist_dir)
                )
            client = chromadb.PersistentClient(path=str(persist_dir))
            self._collections[name] = client.get_collection(name)
        return self._collections[name]

    def is_available(self) -> bool:
        try:
            self._get_collection()
            return True
        except Exception:  # noqa: BLE001
            return False

    def retrieve(
        self,
        query: str,
        top_k: int | None = None,
        collection_name: str | None = None,
    ) -> list[RetrievedChunk]:
        """Return the top-k most relevant documentation chunks for a query."""
        top_k = top_k or self.config.rag_top_k
        collection = self._get_collection(collection_name)
        n_available = collection.count()
        if n_available == 0:
            return []
        result = collection.query(
            query_texts=[query], n_results=min(top_k, n_available)
        )
        chunks: list[RetrievedChunk] = []
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        dists = result.get("distances", [[]])[0] if result.get("distances") else []
        for i, doc in enumerate(docs):
            meta = metas[i] if i < len(metas) else {}
            distance = dists[i] if i < len(dists) else 1.0
            # cosine distance -> similarity
            score = max(0.0, 1.0 - float(distance))
            chunks.append(
                RetrievedChunk(
                    source=str(meta.get("source", "unknown")),
                    start_line=int(meta.get("start_line", 0)),
                    end_line=int(meta.get("end_line", 0)),
                    content=doc,
                    score=score,
                )
            )
        logger.debug("Retrieved %d chunks for query %r", len(chunks), query)
        return chunks

    def format_results(self, query: str, top_k: int | None = None) -> str:
        """Retrieve and render doc results as a string for agent prompts."""
        chunks = self.retrieve(query, top_k)
        if not chunks:
            return registry.entry("retriever.no_results")
        return registry.entry("retriever.chunk_separator").join(c.format() for c in chunks)
