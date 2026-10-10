"""Tests for the RAG indexer/retriever (no real Chroma/embeddings needed)."""

from __future__ import annotations

from unittest.mock import MagicMock

from lgtm.config import LGTMConfig
from lgtm.rag.indexer import chunk_document, find_doc_files
from lgtm.rag.retriever import PolicyRetriever, RetrievedChunk


class TestFindDocFiles:
    def test_finds_md_txt_rst(self, tmp_path):
        (tmp_path / "README.md").write_text("readme")
        (tmp_path / "notes.txt").write_text("notes")
        (tmp_path / "spec.rst").write_text("spec")
        (tmp_path / "code.py").write_text("x = 1")
        sub = tmp_path / "docs"
        sub.mkdir()
        (sub / "policy.md").write_text("policy")
        found = {p.name for p in find_doc_files(tmp_path)}
        assert found == {"README.md", "notes.txt", "spec.rst", "policy.md"}

    def test_skips_hidden_and_vendor_dirs(self, tmp_path):
        for skip in (".git", "node_modules", ".lgtm"):
            d = tmp_path / skip
            d.mkdir()
            (d / "x.md").write_text("hidden")
        (tmp_path / "ok.md").write_text("ok")
        found = {p.name for p in find_doc_files(tmp_path)}
        assert found == {"ok.md"}


class TestChunkDocument:
    def test_single_small_chunk(self):
        chunks = chunk_document("line one\nline two\n", "doc.md")
        assert len(chunks) == 1
        assert chunks[0].source == "doc.md"
        assert chunks[0].start_line == 1
        assert chunks[0].end_line == 2

    def test_long_doc_splits_with_line_ranges(self):
        text = "\n".join(f"line {i} " + "x" * 60 for i in range(1, 201))
        chunks = chunk_document(text, "doc.md", chunk_size_tokens=100)
        assert len(chunks) > 1
        # Line ranges must be contiguous-ish and ordered
        assert chunks[0].start_line == 1
        for prev, cur in zip(chunks, chunks[1:]):
            assert cur.start_line > prev.start_line
            assert cur.start_line <= prev.end_line + 1  # overlap or adjacent
        assert chunks[-1].end_line == 200

    def test_empty_doc(self):
        assert chunk_document("", "doc.md") == []

    def test_chunk_ids_unique(self):
        text = "\n".join("word " * 50 for _ in range(100))
        chunks = chunk_document(text, "doc.md", chunk_size_tokens=50)
        ids = [c.chunk_id for c in chunks]
        assert len(ids) == len(set(ids))


class TestPolicyRetriever:
    def _retriever_with_stub(self, tmp_path, query_result) -> PolicyRetriever:
        retriever = PolicyRetriever(tmp_path, LGTMConfig())
        collection = MagicMock()
        collection.count.return_value = 3
        collection.query.return_value = query_result
        retriever._collection = collection
        return retriever

    def test_retrieve_maps_metadata(self, tmp_path):
        retriever = self._retriever_with_stub(
            tmp_path,
            {
                "documents": [["Only admins may delete users."]],
                "metadatas": [[{"source": "policy.md", "start_line": 4, "end_line": 4}]],
                "distances": [[0.25]],
            },
        )
        chunks = retriever.retrieve("who can delete users?")
        assert len(chunks) == 1
        chunk = chunks[0]
        assert isinstance(chunk, RetrievedChunk)
        assert chunk.source == "policy.md"
        assert chunk.score == 0.75
        assert "policy.md:4-4" in chunk.format()

    def test_format_results_empty(self, tmp_path):
        retriever = self._retriever_with_stub(
            tmp_path, {"documents": [[]], "metadatas": [[]], "distances": [[]]}
        )
        assert "No relevant documentation" in retriever.format_results("anything")

    def test_missing_index_raises_filenotfound(self, tmp_path):
        retriever = PolicyRetriever(tmp_path, LGTMConfig())
        assert not retriever.is_available()
