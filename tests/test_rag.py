"""Tests for the RAG indexer/retriever (no real Chroma/embeddings needed)."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

from lgtm.config import LGTMConfig
from lgtm.rag.indexer import chunk_document, find_doc_files, index_repo_docs
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

    def test_nonempty_chunks_preserve_content_and_line_ranges(self):
        chunks = chunk_document("Access must be authorized.\nAdmins only.", "policy.md")
        assert len(chunks) == 1
        assert chunks[0].content == "Access must be authorized.\nAdmins only."
        assert (chunks[0].source, chunks[0].start_line, chunks[0].end_line) == (
            "policy.md", 1, 2
        )

    def test_chunk_ids_unique(self):
        text = "\n".join("word " * 50 for _ in range(100))
        chunks = chunk_document(text, "doc.md", chunk_size_tokens=50)
        ids = [c.chunk_id for c in chunks]
        assert len(ids) == len(set(ids))


def test_index_repo_docs_replaces_only_policy_collection_and_counts_chunks(
    tmp_path, monkeypatch
):
    (tmp_path / "policy.md").write_text("Admin access requires approval.", encoding="utf-8")
    (tmp_path / "app.py").write_text("def authorize(): pass", encoding="utf-8")
    stale = MagicMock()
    stale.metadata = {"owner": "external"}
    stale.records = {"external-id": ("keep me", {"owner": "external"})}
    policy = MagicMock()
    client = MagicMock()
    client.collections = {"lgtm_code": stale}
    client.delete_collection.side_effect = lambda name: client.collections.pop(name)
    client.create_collection.side_effect = lambda name, metadata=None: client.collections.setdefault(name, policy)
    monkeypatch.setitem(sys.modules, "chromadb", SimpleNamespace(
        PersistentClient=MagicMock(return_value=client)
    ))

    count = index_repo_docs(tmp_path, LGTMConfig())

    assert count == 1
    assert client.delete_collection.call_args_list[0].args == ("lgtm_docs",)
    assert [call.args[0] for call in client.create_collection.call_args_list] == ["lgtm_docs"]
    assert policy.add.call_args.kwargs["documents"] == ["Admin access requires approval."]
    assert policy.add.call_args.kwargs["metadatas"] == [
        {"source": "policy.md", "start_line": 1, "end_line": 1}
    ]
    assert client.collections["lgtm_code"] is stale
    assert stale.metadata == {"owner": "external"}
    assert stale.records == {"external-id": ("keep me", {"owner": "external"})}


class TestReplaceCollectionBatching:
    """Regression: Chroma rejects an add() larger than the backend's max batch
    size (5461 on some SQLite builds), so indexing a repo with more chunks than
    that crashed with "Batch size of N is greater than max batch size"."""

    class _Collection:
        def __init__(self):
            self.batches: list[list[str]] = []

        def add(self, ids, documents, metadatas):
            self.batches.append(list(ids))

    class _Client:
        def __init__(self, limit):
            self.limit = limit
            self.collection = TestReplaceCollectionBatching._Collection()

        def get_max_batch_size(self):
            return self.limit

        def delete_collection(self, name):
            pass

        def create_collection(self, name, metadata=None):
            return self.collection

    @staticmethod
    def _chunks(n):
        from lgtm.rag.indexer import DocChunk

        return [DocChunk(f"id{i}", "a.py", 1, 1, f"text {i}") for i in range(n)]

    def test_adds_in_batches_no_larger_than_the_backend_limit(self):
        from lgtm.rag.indexer import _replace_collection

        client = self._Client(limit=4)
        _replace_collection(client, "code", self._chunks(10))
        sizes = [len(b) for b in client.collection.batches]
        assert max(sizes) <= 4
        assert sum(sizes) == 10

    def test_every_chunk_is_added_exactly_once_in_order(self):
        from lgtm.rag.indexer import _replace_collection

        client = self._Client(limit=3)
        _replace_collection(client, "code", self._chunks(7))
        flat = [i for batch in client.collection.batches for i in batch]
        assert flat == [f"id{i}" for i in range(7)]

    def test_small_index_is_still_one_call(self):
        from lgtm.rag.indexer import _replace_collection

        client = self._Client(limit=5461)
        _replace_collection(client, "docs", self._chunks(5))
        assert len(client.collection.batches) == 1


class TestPolicyRetriever:
    def _retriever_with_stub(self, tmp_path, query_result) -> PolicyRetriever:
        config = LGTMConfig()
        retriever = PolicyRetriever(tmp_path, config)
        collection = MagicMock()
        collection.count.return_value = 3
        collection.query.return_value = query_result
        retriever._collections[config.chroma_collection] = collection
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

    def test_format_results_includes_policy_location_and_content(self, tmp_path):
        retriever = self._retriever_with_stub(
            tmp_path,
            {
                "documents": [["Admins must approve access."]],
                "metadatas": [[{"source": "policy.md", "start_line": 3, "end_line": 4}]],
                "distances": [[0.2]],
            },
        )
        result = retriever.format_results("who approves access?")
        assert "[policy.md:3-4]" in result
        assert "Admins must approve access." in result

    def test_missing_index_raises_filenotfound(self, tmp_path):
        retriever = PolicyRetriever(tmp_path, LGTMConfig())
        assert not retriever.is_available()
