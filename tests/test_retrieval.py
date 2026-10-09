from __future__ import annotations

from pathlib import Path

from vulntriage.embeddings import HashEmbedder
from vulntriage.knowledge_processing import iter_nvd_documents, normalize_knowledge
from vulntriage.retrieval import VectorIndex, leakage_identifiers, should_exclude
from vulntriage.schemas import KnowledgeDocument


def test_nvd_parser_skips_rejected(tiny_nvd: Path):
    docs = list(iter_nvd_documents(tiny_nvd))
    ids = {d.identifier for d in docs}
    assert "CVE-2024-0001" in ids
    assert "CVE-2024-9999" not in ids
    assert docs[0].source == "NVD"
    assert "CWE-89" in docs[0].relationships


def test_normalize_writes_processed(tmp_path: Path, tiny_nvd: Path):
    raw = tmp_path / "raw" / "nvd"
    raw.mkdir(parents=True)
    (raw / tiny_nvd.name).write_text(tiny_nvd.read_text())
    out = tmp_path / "processed" / "documents.jsonl"
    counts = normalize_knowledge(tmp_path / "raw", out, sources=["nvd"])
    assert counts["nvd"] == 1
    assert out.exists()


def test_leakage_filter():
    doc = KnowledgeDocument(
        document_id="nvd:CVE-2024-0001",
        source="NVD",
        identifier="CVE-2024-0001",
        title="CVE-2024-0001",
        description="sql injection",
    )
    excluded = leakage_identifiers("CVE-2024-0001")
    assert should_exclude(doc, excluded)
    other = KnowledgeDocument(
        document_id="nvd:CVE-2024-0002",
        source="NVD",
        identifier="CVE-2024-0002",
        title="x",
        description="y",
    )
    assert not should_exclude(other, excluded)


def test_search_excludes_target_cve(tmp_path: Path):
    docs = [
        KnowledgeDocument(
            document_id="nvd:CVE-2024-0001",
            source="NVD",
            identifier="CVE-2024-0001",
            title="SQL injection in example app",
            description="SQL injection in example app",
        ),
        KnowledgeDocument(
            document_id="cwe:CWE-89",
            source="CWE",
            identifier="CWE-89",
            title="SQL Injection",
            description="Improper neutralization of special elements used in an SQL command",
        ),
    ]
    embedder = HashEmbedder()
    index = VectorIndex(tmp_path / "qdrant", "security_knowledge", embedder)
    meta = index.build(docs)
    assert meta["n_documents"] == 2
    result = index.search(
        "SQL injection in example app",
        top_k=5,
        exclude_identifiers=["CVE-2024-0001"],
    )
    assert result.status == "ok"
    ids = {d.identifier for d in result.documents}
    assert "CVE-2024-0001" not in ids
    assert result.excluded_identifiers
