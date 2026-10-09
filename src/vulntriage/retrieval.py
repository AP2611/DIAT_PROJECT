from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from vulntriage.embeddings import Embedder
from vulntriage.schemas import KnowledgeDocument, RetrievedDocument, RetrievalResult

try:
    from qdrant_client import QdrantClient
    from qdrant_client.http import models as qmodels
except ImportError:  # pragma: no cover - exercised only when dep missing
    QdrantClient = None  # type: ignore[misc, assignment]
    qmodels = None  # type: ignore[misc, assignment]


def index_version(embedding_model: str, doc_ids: Iterable[str]) -> str:
    joined = embedding_model + "|" + "|".join(sorted(doc_ids))
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def leakage_identifiers(cve_id: str | None) -> set[str]:
    if not cve_id:
        return set()
    text = cve_id.strip().upper()
    if not text:
        return set()
    return {text, f"nvd:{text}", text.lower()}


def should_exclude(doc: dict[str, Any] | KnowledgeDocument | RetrievedDocument, excluded: set[str]) -> bool:
    if not excluded:
        return False
    if isinstance(doc, (KnowledgeDocument, RetrievedDocument)):
        ident = (doc.identifier or "").upper()
        doc_id = doc.document_id.lower()
    else:
        ident = str(doc.get("identifier") or "").upper()
        doc_id = str(doc.get("document_id") or "").lower()
    excluded_upper = {x.upper() for x in excluded}
    if ident and ident in excluded_upper:
        return True
    if doc_id and doc_id in {x.lower() for x in excluded}:
        return True
    return False


class VectorIndex:
    def __init__(
        self,
        path: Path,
        collection_name: str,
        embedder: Embedder,
    ) -> None:
        if QdrantClient is None:
            raise RuntimeError("qdrant-client is not installed. pip install -e .")
        path.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.collection_name = collection_name
        self.embedder = embedder
        self.client = QdrantClient(path=str(path))
        self.meta_path = path / "index_meta.json"

    def _ensure_collection(self) -> None:
        existing = {c.name for c in self.client.get_collections().collections}
        if self.collection_name not in existing:
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=qmodels.VectorParams(
                    size=self.embedder.dimension,
                    distance=qmodels.Distance.COSINE,
                ),
            )

    def build(self, documents: list[KnowledgeDocument], *, batch_size: int = 64) -> dict[str, Any]:
        existing = {c.name for c in self.client.get_collections().collections}
        if self.collection_name in existing:
            self.client.delete_collection(self.collection_name)
        self._ensure_collection()
        ids = []
        for start in range(0, len(documents), batch_size):
            batch = documents[start : start + batch_size]
            vectors = self.embedder.encode([doc.embed_text() for doc in batch])
            points = []
            for offset, doc in enumerate(batch):
                ids.append(doc.document_id)
                points.append(
                    qmodels.PointStruct(
                        id=start + offset,
                        vector=vectors[offset].tolist(),
                        payload=doc.model_dump(),
                    )
                )
            self.client.upsert(collection_name=self.collection_name, points=points)
        meta = {
            "embedding_model": self.embedder.model_name,
            "dimension": self.embedder.dimension,
            "collection_name": self.collection_name,
            "n_documents": len(documents),
            "index_version": index_version(self.embedder.model_name, ids),
            "retrieval_metrics": (
                "Retrieval Precision@k / Recall@k / MRR / nDCG are not reported "
                "because this prototype has no labelled relevance judgments (qrels)."
            ),
        }
        self.meta_path.write_text(json.dumps(meta, indent=2))
        return meta

    def _query(self, vector: list[float], limit: int):
        if hasattr(self.client, "query_points"):
            response = self.client.query_points(
                collection_name=self.collection_name,
                query=vector,
                limit=limit,
                with_payload=True,
            )
            return list(getattr(response, "points", response))
        return self.client.search(
            collection_name=self.collection_name,
            query_vector=vector,
            limit=limit,
            with_payload=True,
        )

    def load_meta(self) -> dict[str, Any]:
        if self.meta_path.exists():
            return json.loads(self.meta_path.read_text())
        return {}

    def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        exclude_identifiers: Iterable[str] | None = None,
    ) -> RetrievalResult:
        excluded = leakage_identifiers(None)
        for ident in exclude_identifiers or []:
            excluded |= leakage_identifiers(ident)
        try:
            self._ensure_collection()
            vector = self.embedder.encode([query])[0].tolist()
            # Over-fetch so leakage filtering can drop matching CVE records.
            limit = top_k + max(5, len(excluded) * 3)
            hits = self._query(vector, limit)
        except Exception as exc:
            return RetrievalResult(
                status="error",
                query=query,
                excluded_identifiers=sorted(excluded),
                error=str(exc),
                index_version=self.load_meta().get("index_version"),
                embedding_model=self.embedder.model_name,
            )
        docs: list[RetrievedDocument] = []
        for hit in hits:
            payload = hit.payload or {}
            if should_exclude(payload, excluded):
                continue
            docs.append(
                RetrievedDocument(
                    document_id=str(payload.get("document_id") or hit.id),
                    score=float(hit.score),
                    source=str(payload.get("source") or ""),
                    source_version=payload.get("source_version"),
                    identifier=payload.get("identifier"),
                    title=payload.get("title"),
                    description=payload.get("description"),
                    relationships=list(payload.get("relationships") or []),
                    references=list(payload.get("references") or []),
                )
            )
            if len(docs) >= top_k:
                break
        meta = self.load_meta()
        return RetrievalResult(
            status="ok",
            documents=docs,
            query=query,
            excluded_identifiers=sorted(excluded),
            index_version=meta.get("index_version"),
            embedding_model=self.embedder.model_name,
        )


def code_query(code: str, max_chars: int = 1500) -> str:
    """Build a retrieval query from source code only (no labels or CVE/CWE answers)."""
    compact = " ".join(code.split())
    return compact[:max_chars]
