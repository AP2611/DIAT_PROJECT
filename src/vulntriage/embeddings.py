from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path

import numpy as np


class Embedder(ABC):
    model_name: str
    dimension: int

    @abstractmethod
    def encode(self, texts: list[str]) -> np.ndarray:
        raise NotImplementedError


class HashEmbedder(Embedder):
    """Deterministic local embedder for tests. Not for scientific retrieval."""

    def __init__(self, dimension: int = 32, model_name: str = "hash-embedder-v1") -> None:
        self.dimension = dimension
        self.model_name = model_name

    def encode(self, texts: list[str]) -> np.ndarray:
        matrix = np.zeros((len(texts), self.dimension), dtype=np.float32)
        for i, text in enumerate(texts):
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            rng = np.random.default_rng(int.from_bytes(digest[:8], "little"))
            vec = rng.normal(size=self.dimension).astype(np.float32)
            norm = np.linalg.norm(vec) or 1.0
            matrix[i] = vec / norm
        return matrix


class SentenceTransformerEmbedder(Embedder):
    def __init__(self, model_name: str, device: str = "cpu") -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "sentence-transformers is not installed. "
                "Install project deps with: pip install -e ."
            ) from exc
        cache = Path.home() / ".cache" / "huggingface" / "hub"
        local_hint = "models--" + model_name.replace("/", "--")
        if not any(cache.glob(local_hint)) and "/" in model_name:
            # Still attempt load; ST may use another cache. If it tries the network
            # and fails, the exception is surfaced rather than switching providers.
            pass
        try:
            self._model = SentenceTransformer(model_name, device=device)
        except Exception as exc:
            raise RuntimeError(
                f"Local embedding model {model_name!r} could not be loaded: {exc}\n"
                "Obtain it locally (no remote embedding API will be used), e.g.:\n"
                "  python -c \"from sentence_transformers import SentenceTransformer as S; "
                f"S('{model_name}')\"\n"
                "This machine already has sentence-transformers/all-MiniLM-L6-v2 cached "
                "under ~/.cache/huggingface/hub if you keep the default."
            ) from exc
        self.model_name = model_name
        self.dimension = int(self._model.get_sentence_embedding_dimension())

    def encode(self, texts: list[str]) -> np.ndarray:
        vectors = self._model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=len(texts) > 32,
        )
        return np.asarray(vectors, dtype=np.float32)


def load_embedder(model_name: str, device: str = "cpu") -> Embedder:
    if model_name.startswith("hash"):
        return HashEmbedder(model_name=model_name)
    return SentenceTransformerEmbedder(model_name, device=device)
