"""FAISS Vector Index for Brand Reference Embeddings.

Stores 512-dimensional CLIP embeddings of legitimate reference brand screenshots
(e.g., Google, Microsoft, PayPal, Chase, Apple). Uses FAISS IndexFlatIP
for high-speed cosine similarity retrieval.

Research Design Principle:
    - High visual similarity to a legitimate brand domain (when the website's domain
      does NOT match the brand domain) serves as evidence of brand impersonation.
    - Used as a quantitative input signal to the multimodal model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

try:
    import faiss
    _FAISS_AVAILABLE = True
except ImportError:
    _FAISS_AVAILABLE = False

from backend.app.core.config import PROJECT_ROOT
from backend.app.core.logging import get_logger

logger = get_logger(__name__)


class BrandIndex:
    """FAISS vector database index for legitimate brand template matching.

    Usage:
        index = BrandIndex()
        index.add_brand("PayPal", "paypal.com", embedding_512)
        index.save()
        results = index.search(query_embedding, top_k=5)
    """

    def __init__(self, index_dir: str | Path | None = None, embedding_dim: int = 512) -> None:
        self.embedding_dim = embedding_dim
        if index_dir:
            self.index_dir = Path(index_dir)
        else:
            self.index_dir = PROJECT_ROOT / "data" / "brand_references"
        
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.faiss_path = self.index_dir / "brand_index.faiss"
        self.metadata_path = self.index_dir / "brand_metadata.json"

        self.metadata: list[dict[str, Any]] = []
        self._index: Any = None

        self._init_or_load_index()

    def _init_or_load_index(self) -> None:
        """Load index from disk or create a new FAISS inner product index."""
        if _FAISS_AVAILABLE and self.faiss_path.exists() and self.metadata_path.exists():
            try:
                self._index = faiss.read_index(str(self.faiss_path))
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                logger.info(f"Loaded FAISS brand index with {self._index.ntotal} vectors")
                return
            except Exception as e:
                logger.warning(f"Failed loading FAISS index from disk: {str(e)}")

        if _FAISS_AVAILABLE:
            # Cosine similarity using IndexFlatIP on L2-normalized vectors
            self._index = faiss.IndexFlatIP(self.embedding_dim)
        else:
            self._index = None

    def add_brand(self, brand_name: str, domain: str, embedding: np.ndarray) -> None:
        """Add a reference brand embedding to the index.

        Args:
            brand_name: Canonical name of brand (e.g. "PayPal").
            domain: Legitimate domain of brand (e.g. "paypal.com").
            embedding: 512-dim numpy array.
        """
        vec = np.ascontiguousarray(embedding.astype("float32").reshape(1, -1))
        # Normalize for inner product (cosine similarity)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm

        if _FAISS_AVAILABLE and self._index is not None:
            self._index.add(vec)

        self.metadata.append({
            "brand_name": brand_name,
            "domain": domain,
            "index_id": len(self.metadata),
        })

    def save(self) -> None:
        """Persist FAISS index and metadata to disk."""
        if _FAISS_AVAILABLE and self._index is not None:
            faiss.write_index(self._index, str(self.faiss_path))
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

    def search(self, query_embedding: np.ndarray, top_k: int = 5) -> list[dict[str, Any]]:
        """Find top-K visually similar legitimate brand signatures.

        Args:
            query_embedding: 512-dim numpy array of target screenshot.
            top_k: Number of nearest matches to return.

        Returns:
            List of match dictionaries containing brand_name, domain, and similarity score.
        """
        if not _FAISS_AVAILABLE or self._index is None or self._index.ntotal == 0:
            return []

        vec = np.ascontiguousarray(query_embedding.astype("float32").reshape(1, -1))
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm

        k = min(top_k, self._index.ntotal)
        scores, indices = self._index.search(vec, k)

        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= 0 and idx < len(self.metadata):
                meta = self.metadata[idx].copy()
                meta["similarity_score"] = float(score)
                results.append(meta)

        return results
