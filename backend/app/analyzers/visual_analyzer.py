"""Visual embedding feature extraction and brand similarity analysis for PhishGuard.

Uses OpenAI CLIP (ViT-B/32) vision encoder to generate 512-dimensional visual
embeddings from website screenshots. Queries FAISS vector index to measure
similarity against legitimate reference brand signatures.

IMPORTANT RESEARCH DESIGN PRINCIPLE:
    - High visual similarity is evidence of brand intent, NOT standalone proof of phishing.
    - Used alongside URL, HTML, SSL, Domain, and OCR features in feature fusion.

Features (5 visual summary metrics + 512-dim embedding):
    1. max_brand_similarity (float): Highest cosine similarity score to a reference brand (0.0 to 1.0)
    2. is_visual_brand_impersonation (bool): High similarity (>0.80) to brand template
    3. top1_similarity (float): Nearest neighbor similarity score
    4. top5_avg_similarity (float): Average score of top 5 matches
    5. embedding_norm (float): L2 norm of the raw visual embedding
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

try:
    import torch
    from transformers import CLIPModel, CLIPProcessor
    _CLIP_AVAILABLE = True
except ImportError:
    _CLIP_AVAILABLE = False

from backend.app.core.config import PROJECT_ROOT, get_settings
from backend.app.core.logging import get_logger
from ml.embeddings.brand_index import BrandIndex

logger = get_logger(__name__)


@dataclass
class VisualFeatures:
    """Container for extracted visual features and embedding vector."""

    embedding: np.ndarray = field(default_factory=lambda: np.zeros((512,), dtype=np.float32))
    max_brand_similarity: float = 0.0
    nearest_brand: str = "none"
    nearest_domain: str = "none"
    top_matches: list[dict[str, Any]] = field(default_factory=list)
    features: dict[str, float | int | bool] = field(default_factory=dict)
    embedding_path: str = ""
    extraction_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Convert visual summary metrics to numerical feature vector."""
        return [
            float(self.features.get(name, 0.0))
            for name in VISUAL_FEATURE_NAMES
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "max_brand_similarity": self.max_brand_similarity,
            "nearest_brand": self.nearest_brand,
            "nearest_domain": self.nearest_domain,
            "top_matches": self.top_matches,
            "embedding_shape": list(self.embedding.shape),
            "features": self.features,
            "feature_vector": self.to_vector(),
            "feature_names": VISUAL_FEATURE_NAMES,
            "embedding_path": self.embedding_path,
            "extraction_time_ms": self.extraction_time_ms,
            "errors": self.errors,
        }


# Summary visual features (in addition to 512-dim embedding)
VISUAL_FEATURE_NAMES: list[str] = [
    "max_brand_similarity",
    "is_visual_brand_impersonation",
    "top1_similarity",
    "top5_avg_similarity",
    "embedding_norm",
]

NUM_VISUAL_SUMMARY_FEATURES = len(VISUAL_FEATURE_NAMES)  # 5


class VisualAnalyzer:
    """CLIP-based visual screenshot analyzer and FAISS brand match retriever.

    Usage:
        analyzer = VisualAnalyzer()
        result = analyzer.extract_features("data/screenshots/sample.png", sample_id="sample_1")
    """

    def __init__(self, brand_index: BrandIndex | None = None) -> None:
        settings = get_settings()
        self._model_name = getattr(settings.visual, "model_name", "openai/clip-vit-base-patch32")
        self._embedding_dim = getattr(settings.visual, "embedding_dim", 512)
        self._similarity_threshold = getattr(settings.visual, "similarity_threshold", 0.85)

        self._model: Any = None
        self._processor: Any = None

        self._brand_index = brand_index or BrandIndex()

        self._embeddings_dir = PROJECT_ROOT / "data" / "processed" / "visual_embeddings"
        self._embeddings_dir.mkdir(parents=True, exist_ok=True)

    def _get_model_and_processor(self) -> tuple[Any, Any]:
        """Lazy load CLIP model and processor from Hugging Face."""
        if self._model is None or self._processor is None:
            if not _CLIP_AVAILABLE:
                logger.warning("Torch / Transformers not available for CLIP model")
                return None, None
            try:
                logger.info(f"Loading CLIP vision encoder ({self._model_name})...")
                self._model = CLIPModel.from_pretrained(self._model_name)
                self._processor = CLIPProcessor.from_pretrained(self._model_name)
                self._model.eval()
            except Exception as e:
                logger.error(f"Failed to load CLIP model ({self._model_name}): {str(e)}")
                return None, None
        return self._model, self._processor

    def extract_features(
        self,
        image_path_or_image: str | Path | Image.Image,
        sample_id: str | None = None,
        save_embedding: bool = True,
    ) -> VisualFeatures:
        """Extract 512-dim CLIP visual embedding and compute brand similarity.

        Args:
            image_path_or_image: Path to screenshot PNG or PIL Image.
            sample_id: Identifier for saving .npy file.
            save_embedding: Whether to save array to data/processed/visual_embeddings/.

        Returns:
            VisualFeatures container.
        """
        start_time = time.perf_counter()
        result = VisualFeatures()

        img: Image.Image | None = None
        if isinstance(image_path_or_image, (str, Path)):
            img_path = Path(image_path_or_image)
            if not img_path.exists():
                result.errors.append(f"Screenshot file does not exist: {img_path}")
                self._fill_defaults(result.features)
                result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
                return result
            try:
                img = Image.open(img_path).convert("RGB")
            except Exception as e:
                result.errors.append(f"Failed to open image file: {str(e)}")
                self._fill_defaults(result.features)
                result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
                return result
        elif isinstance(image_path_or_image, Image.Image):
            img = image_path_or_image.convert("RGB")

        model, processor = self._get_model_and_processor()

        if model is not None and processor is not None and img is not None:
            try:
                inputs = processor(images=img, return_tensors="pt")
                with torch.no_grad():
                    outputs = model.get_image_features(**inputs)
                    if hasattr(outputs, "image_embeds"):
                        image_features = outputs.image_embeds
                    elif hasattr(outputs, "pooler_output"):
                        image_features = outputs.pooler_output
                    elif isinstance(outputs, torch.Tensor):
                        image_features = outputs
                    else:
                        image_features = outputs[0]
                    # L2 Normalize embedding
                    image_features = image_features / image_features.norm(dim=-1, keepdim=True)
                    embedding_np = image_features.cpu().numpy().squeeze().astype(np.float32)

                result.embedding = embedding_np
                norm_val = float(np.linalg.norm(embedding_np))
                result.features["embedding_norm"] = round(norm_val, 4)

                # Save .npy vector to disk
                if save_embedding and sample_id:
                    npy_path = self._embeddings_dir / f"{sample_id}.npy"
                    np.save(npy_path, embedding_np)
                    result.embedding_path = str(npy_path)

                # Search FAISS index for brand template similarity
                matches = self._brand_index.search(embedding_np, top_k=5)
                result.top_matches = matches

                if matches:
                    top1 = matches[0]
                    result.max_brand_similarity = round(top1["similarity_score"], 4)
                    result.nearest_brand = top1["brand_name"]
                    result.nearest_domain = top1["domain"]

                    scores = [m["similarity_score"] for m in matches]
                    result.features["max_brand_similarity"] = result.max_brand_similarity
                    result.features["is_visual_brand_impersonation"] = result.max_brand_similarity >= self._similarity_threshold
                    result.features["top1_similarity"] = result.max_brand_similarity
                    result.features["top5_avg_similarity"] = round(float(np.mean(scores)), 4)
                else:
                    self._fill_defaults(result.features)

            except Exception as e:
                result.errors.append(f"CLIP embedding extraction error: {str(e)}")
                logger.error(f"Visual analyzer failed: {str(e)}", exc_info=True)
                self._fill_defaults(result.features)
        else:
            result.errors.append("CLIP model or image unavailable")
            self._fill_defaults(result.features)

        result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # Assert summary features
        assert len(result.features) == NUM_VISUAL_SUMMARY_FEATURES, (
            f"Expected {NUM_VISUAL_SUMMARY_FEATURES} summary features, got {len(result.features)}."
        )

        return result

    @staticmethod
    def _fill_defaults(features_dict: dict[str, float | int | bool]) -> None:
        """Fill defaults for missing visual features."""
        defaults: dict[str, float | int | bool] = {
            "max_brand_similarity": 0.0,
            "is_visual_brand_impersonation": False,
            "top1_similarity": 0.0,
            "top5_avg_similarity": 0.0,
            "embedding_norm": 0.0,
        }
        for name in VISUAL_FEATURE_NAMES:
            if name not in features_dict:
                features_dict[name] = defaults[name]
