"""Unit tests for the Visual Analyzer and FAISS Brand Index modules.

Tests 512-dim visual embedding generation, FAISS index indexing & search,
summary metric extraction, and missing image file error handling.
"""

from pathlib import Path
import numpy as np
import torch
from PIL import Image

import pytest
from backend.app.analyzers.visual_analyzer import (
    NUM_VISUAL_SUMMARY_FEATURES,
    VISUAL_FEATURE_NAMES,
    VisualAnalyzer,
    VisualFeatures,
)
from ml.embeddings.brand_index import BrandIndex


@pytest.fixture
def tmp_index(tmp_path: Path) -> BrandIndex:
    """Fixture providing BrandIndex instance with temporary directory."""
    return BrandIndex(index_dir=tmp_path)


@pytest.fixture
def sample_screenshot(tmp_path: Path) -> Path:
    """Create a synthetic PNG image for testing visual embeddings."""
    img_path = tmp_path / "test_screenshot.png"
    img = Image.new("RGB", (640, 480), color=(0, 102, 204))  # Solid blue image
    img.save(img_path)
    return img_path


class TestBrandIndex:
    """Test suite for FAISS brand index management."""

    def test_add_and_search_brand(self, tmp_index: BrandIndex) -> None:
        """Verify adding vectors and retrieving top-K nearest matches."""
        vec1 = np.random.randn(512).astype("float32")
        vec2 = np.random.randn(512).astype("float32")

        tmp_index.add_brand("PayPal", "paypal.com", vec1)
        tmp_index.add_brand("Google", "google.com", vec2)
        tmp_index.save()

        # Search with vec1 (should match PayPal nearest with high score)
        results = tmp_index.search(vec1, top_k=2)
        assert len(results) == 2
        assert results[0]["brand_name"] == "PayPal"
        assert results[0]["similarity_score"] > 0.90


class TestVisualAnalyzer:
    """Test suite for CLIP visual analyzer."""

    def test_missing_image_file_handling(self, tmp_index: BrandIndex) -> None:
        """Verify non-existent image path fails gracefully with default features."""
        analyzer = VisualAnalyzer(brand_index=tmp_index)
        result = analyzer.extract_features("non_existent_image_12345.png")
        assert result.max_brand_similarity == 0.0
        assert result.features["is_visual_brand_impersonation"] is False
        assert len(result.errors) > 0

    def test_embedding_shape_and_features(self, tmp_index: BrandIndex, sample_screenshot: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify visual embedding generation, 512-dim shape, and summary features with mocked CLIP encoder."""
        # Seed brand index
        ref_vec = np.random.randn(512).astype("float32")
        ref_vec = ref_vec / np.linalg.norm(ref_vec)
        tmp_index.add_brand("TestBrand", "testbrand.com", ref_vec)

        # Mock CLIP model/processor return values for fast offline testing
        mock_features = torch.tensor(ref_vec.copy()).unsqueeze(0)

        class MockModel:
            def get_image_features(self, **kwargs):
                return mock_features

        class MockProcessor:
            def __call__(self, images=None, return_tensors="pt"):
                return {"pixel_values": None}

        analyzer = VisualAnalyzer(brand_index=tmp_index)
        monkeypatch.setattr(analyzer, "_get_model_and_processor", lambda: (MockModel(), MockProcessor()))

        result = analyzer.extract_features(sample_screenshot, sample_id="sample_test_1")

        assert len(result.features) == NUM_VISUAL_SUMMARY_FEATURES
        assert set(result.features.keys()) == set(VISUAL_FEATURE_NAMES)
        assert result.embedding.shape == (512,)
        assert result.features["embedding_norm"] > 0.0
        assert result.features["max_brand_similarity"] > 0.80
        assert Path(result.embedding_path).exists()
