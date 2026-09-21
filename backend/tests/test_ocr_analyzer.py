"""Unit tests for the OCR Analyzer module.

Tests extraction of all 13 OCR features on PIL images, mock OCR outputs, and missing file handling.
"""

from pathlib import Path
from PIL import Image, ImageDraw

import pytest
from backend.app.analyzers.ocr_analyzer import (
    NUM_OCR_FEATURES,
    OCR_FEATURE_NAMES,
    OCRAnalyzer,
    OCRResults,
)


@pytest.fixture
def analyzer() -> OCRAnalyzer:
    """Fixture providing OCRAnalyzer instance."""
    return OCRAnalyzer()


@pytest.fixture
def sample_image(tmp_path: Path) -> Path:
    """Create a synthetic PNG image containing text for testing."""
    img_path = tmp_path / "test_ocr_sample.png"
    img = Image.new("RGB", (600, 300), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 20), "Please Sign In to Your Paypal Account", fill=(0, 0, 0))
    draw.text((20, 80), "Enter Username and Password Immediately", fill=(0, 0, 0))
    img.save(img_path)
    return img_path


class TestOCRAnalyzer:
    """Test suite for OCR feature extraction."""

    def test_feature_count_and_names(self, analyzer: OCRAnalyzer, sample_image: Path) -> None:
        """Verify OCR feature vector length is exactly 13."""
        result = analyzer.extract_features(sample_image)
        assert len(result.features) == NUM_OCR_FEATURES
        assert set(result.features.keys()) == set(OCR_FEATURE_NAMES)

    def test_missing_image_file_handling(self, analyzer: OCRAnalyzer) -> None:
        """Verify non-existent image path fails gracefully with default features."""
        result = analyzer.extract_features("non_existent_file_9999.png")
        assert result.features["word_count"] == 0
        assert result.features["text_length"] == 0
        assert len(result.errors) > 0

    def test_mock_ocr_output_processing(self, analyzer: OCRAnalyzer) -> None:
        """Verify feature calculations on mock EasyOCR output tuples."""
        mock_output = [
            ([[10, 10], [100, 10], [100, 30], [10, 30]], "Urgent: Verify Your Paypal Password Immediately", 0.95),
            ([[10, 40], [100, 40], [100, 60], [10, 60]], "Sign In to Bank Account", 0.88),
        ]
        res = OCRResults()
        analyzer._process_ocr_output(mock_output, 1280, 720, res)

        assert res.features["word_count"] > 5
        assert res.features["num_text_regions"] == 2
        assert res.features["avg_confidence"] > 0.90
        assert res.features["brand_name_count"] >= 1  # paypal
        assert res.features["suspicious_login_terms"] >= 1  # sign in
        assert res.features["urgency_terms"] >= 2  # urgent, verify, immediately
        assert res.features["credential_terms"] >= 1  # password
