"""OCR text extraction and feature analysis module for PhishGuard.

Performs Optical Character Recognition on captured website screenshots using EasyOCR.
Extracts 13 visual text features and bounding box metadata.

IMPORTANT RESEARCH DESIGN PRINCIPLE:
    - Keywords extracted via OCR are features for the ML model — NOT hardcoded classification rules.
    - Captures text rendered inside images/canvas/buttons that raw HTML DOM parsers miss.

Feature Groups (13 features total):
    1. word_count (int): Total words recognized in image
    2. text_length (int): Total character length
    3. avg_confidence (float): Mean OCR recognition confidence (0.0 to 1.0)
    4. min_confidence (float): Minimum region confidence score
    5. num_text_regions (int): Total bounding boxes detected
    6. suspicious_login_terms (int): Count of login/signin/auth terms
    7. brand_name_count (int): Count of targeted brand names in visible text
    8. payment_terms (int): Count of payment/bank/credit card terms
    9. urgency_terms (int): Count of urgency terms (immediately, suspended, verify)
    10. credential_terms (int): Count of credential harvest keywords
    11. mixed_language (bool): Multiple character sets/languages detected
    12. text_density (float): Characters per screenshot pixel area
    13. language_detected_score (float): Confidence score of primary language
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PIL import Image

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)

# Keywords for feature extraction (NOT rules)
_LOGIN_TERMS = {"login", "sign in", "signin", "log in", "enter password", "authenticate", "portal"}
_PAYMENT_TERMS = {"credit card", "bank", "card number", "cvv", "payment", "billing", "checkout", "paypal", "visa", "mastercard"}
_URGENCY_TERMS = {"immediately", "urgent", "suspended", "expire", "24 hours", "restricted", "action required", "locked"}
_CREDENTIAL_TERMS = {"password", "username", "ssn", "social security", "passcode", "pin", "otp", "verification code"}


@dataclass
class OCRResults:
    """Container for OCR extraction outputs and feature vectors."""

    raw_text: str = ""
    detected_regions: list[dict[str, Any]] = field(default_factory=list)
    features: dict[str, float | int | bool] = field(default_factory=dict)
    language_detected: str = "en"
    extraction_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Convert features to canonical numerical vector."""
        return [
            float(self.features.get(name, 0.0))
            for name in OCR_FEATURE_NAMES
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "raw_text": self.raw_text,
            "detected_regions_count": len(self.detected_regions),
            "language_detected": self.language_detected,
            "features": self.features,
            "feature_vector": self.to_vector(),
            "feature_names": OCR_FEATURE_NAMES,
            "extraction_time_ms": self.extraction_time_ms,
            "errors": self.errors,
        }


# Canonical order of 13 OCR features
OCR_FEATURE_NAMES: list[str] = [
    "word_count",
    "text_length",
    "avg_confidence",
    "min_confidence",
    "num_text_regions",
    "suspicious_login_terms",
    "brand_name_count",
    "payment_terms",
    "urgency_terms",
    "credential_terms",
    "mixed_language",
    "text_density",
    "language_detected_score",
]

NUM_OCR_FEATURES = len(OCR_FEATURE_NAMES)  # 13


class OCRAnalyzer:
    """Optical Character Recognition feature analyzer.

    Usage:
        analyzer = OCRAnalyzer()
        result = analyzer.extract_features("data/screenshots/sample.png")
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._languages = getattr(settings.ocr, "languages", ["en"])
        self._gpu = getattr(settings.ocr, "gpu", False)
        self._confidence_threshold = getattr(settings.ocr, "confidence_threshold", 0.3)
        self._brand_names = set(
            b.lower() for b in getattr(settings.ocr, "brand_names", [
                "google", "facebook", "microsoft", "apple", "amazon",
                "paypal", "netflix", "instagram", "twitter", "linkedin",
                "chase", "wellsfargo", "bankofamerica", "citi", "dropbox",
                "adobe", "dhl", "usps", "fedex", "walmart",
            ])
        )
        self._reader: Any = None

    def _get_reader(self) -> Any:
        """Lazy initialization of EasyOCR Reader."""
        if self._reader is None:
            try:
                import easyocr
                self._reader = easyocr.Reader(self._languages, gpu=self._gpu)
            except Exception as e:
                logger.warning(f"Failed to initialize EasyOCR reader: {str(e)}")
                self._reader = None
        return self._reader

    def extract_features(self, image_path_or_image: str | Path | Image.Image) -> OCRResults:
        """Extract 13 OCR features from a screenshot image.

        Args:
            image_path_or_image: Path to image file or PIL Image object.

        Returns:
            OCRResults container.
        """
        start_time = time.perf_counter()
        result = OCRResults()

        img: Image.Image | None = None
        img_bytes_path: str | Path | None = None
        width, height = 1280, 720

        try:
            if isinstance(image_path_or_image, (str, Path)):
                img_path = Path(image_path_or_image)
                if not img_path.exists():
                    result.errors.append(f"Image file does not exist: {img_path}")
                    self._fill_defaults(result.features)
                    result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
                    return result
                img = Image.open(img_path)
                img_bytes_path = img_path
            elif isinstance(image_path_or_image, Image.Image):
                img = image_path_or_image
                img_bytes_path = image_path_or_image

            if img:
                width, height = img.size

            reader = self._get_reader()
            if reader and img_bytes_path is not None:
                # Perform EasyOCR read
                if isinstance(img_bytes_path, (str, Path)):
                    ocr_output = reader.readtext(str(img_bytes_path))
                else:
                    # Convert PIL image to byte array for EasyOCR if passed as PIL object
                    import numpy as np
                    ocr_output = reader.readtext(np.array(img_bytes_path))

                self._process_ocr_output(ocr_output, width, height, result)
            else:
                result.errors.append("OCR Engine unavailable")
                self._fill_defaults(result.features)

        except Exception as e:
            result.errors.append(f"OCR processing error: {str(e)}")
            logger.error(f"OCR feature extraction failed: {str(e)}", exc_info=True)
            self._fill_defaults(result.features)

        result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # Assert exactly 13 features present
        assert len(result.features) == NUM_OCR_FEATURES, (
            f"Expected {NUM_OCR_FEATURES} OCR features, got {len(result.features)}. "
            f"Missing: {set(OCR_FEATURE_NAMES) - set(result.features.keys())}"
        )

        return result

    def _process_ocr_output(self, ocr_output: list[Any], width: int, height: int, result: OCRResults) -> None:
        """Process EasyOCR output tuples (bbox, text, confidence)."""
        detected_texts: list[str] = []
        confidences: list[float] = []

        for item in ocr_output:
            bbox, text, conf = item[0], item[1], float(item[2])
            if conf >= self._confidence_threshold:
                clean_text = str(text).strip()
                if clean_text:
                    detected_texts.append(clean_text)
                    confidences.append(conf)
                    result.detected_regions.append({
                        "text": clean_text,
                        "confidence": round(conf, 4),
                        "bbox": bbox,
                    })

        full_raw_text = " ".join(detected_texts)
        result.raw_text = full_raw_text
        words = full_raw_text.split()
        total_chars = len(full_raw_text)

        # 1-5. Text Statistics
        result.features["word_count"] = len(words)
        result.features["text_length"] = total_chars
        result.features["num_text_regions"] = len(confidences)
        result.features["avg_confidence"] = round(sum(confidences) / len(confidences), 4) if confidences else 0.0
        result.features["min_confidence"] = round(min(confidences), 4) if confidences else 0.0

        # 6-10. Keyword Counts
        text_lower = full_raw_text.lower()
        result.features["suspicious_login_terms"] = sum(1 for term in _LOGIN_TERMS if term in text_lower)
        result.features["payment_terms"] = sum(1 for term in _PAYMENT_TERMS if term in text_lower)
        result.features["urgency_terms"] = sum(1 for term in _URGENCY_TERMS if term in text_lower)
        result.features["credential_terms"] = sum(1 for term in _CREDENTIAL_TERMS if term in text_lower)
        result.features["brand_name_count"] = sum(1 for brand in self._brand_names if brand in text_lower)

        # 11. Mixed Language Check
        has_non_ascii = any(ord(char) > 127 for char in full_raw_text)
        has_ascii = any(ord(char) <= 127 and char.isalpha() for char in full_raw_text)
        result.features["mixed_language"] = bool(has_non_ascii and has_ascii)

        # 12. Text Density (characters per 10,000 pixels)
        total_pixels = max(width * height, 1)
        result.features["text_density"] = round((total_chars / total_pixels) * 10000, 4)

        # 13. Language Detected Score
        result.features["language_detected_score"] = round(result.features["avg_confidence"], 4)

    @staticmethod
    def _fill_defaults(features_dict: dict[str, float | int | bool]) -> None:
        """Fill defaults for missing OCR outputs."""
        defaults: dict[str, float | int | bool] = {
            "word_count": 0,
            "text_length": 0,
            "avg_confidence": 0.0,
            "min_confidence": 0.0,
            "num_text_regions": 0,
            "suspicious_login_terms": 0,
            "brand_name_count": 0,
            "payment_terms": 0,
            "urgency_terms": 0,
            "credential_terms": 0,
            "mixed_language": False,
            "text_density": 0.0,
            "language_detected_score": 0.0,
        }
        for name in OCR_FEATURE_NAMES:
            if name not in features_dict:
                features_dict[name] = defaults[name]
