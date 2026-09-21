"""Dataset manifest builder and integrity tracker for PhishGuard.

Exports and loads `data/manifests/dataset_manifest.csv` following the required schema:
`sample_id, url, label, source, collection_date, domain, screenshot_path, html_path, ssl_available, domain_age_available, ocr_available, visual_embedding_available, split`

Verifies modality availability and prevents missing path inconsistencies.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pandas as pd

from backend.app.core.config import PROJECT_ROOT
from backend.app.core.logging import get_logger

logger = get_logger(__name__)

MANIFEST_HEADER = [
    "sample_id",
    "url",
    "label",
    "source",
    "collection_date",
    "domain",
    "screenshot_path",
    "html_path",
    "ssl_available",
    "domain_age_available",
    "ocr_available",
    "visual_embedding_available",
    "split",
]


class ManifestBuilder:
    """Builder for constructing and validating dataset manifest CSV files.

    Usage:
        builder = ManifestBuilder()
        builder.build_manifest(samples, filename="dataset_manifest.csv")
    """

    def __init__(self, manifests_dir: str | Path | None = None) -> None:
        if manifests_dir:
            self.manifests_dir = Path(manifests_dir)
        else:
            self.manifests_dir = PROJECT_ROOT / "data" / "manifests"
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

    def build_manifest(
        self, samples: list[dict[str, Any]], filename: str = "dataset_manifest.csv"
    ) -> Path:
        """Build CSV dataset manifest from sample dictionary list.

        Args:
            samples: List of sample dictionaries.
            filename: Target CSV filename.

        Returns:
            Path to exported manifest CSV file.
        """
        target_path = self.manifests_dir / filename

        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(MANIFEST_HEADER)

            for s in samples:
                row = [
                    s.get("sample_id", ""),
                    s.get("url", ""),
                    s.get("label", ""),
                    s.get("source", ""),
                    s.get("collection_date", ""),
                    s.get("domain", ""),
                    s.get("screenshot_path", ""),
                    s.get("html_path", ""),
                    s.get("ssl_available", False),
                    s.get("domain_age_available", False),
                    s.get("ocr_available", False),
                    s.get("visual_embedding_available", False),
                    s.get("split", "train"),
                ]
                writer.writerow(row)

        logger.info(f"Dataset manifest with {len(samples)} rows exported to {target_path}")
        return target_path

    def load_manifest(self, filename: str = "dataset_manifest.csv") -> pd.DataFrame:
        """Load manifest CSV into a pandas DataFrame.

        Args:
            filename: CSV filename.

        Returns:
            DataFrame containing manifest columns.
        """
        target_path = self.manifests_dir / filename
        if not target_path.exists():
            logger.warning(f"Manifest file {target_path} not found. Returning empty DataFrame.")
            return pd.DataFrame(columns=MANIFEST_HEADER)

        df = pd.read_csv(target_path)
        logger.info(f"Loaded dataset manifest with {len(df)} rows from {target_path}")
        return df

    def verify_integrity(self, filename: str = "dataset_manifest.csv") -> dict[str, Any]:
        """Verify dataset manifest integrity and file path existence.

        Returns:
            Dictionary with sample counts, label distribution, and missing file counts.
        """
        df = self.load_manifest(filename)
        if df.empty:
            return {"status": "empty", "total_samples": 0}

        missing_screenshots = 0
        missing_html = 0

        for _, row in df.iterrows():
            sc_path = str(row.get("screenshot_path") or "")
            html_path = str(row.get("html_path") or "")

            if sc_path and not Path(sc_path).exists():
                missing_screenshots += 1
            if html_path and not Path(html_path).exists():
                missing_html += 1

        label_counts = df["label"].value_counts().to_dict() if "label" in df.columns else {}
        split_counts = df["split"].value_counts().to_dict() if "split" in df.columns else {}

        report = {
            "status": "valid",
            "total_samples": len(df),
            "label_distribution": label_counts,
            "split_distribution": split_counts,
            "missing_screenshots": missing_screenshots,
            "missing_html": missing_html,
        }
        logger.info(f"Manifest Integrity Report: {report}")
        return report
