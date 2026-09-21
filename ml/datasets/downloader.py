"""Dataset downloader and dataset acquisition module for PhishGuard.

Downloads active phishing URL feeds (PhishTank) and top legitimate domain lists (Tranco).
Includes fallback offline sample generation for reproducible automated testing.

Sources:
    - PhishTank Bulk Data: http://data.phishtank.com/data/online-valid.csv
    - Tranco Top 1M List: https://tranco-list.eu/top-1m.csv.zip
"""

from __future__ import annotations

import csv
import io
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import tldextract

from backend.app.core.config import PROJECT_ROOT
from backend.app.core.logging import get_logger

logger = get_logger(__name__)

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


class DatasetDownloader:
    """Downloader for raw phishing and benign URL datasets.

    Usage:
        downloader = DatasetDownloader()
        downloader.download_all()
    """

    def __init__(self, raw_dir: str | Path | None = None) -> None:
        if raw_dir:
            self.raw_dir = Path(raw_dir)
        else:
            self.raw_dir = PROJECT_ROOT / "data" / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def download_phishtank(self, filename: str = "phishtank_raw.csv") -> Path:
        """Download latest PhishTank online phishing URL dataset.

        Returns:
            Path to downloaded CSV file.
        """
        target_path = self.raw_dir / filename
        logger.info(f"Downloading PhishTank data from {PHISHTANK_URL}...")
        try:
            with httpx.Client(timeout=30.0, follow_redirects=True) as client:
                resp = client.get(PHISHTANK_URL)
                resp.raise_for_status()
                with open(target_path, "wb") as f:
                    f.write(resp.content)
            logger.info(f"PhishTank data saved to {target_path}")
        except Exception as e:
            logger.warning(f"PhishTank download failed: {str(e)}. Generating fallback synthetic set.")
            self._create_fallback_phishing_set(target_path)
        return target_path

    def download_tranco(self, filename: str = "tranco_raw.csv") -> Path:
        """Download latest Tranco top 1M benign domain list.

        Returns:
            Path to downloaded CSV file.
        """
        target_path = self.raw_dir / filename
        logger.info(f"Downloading Tranco Top 1M list from {TRANCO_URL}...")
        try:
            with httpx.Client(timeout=30.0, follow_redirects=True) as client:
                resp = client.get(TRANCO_URL)
                resp.raise_for_status()
                # Unzip in memory
                with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
                    for name in z.namelist():
                        if name.endswith(".csv"):
                            content = z.read(name)
                            with open(target_path, "wb") as f:
                                f.write(content)
                            break
            logger.info(f"Tranco Top 1M data saved to {target_path}")
        except Exception as e:
            logger.warning(f"Tranco download failed: {str(e)}. Generating fallback benign set.")
            self._create_fallback_benign_set(target_path)
        return target_path

    def generate_reproducible_sample_set(self, num_samples: int = 100) -> list[dict[str, Any]]:
        """Generate a balanced, reproducible sample list for pipeline testing.

        Args:
            num_samples: Number of total samples (50% benign, 50% phishing).

        Returns:
            List of sample dictionaries.
        """
        samples: list[dict[str, Any]] = []
        now_str = datetime.now(timezone.utc).isoformat()

        half = num_samples // 2

        benign_domains = [
            "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
            "wikipedia.org", "cloudflare.com", "python.org", "mozilla.org", "stackoverflow.com"
        ]

        phishing_patterns = [
            "http://login-paypal-verify-secure.xyz/account/login",
            "http://chase-bank-alert-update.top/security/index.php",
            "http://account-verify-apple-id.click/auth/verify",
            "http://netflix-billing-update-required.work/login.html",
            "http://microsoft-online-drive-verify.buzz/signin",
            "http://wellsfargo-unusual-activity-alert.xyz/verify",
            "http://amazon-prime-order-update.top/confirm",
            "http://instagram-copyright-infringement.click/support",
            "http://dhl-express-package-delivery.work/tracking",
            "http://bankofamerica-card-security.buzz/update"
        ]

        # Generate Benign Samples
        for i in range(half):
            dom = benign_domains[i % len(benign_domains)]
            url = f"https://www.{dom}/page_{i}"
            samples.append({
                "sample_id": f"benign_{i+1:04d}",
                "url": url,
                "label": "benign",
                "source": "tranco",
                "collection_date": now_str,
                "domain": dom,
            })

        # Generate Phishing Samples
        for i in range(half):
            url = phishing_patterns[i % len(phishing_patterns)]
            ext = tldextract.extract(url)
            dom = f"{ext.domain}.{ext.suffix}" if ext.domain else "phish.com"
            samples.append({
                "sample_id": f"phishing_{i+1:04d}",
                "url": url,
                "label": "phishing",
                "source": "phishtank",
                "collection_date": now_str,
                "domain": dom,
            })

        return samples

    def _create_fallback_phishing_set(self, target_path: Path) -> None:
        """Create fallback raw phishing CSV file if remote download fails."""
        samples = self.generate_reproducible_sample_set(50)
        phish_samples = [s for s in samples if s["label"] == "phishing"]
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["phish_id", "url", "phish_detail_url", "submission_time", "verified", "target"])
            for idx, s in enumerate(phish_samples):
                writer.writerow([idx + 1000, s["url"], "http://phishtank.com/detail", s["collection_date"], "yes", "various"])

    def _create_fallback_benign_set(self, target_path: Path) -> None:
        """Create fallback raw benign CSV file if remote download fails."""
        samples = self.generate_reproducible_sample_set(50)
        benign_samples = [s for s in samples if s["label"] == "benign"]
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for idx, s in enumerate(benign_samples):
                writer.writerow([idx + 1, s["domain"]])
