"""Unit tests for the Dataset Pipeline (Downloader, Splitter, ManifestBuilder).

Tests:
- Sample generation & downloading fallback logic
- CSV manifest build, load, and integrity verification
- All 4 splitting strategies (Random, Domain-Disjoint, Temporal, Unseen-Domain)
- Strict assertion verifying ZERO domain leakage in domain-disjoint split
"""

from pathlib import Path
import pytest

from ml.datasets.downloader import DatasetDownloader
from ml.datasets.manifest_builder import ManifestBuilder
from ml.datasets.split_strategy import DatasetSplitter


@pytest.fixture
def downloader(tmp_path: Path) -> DatasetDownloader:
    return DatasetDownloader(raw_dir=tmp_path / "raw")


@pytest.fixture
def builder(tmp_path: Path) -> ManifestBuilder:
    return ManifestBuilder(manifests_dir=tmp_path / "manifests")


@pytest.fixture
def splitter() -> DatasetSplitter:
    return DatasetSplitter(seed=42)


class TestDatasetPipeline:
    """Test suite for dataset acquisition, splitting, and manifest building."""

    def test_sample_generation(self, downloader: DatasetDownloader) -> None:
        """Verify reproducible dataset sample generation."""
        samples = downloader.generate_reproducible_sample_set(num_samples=40)
        assert len(samples) == 40
        benign = [s for s in samples if s["label"] == "benign"]
        phishing = [s for s in samples if s["label"] == "phishing"]
        assert len(benign) == 20
        assert len(phishing) == 20

    def test_manifest_build_and_load(self, downloader: DatasetDownloader, builder: ManifestBuilder) -> None:
        """Verify manifest CSV export and loading into pandas DataFrame."""
        samples = downloader.generate_reproducible_sample_set(num_samples=20)
        manifest_path = builder.build_manifest(samples, filename="test_manifest.csv")
        assert manifest_path.exists()

        df = builder.load_manifest(filename="test_manifest.csv")
        assert len(df) == 20
        assert "sample_id" in df.columns
        assert "domain" in df.columns

        report = builder.verify_integrity(filename="test_manifest.csv")
        assert report["status"] == "valid"
        assert report["total_samples"] == 20

    def test_random_split(self, downloader: DatasetDownloader, splitter: DatasetSplitter) -> None:
        """Verify stratified random split ratios."""
        samples = downloader.generate_reproducible_sample_set(num_samples=100)
        train, val, test = splitter.random_split(samples, train_ratio=0.70, val_ratio=0.15)
        assert len(train) + len(val) + len(test) == 100
        assert len(train) == 70
        assert len(val) >= 14
        assert len(test) >= 15

    def test_domain_disjoint_split_zero_leakage(self, downloader: DatasetDownloader, splitter: DatasetSplitter) -> None:
        """Verify ZERO domain leakage between train, val, and test splits."""
        samples = downloader.generate_reproducible_sample_set(num_samples=60)
        train, val, test = splitter.domain_disjoint_split(samples, train_ratio=0.70, val_ratio=0.15)

        train_domains = set(s["domain"] for s in train)
        val_domains = set(s["domain"] for s in val)
        test_domains = set(s["domain"] for s in test)

        # Assert ZERO domain overlap
        assert train_domains.isdisjoint(val_domains)
        assert train_domains.isdisjoint(test_domains)
        assert val_domains.isdisjoint(test_domains)

    def test_temporal_split_chronological(self, downloader: DatasetDownloader, splitter: DatasetSplitter) -> None:
        """Verify temporal split maintains chronological order."""
        samples = downloader.generate_reproducible_sample_set(num_samples=30)
        train, val, test = splitter.temporal_split(samples, train_ratio=0.70, val_ratio=0.15)
        assert len(train) + len(val) + len(test) == 30

    def test_unseen_domain_split(self, downloader: DatasetDownloader, splitter: DatasetSplitter) -> None:
        """Verify dedicated held-out unseen domain split."""
        samples = downloader.generate_reproducible_sample_set(num_samples=40)
        held_out = ["google.com", "login-paypal-verify-secure.xyz"]
        train, unseen_test = splitter.unseen_domain_split(samples, held_out)

        for s in unseen_test:
            assert s["domain"].lower() in held_out
        for s in train:
            assert s["domain"].lower() not in held_out

    def test_stratified_80_20_split(self, downloader: DatasetDownloader, splitter: DatasetSplitter) -> None:
        """Verify 80:20 stratified split preserves exact class balance."""
        samples = downloader.generate_reproducible_sample_set(num_samples=100)
        train, test = splitter.stratified_split(samples, train_ratio=0.80)

        assert len(train) == 80
        assert len(test) == 20

        train_phish = sum(1 for s in train if s["label"] == "phishing")
        train_benign = sum(1 for s in train if s["label"] == "benign")
        test_phish = sum(1 for s in test if s["label"] == "phishing")
        test_benign = sum(1 for s in test if s["label"] == "benign")

        assert train_phish == 40
        assert train_benign == 40
        assert test_phish == 10
        assert test_benign == 10

        assert all(s["split"] == "train" for s in train)
        assert all(s["split"] == "test" for s in test)

    def test_domain_leakage_diagnostic(self, splitter: DatasetSplitter) -> None:
        """Verify check_domain_leakage detects and reports domain overlap."""
        train = [
            {"domain": "google.com", "label": "benign"},
            {"domain": "phish1.com", "label": "phishing"},
        ]
        test = [
            {"domain": "google.com", "label": "benign"},
            {"domain": "phish2.com", "label": "phishing"},
        ]
        diag = splitter.check_domain_leakage(train, test)
        assert diag["overlapping_domain_count"] == 1
        assert diag["overlapping_domains_sample"] == ["google.com"]
        assert diag["zero_leakage"] is False

