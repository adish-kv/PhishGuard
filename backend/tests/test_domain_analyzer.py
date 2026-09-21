"""Unit tests for the Domain Analyzer module.

Tests extraction of all 6 domain age and WHOIS features on real domains, invalid domains, and mock objects.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from backend.app.analyzers.domain_analyzer import (
    DOMAIN_FEATURE_NAMES,
    NUM_DOMAIN_FEATURES,
    DomainAnalyzer,
    DomainFeatures,
)


@pytest.fixture
def analyzer() -> DomainAnalyzer:
    """Fixture providing DomainAnalyzer instance."""
    return DomainAnalyzer()


class TestDomainAnalyzer:
    """Test suite for domain age feature extraction."""

    def test_feature_count_and_names(self, analyzer: DomainAnalyzer) -> None:
        """Verify domain feature vector length is exactly 6."""
        result = analyzer.extract_features("google.com")
        assert len(result.features) == NUM_DOMAIN_FEATURES
        assert set(result.features.keys()) == set(DOMAIN_FEATURE_NAMES)

    def test_live_domain_whois(self, analyzer: DomainAnalyzer) -> None:
        """Verify live WHOIS lookup on well-known old domain (google.com)."""
        result = analyzer.extract_features("https://www.google.com")
        assert result.whois_available is True
        assert result.features["whois_available"] is True
        assert result.features["domain_age_days"] > 365 * 10  # Google > 10 years old
        assert result.features["registrar_known"] is True

    def test_invalid_domain_missing_representation(self, analyzer: DomainAnalyzer) -> None:
        """Verify invalid domain sets WHOIS unavailable and age to -1 (never invents values)."""
        result = analyzer.extract_features("invalid-domain-987654321-xyz.unknown")
        assert result.features["whois_available"] is False
        assert result.features["domain_age_days"] == -1
        assert result.features["registration_period_days"] == -1
        assert result.features["days_to_expiration"] == -1

    def test_mock_whois_processing(self, analyzer: DomainAnalyzer) -> None:
        """Verify date calculations with mock WHOIS response."""
        mock_whois = MagicMock()
        mock_whois.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        mock_whois.expiration_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        mock_whois.registrar = "MarkMonitor Inc."

        res = DomainFeatures()
        analyzer._process_whois_data(mock_whois, res)

        assert res.features["domain_age_days"] > 365
        assert res.features["registration_period_days"] == 3653
        assert res.features["registrar_known"] is True
        assert res.registrar == "MarkMonitor Inc."
