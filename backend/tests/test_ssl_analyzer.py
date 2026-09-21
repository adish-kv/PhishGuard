"""Unit tests for the SSL Analyzer module.

Tests extraction of all 10 SSL features using real domain connections and mock cert dictionaries.
"""

import pytest
from backend.app.analyzers.ssl_analyzer import (
    NUM_SSL_FEATURES,
    SSL_FEATURE_NAMES,
    SSLAnalyzer,
    SSLFeatures,
)


@pytest.fixture
def analyzer() -> SSLAnalyzer:
    """Fixture providing SSLAnalyzer instance."""
    return SSLAnalyzer()


class TestSSLAnalyzer:
    """Test suite for SSL certificate feature extraction."""

    def test_feature_count_and_names(self, analyzer: SSLAnalyzer) -> None:
        """Verify SSL feature vector length is exactly 10."""
        result = analyzer.extract_features("google.com")
        assert len(result.features) == NUM_SSL_FEATURES
        assert set(result.features.keys()) == set(SSL_FEATURE_NAMES)

    def test_valid_https_domain(self, analyzer: SSLAnalyzer) -> None:
        """Verify SSL feature extraction on live valid HTTPS site."""
        result = analyzer.extract_features("https://www.google.com")
        assert result.cert_available is True
        assert result.features["https_available"] is True
        assert result.features["cert_valid"] is True
        assert result.features["has_cert_error"] is False
        assert result.features["cert_days_to_expiry"] > 0
        assert result.features["hostname_match"] is True

    def test_invalid_domain_graceful_failure(self, analyzer: SSLAnalyzer) -> None:
        """Verify invalid/non-existent domain fails gracefully with default features."""
        result = analyzer.extract_features("https://invalid-nonexistent-domain-12345.xyz")
        assert result.features["https_available"] is False
        assert result.features["cert_valid"] is False
        assert result.features["has_cert_error"] is True
        assert len(result.errors) > 0

    def test_mock_cert_processing(self, analyzer: SSLAnalyzer) -> None:
        """Verify mock cert dictionary parsing and feature calculations."""
        mock_cert = {
            "notBefore": "Jan 01 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        res = SSLFeatures()
        analyzer._process_cert(mock_cert, "example.com", "TLSv1.3", res)

        assert res.features["cert_days_to_expiry"] > 0
        assert res.features["cert_age_days"] >= 0
        assert res.features["hostname_match"] is True
        assert res.features["self_signed"] is False
        assert res.features["tls_version_numeric"] == 1.3
        assert res.issuer_org == "Let's Encrypt"
        assert res.subject_cn == "example.com"

    def test_wildcard_hostname_matching(self) -> None:
        """Verify wildcard SAN matching helper method."""
        assert SSLAnalyzer._check_hostname_match("sub.example.com", ["*.example.com"]) is True
        assert SSLAnalyzer._check_hostname_match("other.com", ["*.example.com"]) is False
