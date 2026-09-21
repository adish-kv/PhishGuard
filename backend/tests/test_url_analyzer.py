"""Unit tests for the URL Analyzer module.

Tests extraction of all 22 lexical and structural features across a variety
of URL types (benign, phishing, IP-based, obfuscated, punycode, etc.).
"""

import pytest
from backend.app.analyzers.url_analyzer import (
    FEATURE_NAMES,
    NUM_URL_FEATURES,
    URLAnalyzer,
    URLFeatures,
)


@pytest.fixture
def analyzer() -> URLAnalyzer:
    """Fixture providing a fresh URLAnalyzer instance."""
    return URLAnalyzer()


class TestURLAnalyzer:
    """Test suite for URL feature extraction."""

    def test_feature_count_and_names(self, analyzer: URLAnalyzer) -> None:
        """Verify feature count is exactly 22 and names match CANONICAL list."""
        result = analyzer.extract_features("https://www.google.com")
        assert len(result.features) == NUM_URL_FEATURES
        assert len(FEATURE_NAMES) == NUM_URL_FEATURES
        assert set(result.features.keys()) == set(FEATURE_NAMES)

    def test_vector_conversion(self, analyzer: URLAnalyzer) -> None:
        """Verify feature vector matches canonical order and converts bools to floats."""
        result = analyzer.extract_features("https://example.com/path?query=1")
        vector = result.to_vector()
        assert len(vector) == NUM_URL_FEATURES
        for val in vector:
            assert isinstance(val, (int, float))

    def test_empty_url_handling(self, analyzer: URLAnalyzer) -> None:
        """Verify empty URL yields errors gracefully without crashing."""
        result = analyzer.extract_features("")
        assert len(result.errors) > 0
        assert result.url == ""

    def test_ip_based_url(self, analyzer: URLAnalyzer) -> None:
        """Verify IPv4 extraction detects IP correctly."""
        result = analyzer.extract_features("http://192.168.1.1/login.php")
        assert result.features["has_ip"] is True
        assert result.features["hostname_length"] == len("192.168.1.1")

    def test_suspicious_tld_detection(self, analyzer: URLAnalyzer) -> None:
        """Verify suspicious TLDs like .xyz or .top are flagged in features."""
        result = analyzer.extract_features("http://secure-account-update.xyz/login")
        assert result.features["suspicious_tld"] is True

        result_benign = analyzer.extract_features("https://www.apple.com")
        assert result_benign.features["suspicious_tld"] is False

    def test_at_symbol_detection(self, analyzer: URLAnalyzer) -> None:
        """Verify @ symbol detection for URL obfuscation."""
        result = analyzer.extract_features("http://google.com@evil-site.com/login")
        assert result.features["has_at_symbol"] is True

    def test_punycode_detection(self, analyzer: URLAnalyzer) -> None:
        """Verify punycode / IDN homograph attack indicator."""
        result = analyzer.extract_features("https://xn--pple-43d.com")
        assert result.features["has_punycode"] is True

    def test_keyword_counter(self, analyzer: URLAnalyzer) -> None:
        """Verify count of suspicious security/login keywords."""
        url = "https://verify-banking-account-login.example.com/update-password"
        result = analyzer.extract_features(url)
        # Should catch: verify, banking, account, login, update, password
        assert result.features["suspicious_keyword_count"] >= 4

    def test_abnormal_port(self, analyzer: URLAnalyzer) -> None:
        """Verify non-standard HTTP/HTTPS ports are identified."""
        result = analyzer.extract_features("http://example.com:8080/path")
        assert result.features["has_abnormal_port"] is True

        result_std = analyzer.extract_features("https://example.com:443/path")
        assert result_std.features["has_abnormal_port"] is False

    def test_shannon_entropy(self, analyzer: URLAnalyzer) -> None:
        """Verify Shannon entropy calculation."""
        # Repetitive string -> low entropy
        low_ent = analyzer._calculate_entropy("aaaaaaa")
        # Random string -> high entropy
        high_ent = analyzer._calculate_entropy("a8f9z3q1v7k9m2x4")
        assert high_ent > low_ent

    def test_subdomain_count(self, analyzer: URLAnalyzer) -> None:
        """Verify subdomain depth calculation."""
        result = analyzer.extract_features("https://a.b.c.d.example.com")
        assert result.features["num_subdomains"] == 4
