"""Security tests for PhishGuard SSRF protection.

These tests verify that the system correctly blocks:
- Private IP addresses
- Localhost URLs
- Cloud metadata endpoints
- Dangerous ports
- Malformed URLs
- Credential-embedded URLs

This is a cybersecurity project — these tests are mandatory.
"""

import pytest

from backend.app.core.config import reset_settings
from backend.app.core.security import SSRFProtector, sanitize_url


@pytest.fixture(autouse=True)
def _reset() -> None:
    """Reset settings before each test."""
    reset_settings()


@pytest.fixture
def protector() -> SSRFProtector:
    """Create a fresh SSRFProtector instance."""
    return SSRFProtector()


class TestSSRFProtection:
    """Test SSRF protection against various attack vectors."""

    # === ALLOWED URLs ===

    def test_valid_https_url(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("https://www.google.com")
        assert result.is_valid, f"Should allow valid HTTPS URL. Errors: {result.errors}"

    def test_valid_http_url(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://example.com")
        assert result.is_valid, f"Should allow valid HTTP URL. Errors: {result.errors}"

    def test_valid_url_with_path(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("https://example.com/login/page")
        assert result.is_valid

    def test_valid_url_with_query(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("https://example.com/search?q=test&page=1")
        assert result.is_valid

    # === BLOCKED: Private IPs ===

    def test_block_localhost_ip(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://127.0.0.1")
        assert not result.is_valid, "Must block localhost IP"

    def test_block_localhost_hostname(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://localhost")
        assert not result.is_valid, "Must block localhost hostname"

    def test_block_private_10(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://10.0.0.1")
        assert not result.is_valid, "Must block 10.x.x.x"

    def test_block_private_172(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://172.16.0.1")
        assert not result.is_valid, "Must block 172.16.x.x"

    def test_block_private_192(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://192.168.1.1")
        assert not result.is_valid, "Must block 192.168.x.x"

    def test_block_zero_ip(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://0.0.0.0")
        assert not result.is_valid, "Must block 0.0.0.0"

    # === BLOCKED: Cloud Metadata ===

    def test_block_aws_metadata(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://169.254.169.254/latest/meta-data/")
        assert not result.is_valid, "Must block AWS metadata endpoint"

    def test_block_gcp_metadata(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://metadata.google.internal/")
        assert not result.is_valid, "Must block GCP metadata endpoint"

    # === BLOCKED: Dangerous Schemes ===

    def test_block_file_scheme(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("file:///etc/passwd")
        assert not result.is_valid, "Must block file:// scheme"

    def test_block_ftp_scheme(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("ftp://evil.com/malware")
        assert not result.is_valid, "Must block ftp:// scheme"

    def test_block_javascript_scheme(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("javascript:alert(1)")
        assert not result.is_valid, "Must block javascript: scheme"

    def test_block_data_scheme(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("data:text/html,<h1>evil</h1>")
        assert not result.is_valid, "Must block data: scheme"

    # === BLOCKED: Dangerous Ports ===

    def test_block_ssh_port(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://example.com:22/")
        assert not result.is_valid, "Must block SSH port"

    def test_block_mysql_port(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://example.com:3306/")
        assert not result.is_valid, "Must block MySQL port"

    def test_block_redis_port(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://example.com:6379/")
        assert not result.is_valid, "Must block Redis port"

    def test_block_postgres_port(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://example.com:5432/")
        assert not result.is_valid, "Must block PostgreSQL port"

    # === BLOCKED: Embedded Credentials ===

    def test_block_credentials_in_url(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://admin:password@evil.com")
        assert not result.is_valid, "Must block credentials in URL"

    # === BLOCKED: Malformed URLs ===

    def test_block_empty_url(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("")
        assert not result.is_valid, "Must block empty URL"

    def test_block_no_hostname(self, protector: SSRFProtector) -> None:
        result = protector.validate_url("http://")
        assert not result.is_valid, "Must block URL with no hostname"

    # === REDIRECT VALIDATION ===

    def test_redirect_to_private_blocked(self, protector: SSRFProtector) -> None:
        result = protector.validate_redirect(
            "https://evil.com", "http://192.168.1.1", redirect_count=0
        )
        assert not result.is_valid, "Must block redirect to private IP"

    def test_redirect_count_exceeded(self, protector: SSRFProtector) -> None:
        result = protector.validate_redirect(
            "https://evil.com", "https://also-evil.com", redirect_count=5
        )
        assert not result.is_valid, "Must block excessive redirects"

    def test_redirect_to_valid_url(self, protector: SSRFProtector) -> None:
        result = protector.validate_redirect(
            "https://example.com", "https://www.example.com", redirect_count=0
        )
        assert result.is_valid, f"Should allow valid redirect. Errors: {result.errors}"


class TestURLSanitization:
    """Test URL sanitization function."""

    def test_add_scheme(self) -> None:
        assert sanitize_url("example.com") == "https://example.com"

    def test_strip_whitespace(self) -> None:
        assert sanitize_url("  https://example.com  ") == "https://example.com"

    def test_remove_null_bytes(self) -> None:
        result = sanitize_url("https://example.com/\x00evil")
        assert "\x00" not in result

    def test_remove_control_chars(self) -> None:
        result = sanitize_url("https://example.com/\x0d\x0aevil")
        assert "\x0d" not in result
        assert "\x0a" not in result

    def test_preserve_valid_url(self) -> None:
        url = "https://www.example.com/path?q=test"
        assert sanitize_url(url) == url

    def test_preserve_http(self) -> None:
        url = "http://example.com"
        assert sanitize_url(url) == url
