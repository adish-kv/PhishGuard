"""SSL/TLS Certificate feature extraction for phishing detection.

Analyzes TLS/SSL certificates and connection properties over socket.
Extracts 10 SSL features while properly treating SSL status as a signal
rather than a definitive classification rule (since >80% of phishing sites
now use free HTTPS certificates like Let's Encrypt).

Security & Performance Constraints:
    - Enforces non-blocking socket connection timeout (default 5s).
    - Catches SSLError, CertificateError, timeout, connection refusal gracefully.
    - Does NOT execute untrusted payloads. Socket handshake only.

Feature Groups (10 features total):
    1. https_available (bool): Whether HTTPS connection succeeded
    2. cert_valid (bool): Whether certificate is fully valid and trusted
    3. cert_days_to_expiry (int): Days until expiration
    4. cert_age_days (int): Days since certificate was issued (-1 if unavailable)
    5. hostname_match (bool): Whether SAN/CN matches target hostname
    6. cert_chain_length (int): Depth of certificate chain
    7. is_ev_cert (bool): Extended Validation (EV) cert indicator
    8. has_cert_error (bool): Certificate validation error occurred
    9. self_signed (bool): Issuer equals Subject (self-signed cert)
    10. tls_version_numeric (float): TLS protocol version (1.2, 1.3, or 0.0)
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SSLFeatures:
    """Container for extracted SSL features."""

    features: dict[str, float | int | bool] = field(default_factory=dict)
    cert_available: bool = False
    issuer_org: str = ""
    subject_cn: str = ""
    error_type: str = ""
    extraction_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Convert features to canonical numerical vector."""
        return [
            float(self.features.get(name, 0.0))
            for name in SSL_FEATURE_NAMES
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cert_available": self.cert_available,
            "issuer_org": self.issuer_org,
            "subject_cn": self.subject_cn,
            "error_type": self.error_type,
            "features": self.features,
            "feature_vector": self.to_vector(),
            "feature_names": SSL_FEATURE_NAMES,
            "extraction_time_ms": self.extraction_time_ms,
            "errors": self.errors,
        }


# Canonical order of 10 SSL features
SSL_FEATURE_NAMES: list[str] = [
    "https_available",
    "cert_valid",
    "cert_days_to_expiry",
    "cert_age_days",
    "hostname_match",
    "cert_chain_length",
    "is_ev_cert",
    "has_cert_error",
    "self_signed",
    "tls_version_numeric",
]

NUM_SSL_FEATURES = len(SSL_FEATURE_NAMES)  # 10


class SSLAnalyzer:
    """TLS/SSL certificate feature extractor.

    Usage:
        analyzer = SSLAnalyzer()
        result = analyzer.extract_features("https://example.com")
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._timeout = getattr(settings.ssl_analyzer, "timeout_seconds", 5)

    def extract_features(self, url_or_hostname: str) -> SSLFeatures:
        """Extract 10 SSL features from target URL or hostname.

        Args:
            url_or_hostname: Target URL or domain hostname.

        Returns:
            SSLFeatures container.
        """
        start_time = time.perf_counter()
        result = SSLFeatures()

        hostname, port = self._parse_target(url_or_hostname)
        if not hostname:
            result.errors.append("Invalid or empty hostname")
            self._fill_defaults(result.features)
            result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return result

        # Step 1: Try trusted SSL context connection
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_ver = ssock.version()
                    result.cert_available = True
                    result.features["https_available"] = True
                    result.features["cert_valid"] = True
                    result.features["has_cert_error"] = False

                    self._process_cert(cert, hostname, tls_ver, result)

        except (ssl.SSLCertVerificationError, ssl.SSLError) as cert_err:
            result.features["https_available"] = True
            result.features["cert_valid"] = False
            result.features["has_cert_error"] = True
            result.error_type = type(cert_err).__name__
            result.errors.append(f"SSL verification error: {str(cert_err)}")

            # Attempt unverified retrieval to extract properties despite verification failure
            self._try_unverified_cert(hostname, port, result)

        except (socket.timeout, TimeoutError):
            result.error_type = "TimeoutError"
            result.errors.append(f"Connection timeout after {self._timeout}s")
            self._fill_defaults(result.features)

        except Exception as e:
            result.error_type = type(e).__name__
            result.errors.append(f"SSL connection failed: {str(e)}")
            self._fill_defaults(result.features)

        result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # Assert exactly 10 features present
        assert len(result.features) == NUM_SSL_FEATURES, (
            f"Expected {NUM_SSL_FEATURES} SSL features, got {len(result.features)}. "
            f"Missing: {set(SSL_FEATURE_NAMES) - set(result.features.keys())}"
        )

        return result

    def _process_cert(self, cert: dict[str, Any], hostname: str, tls_version: str | None, result: SSLFeatures) -> None:
        """Process peer certificate dictionary into features."""
        now = datetime.now(timezone.utc)

        # Dates & Expiry
        not_before_str = cert.get("notBefore")
        not_after_str = cert.get("notAfter")

        days_to_expiry = 0
        if not_after_str:
            try:
                dt_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_to_expiry = max(0, (dt_after - now).days)
            except Exception:
                pass
        result.features["cert_days_to_expiry"] = days_to_expiry

        cert_age = -1
        if not_before_str:
            try:
                dt_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                cert_age = max(0, (now - dt_before).days)
            except Exception:
                pass
        result.features["cert_age_days"] = cert_age

        # Subject & Issuer
        subject_dict = dict(x[0] for x in cert.get("subject", ()) if x)
        issuer_dict = dict(x[0] for x in cert.get("issuer", ()) if x)

        subject_cn = subject_dict.get("commonName", "")
        issuer_org = issuer_dict.get("organizationName", "")

        result.subject_cn = subject_cn
        result.issuer_org = issuer_org

        # Self-signed test
        result.features["self_signed"] = bool(subject_dict and issuer_dict and subject_dict == issuer_dict)

        # Hostname Matching (SAN + CN)
        sans = [item[1] for item in cert.get("subjectAltName", ()) if item[0].lower() == "dns"]
        if not sans and subject_cn:
            sans = [subject_cn]

        result.features["hostname_match"] = self._check_hostname_match(hostname, sans)

        # Chain Length approximation
        result.features["cert_chain_length"] = len(cert.get("subjectAltName", ())) + 1 if cert else 0

        # EV Cert Indicator
        result.features["is_ev_cert"] = "businessCategory" in subject_dict or "serialNumber" in subject_dict

        # TLS Version
        result.features["tls_version_numeric"] = self._parse_tls_version(tls_version)

    def _try_unverified_cert(self, hostname: str, port: int, result: SSLFeatures) -> None:
        """Fetch unverified certificate to extract attributes when verification fails."""
        ctx = ssl._create_unverified_context()
        try:
            with socket.create_connection((hostname, port), timeout=self._timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_ver = ssock.version()
                    if cert:
                        result.cert_available = True
                        self._process_cert(cert, hostname, tls_ver, result)
                    else:
                        self._fill_defaults(result.features, https=True, error=True)
        except Exception:
            self._fill_defaults(result.features, https=True, error=True)

    @staticmethod
    def _check_hostname_match(hostname: str, san_list: list[str]) -> bool:
        """Verify if target hostname matches SAN or wildcard pattern."""
        hostname_lower = hostname.lower()
        for san in san_list:
            san_lower = san.lower()
            if san_lower == hostname_lower:
                return True
            if san_lower.startswith("*."):
                domain_part = san_lower[2:]
                if hostname_lower.endswith(domain_part) and hostname_lower.count(".") == san_lower.count("."):
                    return True
        return False

    @staticmethod
    def _parse_tls_version(tls_ver: str | None) -> float:
        """Convert TLS string (e.g. TLSv1.3) to float representation."""
        if not tls_ver:
            return 0.0
        if "1.3" in tls_ver:
            return 1.3
        if "1.2" in tls_ver:
            return 1.2
        if "1.1" in tls_ver:
            return 1.1
        if "1.0" in tls_ver:
            return 1.0
        return 1.0

    @staticmethod
    def _parse_target(url_or_hostname: str) -> tuple[str, int]:
        """Extract hostname and port from URL or raw hostname."""
        if not url_or_hostname:
            return "", 443

        target = url_or_hostname.strip()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or ""
            port = parsed.port or 443
            return hostname, port
        except Exception:
            return "", 443

    @staticmethod
    def _fill_defaults(features_dict: dict[str, float | int | bool], https: bool = False, error: bool = False) -> None:
        """Fill defaults for failed/unavailable SSL connections."""
        defaults: dict[str, float | int | bool] = {
            "https_available": https,
            "cert_valid": False,
            "cert_days_to_expiry": 0,
            "cert_age_days": -1,
            "hostname_match": False,
            "cert_chain_length": 0,
            "is_ev_cert": False,
            "has_cert_error": error or not https,
            "self_signed": False,
            "tls_version_numeric": 0.0,
        }
        for name in SSL_FEATURE_NAMES:
            if name not in features_dict:
                features_dict[name] = defaults[name]
