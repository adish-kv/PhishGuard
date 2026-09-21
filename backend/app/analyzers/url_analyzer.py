"""URL feature extraction for phishing detection.

Extracts 22 lexical and structural features from a URL string.
This module requires NO network calls — all features are derived
purely from the URL string itself, making it extremely fast (<1ms).

This is the foundation of Stage 1 in the adaptive pipeline.
The URL analyzer runs on every single URL before any other analysis.

Feature Groups:
    1. Length-based (4 features): url_length, hostname_length, path_length, query_length
    2. Count-based (5 features): num_dots, num_hyphens, num_subdomains, num_special_chars, num_digits
    3. Ratio-based (3 features): digit_ratio, char_entropy, domain_to_path_ratio
    4. Boolean-based (6 features): has_ip, has_at_symbol, has_punycode, uses_https,
                                    has_url_encoding, has_abnormal_port
    5. Keyword-based (2 features): suspicious_keyword_count, suspicious_tld
    6. Statistical (2 features): hostname_token_count, path_token_count

Design Principles:
    - No manually selected rules for classification (features only, model decides)
    - No network calls (pure string analysis)
    - Deterministic output for same input (reproducible)
    - Returns a structured dict that can be serialized to JSON
"""

from __future__ import annotations

import ipaddress
import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import tldextract

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)


# Precompiled regex patterns for performance
_IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_PUNYCODE_PATTERN = re.compile(r"xn--", re.IGNORECASE)
_URL_ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
_SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{}|;':\",./<>?~`")

# Standard HTTP/HTTPS ports
_STANDARD_PORTS = {80, 443, None}


@dataclass
class URLFeatures:
    """Container for extracted URL features.

    All 22 features needed for the ML model, plus metadata.

    Attributes:
        features: Dictionary mapping feature names to values.
        url: The original URL that was analyzed.
        extraction_time_ms: Time taken to extract features (for latency tracking).
        errors: Any errors encountered during extraction.
    """

    features: dict[str, float | int | bool] = field(default_factory=dict)
    url: str = ""
    extraction_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Convert features to a fixed-order numerical vector.

        Returns:
            List of float values in a consistent order, suitable
            for ML model input. Booleans are converted to 0.0/1.0.
        """
        return [
            float(self.features.get(name, 0.0))
            for name in FEATURE_NAMES
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dictionary.

        Returns:
            Dictionary with features, metadata, and vector.
        """
        return {
            "url": self.url,
            "features": self.features,
            "feature_vector": self.to_vector(),
            "feature_names": FEATURE_NAMES,
            "extraction_time_ms": self.extraction_time_ms,
            "errors": self.errors,
        }


# Canonical feature order — MUST remain consistent across training and inference.
# Changing this order after training invalidates all existing models.
FEATURE_NAMES: list[str] = [
    # Length-based (4)
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    # Count-based (5)
    "num_dots",
    "num_hyphens",
    "num_subdomains",
    "num_special_chars",
    "num_digits",
    # Ratio-based (3)
    "digit_ratio",
    "char_entropy",
    "domain_to_path_ratio",
    # Boolean-based (6)
    "has_ip",
    "has_at_symbol",
    "has_punycode",
    "uses_https",
    "has_url_encoding",
    "has_abnormal_port",
    # Keyword-based (2)
    "suspicious_keyword_count",
    "suspicious_tld",
    # Statistical (2)
    "hostname_token_count",
    "path_token_count",
]

NUM_URL_FEATURES = len(FEATURE_NAMES)  # Should be 22


class URLAnalyzer:
    """Extracts lexical and structural features from URLs.

    This analyzer operates entirely on the URL string — no DNS lookups,
    no HTTP requests, no external API calls. This makes it:
    - Fast: <1ms per URL
    - Safe: No network exposure
    - Deterministic: Same URL → same features

    Usage:
        analyzer = URLAnalyzer()
        result = analyzer.extract_features("https://suspicious-login.example.com/verify?id=123")
        print(result.features)
        print(result.to_vector())  # For ML model input
    """

    def __init__(self) -> None:
        """Initialize with suspicious keywords and TLDs from config."""
        settings = get_settings()

        # Load from config — these are NOT classification rules,
        # they are used to count occurrences as features.
        self._suspicious_keywords: list[str] = getattr(
            settings, "_url_suspicious_keywords", None
        ) or [
            "login", "signin", "verify", "account", "secure",
            "update", "confirm", "banking", "password", "credential",
            "suspended", "unusual", "restrict", "alert",
        ]

        self._suspicious_tlds: list[str] = getattr(
            settings, "_url_suspicious_tlds", None
        ) or [
            ".xyz", ".top", ".click", ".loan", ".work",
            ".gq", ".ml", ".cf", ".tk", ".ga",
            ".buzz", ".zip", ".mov",
        ]

        # Try loading from YAML config sections
        try:
            yaml_keywords = settings.__dict__.get("url_analyzer", {})
            if isinstance(yaml_keywords, dict):
                if "suspicious_keywords" in yaml_keywords:
                    self._suspicious_keywords = yaml_keywords["suspicious_keywords"]
                if "suspicious_tlds" in yaml_keywords:
                    self._suspicious_tlds = yaml_keywords["suspicious_tlds"]
        except (AttributeError, TypeError):
            pass

    def extract_features(self, url: str) -> URLFeatures:
        """Extract all 22 features from a URL.

        Args:
            url: The URL string to analyze. Can be with or without scheme.

        Returns:
            URLFeatures containing the 22-dimensional feature vector,
            metadata, and any errors encountered.

        Example:
            >>> analyzer = URLAnalyzer()
            >>> result = analyzer.extract_features("https://evil-login.example.xyz/verify?user=1")
            >>> result.features["url_length"]
            47
            >>> result.features["suspicious_keyword_count"]
            2  # "login" and "verify"
        """
        start_time = time.perf_counter()
        result = URLFeatures(url=url)

        try:
            # Normalize: add scheme if missing
            normalized_url = url.strip()
            if not normalized_url:
                result.errors.append("Empty URL")
                result.extraction_time_ms = (time.perf_counter() - start_time) * 1000
                return result

            if not normalized_url.startswith(("http://", "https://", "ftp://")):
                normalized_url = "https://" + normalized_url

            # Parse URL components
            parsed = urlparse(normalized_url)
            extracted = tldextract.extract(normalized_url)

            hostname = parsed.hostname or ""
            path = parsed.path or ""
            query = parsed.query or ""
            full_url = normalized_url

            # ═══════════════════════════════════════════
            # GROUP 1: Length-based features (4)
            # ═══════════════════════════════════════════
            # Phishing URLs tend to be longer because attackers
            # embed brand names, paths, and parameters to look legitimate.
            result.features["url_length"] = len(full_url)
            result.features["hostname_length"] = len(hostname)
            result.features["path_length"] = len(path)
            result.features["query_length"] = len(query)

            # ═══════════════════════════════════════════
            # GROUP 2: Count-based features (5)
            # ═══════════════════════════════════════════
            # Dots: phishing domains often use many subdomains
            # e.g., "secure.login.bank.evil.com"
            result.features["num_dots"] = full_url.count(".")

            # Hyphens: commonly used in phishing to mimic brands
            # e.g., "paypal-secure-login.com"
            result.features["num_hyphens"] = full_url.count("-")

            # Subdomains: legitimate sites rarely have >2 subdomains
            subdomain = extracted.subdomain
            if subdomain:
                result.features["num_subdomains"] = subdomain.count(".") + 1
            else:
                result.features["num_subdomains"] = 0

            # Special characters: high counts suggest obfuscation
            result.features["num_special_chars"] = sum(
                1 for c in full_url if c in _SPECIAL_CHARS
            )

            # Digits in URL: phishing URLs often contain random numbers
            result.features["num_digits"] = sum(1 for c in full_url if c.isdigit())

            # ═══════════════════════════════════════════
            # GROUP 3: Ratio-based features (3)
            # ═══════════════════════════════════════════
            # Digit ratio: proportion of digits in the URL
            url_len = max(len(full_url), 1)  # avoid division by zero
            result.features["digit_ratio"] = round(
                result.features["num_digits"] / url_len, 4
            )

            # Shannon entropy: measures randomness of the URL string.
            # Higher entropy = more random = possibly auto-generated domain.
            result.features["char_entropy"] = round(
                self._calculate_entropy(full_url), 4
            )

            # Domain-to-path ratio: legitimate sites usually have
            # short domains and longer paths. Phishing may be reversed.
            path_len = max(len(path), 1)
            result.features["domain_to_path_ratio"] = round(
                len(hostname) / path_len, 4
            )

            # ═══════════════════════════════════════════
            # GROUP 4: Boolean-based features (6)
            # ═══════════════════════════════════════════
            # IP address instead of domain: strong phishing signal
            # Legitimate sites almost never use raw IPs.
            result.features["has_ip"] = self._is_ip_address(hostname)

            # @ symbol: used for URL obfuscation
            # e.g., "http://legitimate.com@evil.com" — browser goes to evil.com
            result.features["has_at_symbol"] = "@" in full_url

            # Punycode/IDN: internationalized domains can impersonate
            # brands using look-alike characters (homograph attacks)
            # e.g., "xn--pple-43d.com" looks like "apple.com"
            result.features["has_punycode"] = bool(
                _PUNYCODE_PATTERN.search(hostname)
            )

            # HTTPS: note that HTTPS does NOT mean safe!
            # This is a feature, not a classification rule.
            result.features["uses_https"] = parsed.scheme == "https"

            # URL encoding: excessive %XX encoding may indicate obfuscation
            result.features["has_url_encoding"] = bool(
                _URL_ENCODING_PATTERN.search(full_url)
            )

            # Abnormal port: non-standard ports are suspicious
            result.features["has_abnormal_port"] = parsed.port not in _STANDARD_PORTS

            # ═══════════════════════════════════════════
            # GROUP 5: Keyword-based features (2)
            # ═══════════════════════════════════════════
            # Count of suspicious keywords found in URL
            # These are features for the model, NOT classification rules.
            url_lower = full_url.lower()
            result.features["suspicious_keyword_count"] = sum(
                1 for kw in self._suspicious_keywords if kw in url_lower
            )

            # Suspicious TLD: certain TLDs are disproportionately
            # used for phishing (cheap/free registration).
            # Again, this is a feature — not a rule.
            suffix = f".{extracted.suffix}" if extracted.suffix else ""
            result.features["suspicious_tld"] = suffix.lower() in self._suspicious_tlds

            # ═══════════════════════════════════════════
            # GROUP 6: Statistical features (2)
            # ═══════════════════════════════════════════
            # Hostname tokens: split by dots and hyphens
            # More tokens = more complex hostname
            hostname_tokens = re.split(r"[.\-]", hostname)
            result.features["hostname_token_count"] = len(
                [t for t in hostname_tokens if t]
            )

            # Path tokens: split by slashes
            # Deep paths may indicate phishing page structure
            path_tokens = path.strip("/").split("/")
            result.features["path_token_count"] = len(
                [t for t in path_tokens if t]
            )

        except Exception as e:
            result.errors.append(f"Feature extraction error: {str(e)}")
            logger.error(
                "URL feature extraction failed",
                extra={"extra_data": {"error": str(e)}},
                exc_info=True,
            )
            # Fill missing features with defaults
            for name in FEATURE_NAMES:
                if name not in result.features:
                    result.features[name] = 0

        result.extraction_time_ms = round(
            (time.perf_counter() - start_time) * 1000, 3
        )

        # Validate we have exactly 22 features
        assert len(result.features) == NUM_URL_FEATURES, (
            f"Expected {NUM_URL_FEATURES} features, got {len(result.features)}. "
            f"Missing: {set(FEATURE_NAMES) - set(result.features.keys())}"
        )

        return result

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string.

        Shannon entropy measures the randomness/unpredictability of a string.
        - Low entropy (< 3.0): repetitive text like "aaaaaaa"
        - Medium entropy (3.0-4.0): normal English text / domain names
        - High entropy (> 4.0): random strings, hashes, auto-generated domains

        Phishing domains often have higher entropy because attackers
        use random strings or combine many words to avoid detection.

        Args:
            text: The input string.

        Returns:
            Shannon entropy in bits. 0.0 for empty strings.
        """
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Check if hostname is an IP address.

        Legitimate websites almost never use raw IP addresses.
        A URL like http://192.168.1.1/login is highly suspicious.

        Args:
            hostname: The hostname to check.

        Returns:
            True if the hostname is a valid IPv4 or IPv6 address.
        """
        if not hostname:
            return False
        # Quick regex check for IPv4
        if _IP_PATTERN.match(hostname):
            return True
        # Try parsing as IP (catches IPv6 too)
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False
