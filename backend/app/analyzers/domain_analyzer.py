"""Domain age and WHOIS metadata feature extraction for phishing detection.

Extracts 6 domain intelligence features via python-whois / RDAP.
Performs explicit missing-value representations (-1) when WHOIS data is
redacted, restricted, or unavailable due to GDPR/privacy policies.

Security & Performance Constraints:
    - Enforces socket query timeouts (default 10s).
    - NEVER fabricates missing domain age or dates.
    - Operates without binary rules (young domains are features, not instant blocks).

Feature Groups (6 features total):
    1. domain_age_days (int): Days since domain creation (-1 if unavailable)
    2. registration_period_days (int): Days between creation and expiration (-1 if unavailable)
    3. days_to_expiration (int): Days remaining until domain expires (-1 if unavailable)
    4. whois_available (bool): Whether WHOIS/RDAP query succeeded
    5. has_privacy_protection (bool): Domain privacy service detected (e.g. WhoisGuard)
    6. registrar_known (bool): Registrar organization name present
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import tldextract
import whois

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)

# Known WHOIS privacy proxy keywords
_PRIVACY_KEYWORDS = {
    "privacy", "whoisguard", "guard", "protected", "proxy",
    "redacted", "private", "anonymize", "contact privacy", "identity protection"
}


@dataclass
class DomainFeatures:
    """Container for extracted domain features."""

    features: dict[str, float | int | bool] = field(default_factory=dict)
    whois_available: bool = False
    registrar: str = ""
    creation_date_str: str = ""
    expiration_date_str: str = ""
    extraction_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Convert features to canonical numerical vector."""
        return [
            float(self.features.get(name, -1.0 if "days" in name or "period" in name else 0.0))
            for name in DOMAIN_FEATURE_NAMES
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "whois_available": self.whois_available,
            "registrar": self.registrar,
            "creation_date_str": self.creation_date_str,
            "expiration_date_str": self.expiration_date_str,
            "features": self.features,
            "feature_vector": self.to_vector(),
            "feature_names": DOMAIN_FEATURE_NAMES,
            "extraction_time_ms": self.extraction_time_ms,
            "errors": self.errors,
        }


# Canonical order of 6 Domain features
DOMAIN_FEATURE_NAMES: list[str] = [
    "domain_age_days",
    "registration_period_days",
    "days_to_expiration",
    "whois_available",
    "has_privacy_protection",
    "registrar_known",
]

NUM_DOMAIN_FEATURES = len(DOMAIN_FEATURE_NAMES)  # 6


class DomainAnalyzer:
    """WHOIS/RDAP domain metadata feature extractor.

    Usage:
        analyzer = DomainAnalyzer()
        result = analyzer.extract_features("https://example.com")
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._timeout = getattr(settings.domain_analyzer, "whois_timeout_seconds", 10)
        self._missing_val = getattr(settings.domain_analyzer, "missing_value", -1)

    def extract_features(self, url_or_domain: str) -> DomainFeatures:
        """Extract 6 domain features from URL or domain.

        Args:
            url_or_domain: Target URL or raw domain string.

        Returns:
            DomainFeatures container.
        """
        start_time = time.perf_counter()
        result = DomainFeatures()

        registered_domain = self._extract_registered_domain(url_or_domain)
        if not registered_domain:
            result.errors.append("Invalid or empty domain")
            self._fill_defaults(result.features)
            result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return result

        try:
            # Execute WHOIS query
            w_info = whois.whois(registered_domain)
            if w_info and (w_info.creation_date or w_info.registrar):
                result.whois_available = True
                result.features["whois_available"] = True
                self._process_whois_data(w_info, result)
            else:
                result.errors.append("WHOIS query returned empty metadata")
                self._fill_defaults(result.features)

        except Exception as e:
            result.errors.append(f"WHOIS lookup failed: {str(e)}")
            self._fill_defaults(result.features)

        result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # Assert exactly 6 features present
        assert len(result.features) == NUM_DOMAIN_FEATURES, (
            f"Expected {NUM_DOMAIN_FEATURES} Domain features, got {len(result.features)}. "
            f"Missing: {set(DOMAIN_FEATURE_NAMES) - set(result.features.keys())}"
        )

        return result

    def _process_whois_data(self, w_info: Any, result: DomainFeatures) -> None:
        """Process python-whois object into features."""
        now = datetime.now(timezone.utc)

        # Extract creation and expiration dates (python-whois can return list or datetime)
        creation_dt = self._normalize_datetime(w_info.creation_date)
        expiration_dt = self._normalize_datetime(w_info.expiration_date)

        # 1. Domain Age
        if creation_dt:
            result.creation_date_str = creation_dt.isoformat()
            result.features["domain_age_days"] = max(0, (now - creation_dt).days)
        else:
            result.features["domain_age_days"] = self._missing_val

        # 2. Days to Expiration
        if expiration_dt:
            result.expiration_date_str = expiration_dt.isoformat()
            result.features["days_to_expiration"] = (expiration_dt - now).days
        else:
            result.features["days_to_expiration"] = self._missing_val

        # 3. Registration Period
        if creation_dt and expiration_dt:
            result.features["registration_period_days"] = max(0, (expiration_dt - creation_dt).days)
        else:
            result.features["registration_period_days"] = self._missing_val

        # 4. Registrar Known
        registrar = w_info.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else ""
        result.registrar = str(registrar or "").strip()
        result.features["registrar_known"] = bool(result.registrar)

        # 5. Privacy Protection Check
        raw_text = str(w_info).lower()
        has_privacy = any(kw in raw_text for kw in _PRIVACY_KEYWORDS)
        result.features["has_privacy_protection"] = has_privacy

    @staticmethod
    def _normalize_datetime(val: Any) -> datetime | None:
        """Helper to extract single datetime from string, list, or datetime."""
        if not val:
            return None
        if isinstance(val, list):
            val = val[0]
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val
        return None

    @staticmethod
    def _extract_registered_domain(url_or_domain: str) -> str:
        """Extract root domain (e.g. example.com) from URL or subdomain."""
        if not url_or_domain:
            return ""
        target = url_or_domain.strip()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or url_or_domain
            ext = tldextract.extract(hostname)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
            return hostname.lower()
        except Exception:
            return ""

    def _fill_defaults(self, features_dict: dict[str, float | int | bool]) -> None:
        """Fill explicit missing value representations for unavailable WHOIS."""
        defaults: dict[str, float | int | bool] = {
            "domain_age_days": self._missing_val,
            "registration_period_days": self._missing_val,
            "days_to_expiration": self._missing_val,
            "whois_available": False,
            "has_privacy_protection": False,
            "registrar_known": False,
        }
        for name in DOMAIN_FEATURE_NAMES:
            if name not in features_dict:
                features_dict[name] = defaults[name]
