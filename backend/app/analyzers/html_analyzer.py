"""HTML/DOM feature extraction for phishing detection.

Extracts 28 structural, form, script, and resource features from raw webpage HTML.
Uses BeautifulSoup4 with lxml parser for safe, static DOM tree analysis.

Security Constraints:
    - NO untrusted JavaScript is executed. Static DOM parsing only.
    - HTML input size is capped (default 1MB).
    - All features are extracted deterministically.

Feature Groups (28 features total):
    1. Form & Credential Features (6):
       num_forms, num_password_fields, num_input_fields, num_hidden_fields,
       has_login_form, form_action_external_ratio
    2. Script & JavaScript Features (4):
       script_count, inline_js_count, suspicious_js_pattern_count, event_handler_count
    3. External Resource Features (4):
       external_resource_count, external_domain_count, external_stylesheet_count, external_image_count
    4. Link & Anchor Features (4):
       anchor_count, empty_link_count, suspicious_href_count, external_link_ratio
    5. Structural & DOM Features (6):
       iframe_count, meta_refresh_present, redirect_count, dom_depth,
       html_size_bytes, js_to_html_ratio
    6. Content & Meta Indicators (4):
       page_title_length, favicon_external, has_title, credential_collection_score
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup, Tag

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)

# Precompiled suspicious JavaScript patterns (obfuscation, cookie stealing, location hijacking)
_SUSPICIOUS_JS_PATTERNS = [
    re.compile(r"document\.cookie", re.IGNORECASE),
    re.compile(r"window\.location", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"atob\s*\(", re.IGNORECASE),
    re.compile(r"fromCharCode", re.IGNORECASE),
    re.compile(r"unescape\s*\(", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"location\.replace\s*\(", re.IGNORECASE),
]

# Event handlers commonly attached to inline elements for malicious JS execution
_EVENT_HANDLERS = [
    "onload", "onerror", "onclick", "onmouseover", "onsubmit",
    "onkeydown", "onkeypress", "onfocus", "onblur", "onchange"
]

# Credential / sensitive keywords in forms
_CREDENTIAL_TERMS = {
    "password", "passwd", "pwd", "login", "signin", "username",
    "user", "email", "account", "ssn", "social_security", "creditcard",
    "cardnumber", "cvv", "pin", "verify", "authentication"
}


@dataclass
class HTMLFeatures:
    """Container for extracted HTML/DOM features."""

    features: dict[str, float | int | bool] = field(default_factory=dict)
    page_title: str = ""
    extraction_time_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        """Convert features to canonical numerical vector."""
        return [
            float(self.features.get(name, 0.0))
            for name in HTML_FEATURE_NAMES
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "page_title": self.page_title,
            "features": self.features,
            "feature_vector": self.to_vector(),
            "feature_names": HTML_FEATURE_NAMES,
            "extraction_time_ms": self.extraction_time_ms,
            "errors": self.errors,
        }


# Canonical order of 28 HTML features
HTML_FEATURE_NAMES: list[str] = [
    # Form & Credential (6)
    "num_forms",
    "num_password_fields",
    "num_input_fields",
    "num_hidden_fields",
    "has_login_form",
    "form_action_external_ratio",
    # Script & JS (4)
    "script_count",
    "inline_js_count",
    "suspicious_js_pattern_count",
    "event_handler_count",
    # External Resources (4)
    "external_resource_count",
    "external_domain_count",
    "external_stylesheet_count",
    "external_image_count",
    # Link & Anchor (4)
    "anchor_count",
    "empty_link_count",
    "suspicious_href_count",
    "external_link_ratio",
    # Structural & DOM (6)
    "iframe_count",
    "meta_refresh_present",
    "redirect_count",
    "dom_depth",
    "html_size_bytes",
    "js_to_html_ratio",
    # Content & Meta (4)
    "page_title_length",
    "favicon_external",
    "has_title",
    "credential_collection_score",
]

NUM_HTML_FEATURES = len(HTML_FEATURE_NAMES)  # 28


class HTMLAnalyzer:
    """Parser and feature extractor for webpage HTML/DOM trees.

    Usage:
        analyzer = HTMLAnalyzer()
        result = analyzer.extract_features(html_content, url="https://example.com")
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._max_html_size = getattr(
            settings.security, "max_response_size_bytes", 1024 * 1024
        )

    def extract_features(self, html: str, url: str = "") -> HTMLFeatures:
        """Extract 28 HTML/DOM features from raw HTML code.

        Args:
            html: Raw HTML string of the webpage.
            url: Optional base page URL for external domain comparisons.

        Returns:
            HTMLFeatures container with extracted vector and metadata.
        """
        start_time = time.perf_counter()
        result = HTMLFeatures()

        if not html:
            result.errors.append("Empty HTML content")
            self._fill_defaults(result.features)
            result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return result

        # Truncate HTML if oversized for safe parsing
        raw_bytes_len = len(html.encode("utf-8", errors="ignore"))
        result.features["html_size_bytes"] = raw_bytes_len
        if raw_bytes_len > self._max_html_size:
            html = html[: self._max_html_size]
            result.errors.append(f"HTML size exceeded max limit ({self._max_html_size} bytes). Truncated.")

        page_domain = ""
        if url:
            extracted_page_domain = tldextract.extract(url)
            page_domain = f"{extracted_page_domain.domain}.{extracted_page_domain.suffix}".lower()

        try:
            # Parse DOM with BeautifulSoup
            soup = BeautifulSoup(html, "lxml")

            # Extract Title
            title_tag = soup.find("title")
            title_text = title_tag.get_text().strip() if title_tag else ""
            result.page_title = title_text
            result.features["has_title"] = bool(title_text)
            result.features["page_title_length"] = len(title_text)

            # ═══════════════════════════════════════════
            # 1. Form & Credential Features
            # ═══════════════════════════════════════════
            forms = soup.find_all("form")
            result.features["num_forms"] = len(forms)

            inputs = soup.find_all("input")
            result.features["num_input_fields"] = len(inputs)

            password_inputs = [
                inp for inp in inputs
                if (inp.get("type") or "").lower() == "password"
            ]
            result.features["num_password_fields"] = len(password_inputs)

            hidden_inputs = [
                inp for inp in inputs
                if (inp.get("type") or "").lower() == "hidden"
            ]
            result.features["num_hidden_fields"] = len(hidden_inputs)

            # Check if login form exists
            result.features["has_login_form"] = len(password_inputs) > 0 or self._detect_login_form(forms)

            # Form Action Domain checks
            external_actions = 0
            for form in forms:
                action = form.get("action", "")
                if action and self._is_external_url(action, page_domain):
                    external_actions += 1
            result.features["form_action_external_ratio"] = round(
                external_actions / max(len(forms), 1), 4
            )

            # ═══════════════════════════════════════════
            # 2. Script & JavaScript Features
            # ═══════════════════════════════════════════
            scripts = soup.find_all("script")
            result.features["script_count"] = len(scripts)

            inline_scripts = [s for s in scripts if not s.get("src") and s.string]
            result.features["inline_js_count"] = len(inline_scripts)

            total_js_code = "".join([s.string or "" for s in inline_scripts])
            suspicious_js_count = sum(
                1 for pat in _SUSPICIOUS_JS_PATTERNS if pat.search(total_js_code)
            )
            result.features["suspicious_js_pattern_count"] = suspicious_js_count

            # Count inline event handlers (onload, onerror, etc.)
            event_handler_count = 0
            for tag in soup.find_all(True):
                for handler in _EVENT_HANDLERS:
                    if tag.has_attr(handler):
                        event_handler_count += 1
            result.features["event_handler_count"] = event_handler_count

            # JS to HTML Ratio
            js_bytes = len(total_js_code.encode("utf-8"))
            result.features["js_to_html_ratio"] = round(js_bytes / max(raw_bytes_len, 1), 4)

            # ═══════════════════════════════════════════
            # 3. External Resource Features
            # ═══════════════════════════════════════════
            stylesheets = soup.find_all("link", rel=lambda r: r and "stylesheet" in [x.lower() for x in (r if isinstance(r, list) else [r])])
            images = soup.find_all("img")

            ext_stylesheets = sum(1 for link in stylesheets if self._is_external_url(link.get("href", ""), page_domain))
            ext_images = sum(1 for img in images if self._is_external_url(img.get("src", ""), page_domain))

            result.features["external_stylesheet_count"] = ext_stylesheets
            result.features["external_image_count"] = ext_images

            # Collect all external resources and unique external domains
            all_resources = []
            for tag in soup.find_all(["img", "script", "link", "iframe", "embed", "source"]):
                src = tag.get("src") or tag.get("href") or ""
                if src:
                    all_resources.append(src)

            ext_resources = [r for r in all_resources if self._is_external_url(r, page_domain)]
            result.features["external_resource_count"] = len(ext_resources)

            ext_domains = set()
            for r in ext_resources:
                try:
                    ext = tldextract.extract(r)
                    if ext.domain:
                        ext_domains.add(f"{ext.domain}.{ext.suffix}")
                except Exception:
                    pass
            result.features["external_domain_count"] = len(ext_domains)

            # Favicon information
            favicon_tags = soup.find_all("link", rel=lambda r: r and any(x in ["icon", "shortcut icon"] for x in ([r] if isinstance(r, str) else [y.lower() for y in r])))
            fav_external = any(self._is_external_url(fav.get("href", ""), page_domain) for fav in favicon_tags)
            result.features["favicon_external"] = fav_external

            # ═══════════════════════════════════════════
            # 4. Link & Anchor Features
            # ═══════════════════════════════════════════
            anchors = soup.find_all("a")
            result.features["anchor_count"] = len(anchors)

            empty_links = 0
            suspicious_hrefs = 0
            external_links = 0

            for a in anchors:
                href = (a.get("href") or "").strip()
                href_lower = href.lower()
                if not href or href == "#" or href_lower.startswith("javascript:void") or href_lower in ["#javascript:void(0)", "javascript:void(0);", "javascript:;"]:
                    empty_links += 1
                if href_lower.startswith("javascript:") or "eval(" in href_lower or href_lower.startswith("data:"):
                    suspicious_hrefs += 1
                if self._is_external_url(href, page_domain):
                    external_links += 1

            result.features["empty_link_count"] = empty_links
            result.features["suspicious_href_count"] = suspicious_hrefs
            result.features["external_link_ratio"] = round(external_links / max(len(anchors), 1), 4)

            # ═══════════════════════════════════════════
            # 5. Structural & DOM Features
            # ═══════════════════════════════════════════
            iframes = soup.find_all("iframe")
            result.features["iframe_count"] = len(iframes)

            meta_refreshes = soup.find_all("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
            result.features["meta_refresh_present"] = len(meta_refreshes) > 0
            result.features["redirect_count"] = len(meta_refreshes)

            # DOM Max Depth calculation
            result.features["dom_depth"] = self._calculate_max_dom_depth(soup.html if soup.html else soup)

            # ═══════════════════════════════════════════
            # 6. Credential Collection Score
            # ═══════════════════════════════════════════
            result.features["credential_collection_score"] = round(
                self._calculate_credential_score(forms, inputs), 4
            )

        except Exception as e:
            result.errors.append(f"HTML parsing error: {str(e)}")
            logger.error(
                "HTML feature extraction failed",
                extra={"extra_data": {"error": str(e)}},
                exc_info=True,
            )
            self._fill_defaults(result.features)

        result.extraction_time_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # Assert exactly 28 features present
        assert len(result.features) == NUM_HTML_FEATURES, (
            f"Expected {NUM_HTML_FEATURES} HTML features, got {len(result.features)}. "
            f"Missing: {set(HTML_FEATURE_NAMES) - set(result.features.keys())}"
        )

        return result

    @staticmethod
    def _is_external_url(resource_url: str, page_domain: str) -> bool:
        """Check if resource_url belongs to a domain outside page_domain."""
        if not resource_url or not page_domain:
            return False
        if resource_url.startswith(("/", "#", "javascript:", "data:", "mailto:", "tel:")):
            return False
        try:
            ext = tldextract.extract(resource_url)
            if not ext.domain:
                return False
            resource_domain = f"{ext.domain}.{ext.suffix}".lower()
            return resource_domain != page_domain.lower()
        except Exception:
            return False

    @staticmethod
    def _detect_login_form(forms: list[Tag]) -> bool:
        """Check if any form contains credential collection indicators."""
        for form in forms:
            form_str = str(form).lower()
            if any(term in form_str for term in ["login", "signin", "password", "auth"]):
                return True
        return False

    @staticmethod
    def _calculate_max_dom_depth(element: Tag, current_depth: int = 1) -> int:
        """Calculate maximum element nesting depth in DOM tree."""
        if not hasattr(element, "children") or not element.children:
            return current_depth

        max_child_depth = current_depth
        for child in element.children:
            if isinstance(child, Tag):
                depth = HTMLAnalyzer._calculate_max_dom_depth(child, current_depth + 1)
                if depth > max_child_depth:
                    max_child_depth = depth
        return max_child_depth

    @staticmethod
    def _calculate_credential_score(forms: list[Tag], inputs: list[Tag]) -> float:
        """Calculate score indicating likelihood of credential harvesting."""
        score = 0.0
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            id_val = (inp.get("id") or "").lower()
            placeholder = (inp.get("placeholder") or "").lower()
            inp_type = (inp.get("type") or "").lower()

            if inp_type == "password":
                score += 3.0
            if any(term in name or term in id_val or term in placeholder for term in _CREDENTIAL_TERMS):
                score += 1.5

        if len(forms) > 0 and score > 0:
            score += 1.0

        # Normalize score between 0.0 and 10.0
        return min(round(score, 2), 10.0)

    @staticmethod
    def _fill_defaults(features_dict: dict[str, float | int | bool]) -> None:
        """Fill missing features with default 0 value."""
        for name in HTML_FEATURE_NAMES:
            if name not in features_dict:
                features_dict[name] = 0
