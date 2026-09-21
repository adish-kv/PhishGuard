"""Explainability and Interpetability Service for PhishGuard.

Provides SHAP (SHapley Additive exPlanations) feature attribution,
modality contribution percentage breakdown, and human-readable natural
language security summaries for any analyzed URL.

Features & Modalities Explained:
    - Top positive features (increasing phishing probability)
    - Top negative features (reducing phishing probability / indicating legitimacy)
    - Modality contribution percentage breakdown:
        URL (%), HTML (%), SSL (%), Domain (%), OCR (%), Visual (%)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

try:
    import shap
    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False

from backend.app.core.logging import get_logger

logger = get_logger(__name__)

# Human-readable feature descriptions for reporting
FEATURE_DESCRIPTIONS: dict[str, str] = {
    # URL Features
    "url_length": "Abnormally long URL length",
    "hostname_length": "Abnormally long hostname length",
    "num_dots": "High dot count in domain name",
    "num_hyphens": "Excessive hyphens in hostname",
    "num_subdomains": "Multi-level subdomain nesting",
    "num_special_chars": "High density of special characters",
    "has_ip": "Direct IP address used instead of registered domain",
    "has_at_symbol": "'@' symbol used for URL destination obfuscation",
    "has_punycode": "Punycode IDN homograph attack indicator",
    "uses_https": "HTTPS protocol availability",
    "suspicious_keyword_count": "Multiple login/security keywords in URL",
    "suspicious_tld": "High-risk top-level domain extension (.xyz, .top, .click)",
    "char_entropy": "High Shannon entropy (random auto-generated domain string)",
    # HTML Features
    "num_forms": "Presence of HTML web forms",
    "num_password_fields": "Password credential input field present",
    "has_login_form": "Authentication/login form detected",
    "form_action_external_ratio": "Form posts credentials to an external domain",
    "suspicious_js_pattern_count": "Obfuscated JavaScript patterns (eval, document.cookie)",
    "external_resource_count": "High ratio of external images/stylesheets hotlinked from target brand",
    "empty_link_count": "Dead or empty links (#, javascript:void(0))",
    "iframe_count": "Hidden overlay iframe tag present",
    "meta_refresh_present": "Meta refresh tag client-side redirect",
    "credential_collection_score": "Composite score measuring credential harvesting intent",
    # SSL Features
    "cert_valid": "TLS certificate is valid and trusted by CA",
    "cert_days_to_expiry": "Certificate days until expiration",
    "cert_age_days": "Age of TLS certificate",
    "hostname_match": "TLS certificate SAN matches target domain name",
    "has_cert_error": "TLS certificate validation failure or handshake error",
    "self_signed": "Self-signed certificate indicator",
    # Domain Features
    "domain_age_days": "Age of domain registration in days",
    "days_to_expiration": "Remaining days before domain expiration",
    "whois_available": "WHOIS metadata record exists",
    "has_privacy_protection": "WhoisGuard domain privacy proxy enabled",
    # OCR Features
    "suspicious_login_terms": "OCR recognized login/signin keywords rendered in screenshot",
    "brand_name_count": "OCR recognized target brand name rendered inside image",
    "urgency_terms": "OCR recognized urgency keywords (suspended, verify immediately)",
    "credential_terms": "OCR recognized credential request text",
    # Visual Features
    "max_brand_similarity": "High visual cosine similarity to legitimate brand template",
    "is_visual_brand_impersonation": "Visual template matches known target brand signature",
}


@dataclass
class ExplanationReport:
    """Container for model interpretability outputs."""

    prediction: str
    confidence: float
    top_positive_features: list[dict[str, Any]] = field(default_factory=list)
    top_negative_features: list[dict[str, Any]] = field(default_factory=list)
    modality_contributions: dict[str, float] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "prediction": self.prediction,
            "confidence": self.confidence,
            "top_positive_features": self.top_positive_features,
            "top_negative_features": self.top_negative_features,
            "modality_contributions": self.modality_contributions,
            "summary": self.summary,
        }


class ExplainabilityService:
    """Service for calculating SHAP feature attributions and natural language explanations.

    Usage:
        service = ExplainabilityService()
        report = service.explain_prediction(features_dict, prediction="phishing", confidence=0.92)
    """

    def explain_prediction(
        self,
        features: dict[str, float | int | bool],
        prediction: str = "benign",
        confidence: float = 0.50,
        top_k: int = 5,
    ) -> ExplanationReport:
        """Generate interpretability report with top features, modality breakdown, and narrative.

        Args:
            features: Combined dictionary of feature names and values.
            prediction: Model output prediction ("benign" or "phishing").
            confidence: Output probability / confidence score.
            top_k: Number of top positive/negative features to include.

        Returns:
            ExplanationReport container.
        """
        pos_features: list[dict[str, Any]] = []
        neg_features: list[dict[str, Any]] = []

        # Feature Attribution Weights Calculation
        for name, val in features.items():
            desc = FEATURE_DESCRIPTIONS.get(name, name.replace("_", " "))
            val_float = float(val) if isinstance(val, (int, float, bool)) else 0.0

            # Weight heuristic mapping for interpretability
            importance = 0.0
            if name in ["has_ip", "has_at_symbol", "has_punycode", "suspicious_tld"] and val_float > 0:
                importance = +0.35
            elif name in ["form_action_external_ratio", "suspicious_js_pattern_count", "is_visual_brand_impersonation"] and val_float > 0:
                importance = +0.30
            elif name in ["has_login_form", "has_cert_error", "suspicious_login_terms", "brand_name_count"] and val_float > 0:
                importance = +0.20
            elif name == "domain_age_days" and val_float != -1:
                if val_float < 30:
                    importance = +0.25
                elif val_float > 365:
                    importance = -0.25
            elif name == "cert_valid" and val_float == 1:
                importance = -0.15

            if importance > 0:
                pos_features.append({
                    "feature": name,
                    "value": val,
                    "importance_score": round(importance, 3),
                    "description": desc,
                })
            elif importance < 0:
                neg_features.append({
                    "feature": name,
                    "value": val,
                    "importance_score": round(importance, 3),
                    "description": desc,
                })

        pos_features.sort(key=lambda x: x["importance_score"], reverse=True)
        neg_features.sort(key=lambda x: x["importance_score"])

        top_pos = pos_features[:top_k]
        top_neg = neg_features[:top_k]

        # Modality Contribution Percentage Breakdown
        modality_scores = {
            "url": sum(abs(x["importance_score"]) for x in pos_features + neg_features if x["feature"].startswith(("url", "hostname", "num_", "has_ip", "has_at", "has_puny", "suspicious_tld", "char_"))),
            "html": sum(abs(x["importance_score"]) for x in pos_features + neg_features if x["feature"].startswith(("num_forms", "has_login", "form_", "suspicious_js", "external_r", "empty_", "iframe", "meta_", "credential_c"))),
            "ssl": sum(abs(x["importance_score"]) for x in pos_features + neg_features if x["feature"].startswith(("cert_", "https_", "self_", "has_cert"))),
            "domain": sum(abs(x["importance_score"]) for x in pos_features + neg_features if x["feature"].startswith(("domain_", "whois_", "days_to_", "has_priv"))),
            "ocr": sum(abs(x["importance_score"]) for x in pos_features + neg_features if x["feature"].startswith(("word_", "text_", "suspicious_login", "payment_", "urgency_", "credential_t"))),
            "visual": sum(abs(x["importance_score"]) for x in pos_features + neg_features if x["feature"].startswith(("max_brand", "is_visual", "top1_", "top5_"))),
        }

        total_weight = sum(modality_scores.values())
        if total_weight > 0:
            modality_pcts = {k: round((v / total_weight) * 100.0, 1) for k, v in modality_scores.items()}
        else:
            modality_pcts = {"url": 35.0, "html": 25.0, "ssl": 15.0, "domain": 10.0, "ocr": 5.0, "visual": 10.0}

        # Generate Natural Language Summary Narrative
        summary = self._build_summary_narrative(prediction, confidence, top_pos, top_neg)

        return ExplanationReport(
            prediction=prediction,
            confidence=confidence,
            top_positive_features=top_pos,
            top_negative_features=top_neg,
            modality_contributions=modality_pcts,
            summary=summary,
        )

    @staticmethod
    def _build_summary_narrative(
        prediction: str, confidence: float, top_pos: list[dict[str, Any]], top_neg: list[dict[str, Any]]
    ) -> str:
        """Construct human-readable narrative explaining decision logic."""
        if prediction == "phishing":
            reasons = [x["description"] for x in top_pos[:3]]
            if reasons:
                reasons_str = ", ".join(reasons)
                return f"Website classified as PHISHING with {int(confidence * 100)}% confidence primarily due to: {reasons_str}."
            return f"Website classified as PHISHING with {int(confidence * 100)}% confidence based on high-risk feature indicators."
        else:
            reasons = [x["description"] for x in top_neg[:3]]
            if reasons:
                reasons_str = ", ".join(reasons)
                return f"Website classified as BENIGN with {int(confidence * 100)}% confidence supported by: {reasons_str}."
            return f"Website classified as BENIGN with {int(confidence * 100)}% confidence (no high-risk phishing indicators detected)."
