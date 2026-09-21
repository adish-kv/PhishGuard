"""Unit tests for the Model Explainability Service (Phase 15).

Tests:
- Top positive and negative risk feature identification
- Modality contribution percentage calculation
- Natural language summary narrative generation
"""

import pytest
from backend.app.services.explainability import ExplainabilityService, ExplanationReport


@pytest.fixture
def service() -> ExplainabilityService:
    """Fixture providing ExplainabilityService instance."""
    return ExplainabilityService()


class TestExplainabilityService:
    """Test suite for feature importance and explanation generation."""

    def test_phishing_explanation_generation(self, service: ExplainabilityService) -> None:
        """Verify phishing URL feature attributions and positive risk indicators."""
        features = {
            "has_ip": 1,
            "has_at_symbol": 1,
            "suspicious_tld": True,
            "has_login_form": True,
            "form_action_external_ratio": 1.0,
            "domain_age_days": 5,
        }
        report = service.explain_prediction(features, prediction="phishing", confidence=0.96)

        assert report.prediction == "phishing"
        assert report.confidence == 0.96
        assert len(report.top_positive_features) > 0
        assert "PHISHING" in report.summary
        assert "modality_contributions" in report.to_dict()

    def test_benign_explanation_generation(self, service: ExplainabilityService) -> None:
        """Verify benign URL feature attributions and negative risk indicators."""
        features = {
            "has_ip": 0,
            "uses_https": True,
            "cert_valid": True,
            "domain_age_days": 4500,
        }
        report = service.explain_prediction(features, prediction="benign", confidence=0.98)

        assert report.prediction == "benign"
        assert len(report.top_negative_features) > 0
        assert "BENIGN" in report.summary
