"""FastAPI API Integration Unit Tests (Phase 14).

Tests HTTP endpoints:
- GET /
- GET /api/v1/health
- POST /api/v1/analyze
- GET /api/v1/history
- GET /api/v1/experiments
"""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from backend.app.adaptive.decision_engine import AdaptiveDecisionResult
from backend.app.api.v1.endpoints import engine
from backend.app.main import app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing FastAPI TestClient."""
    return TestClient(app)


class TestAPIEndpoints:
    """Test suite for FastAPI REST API endpoints."""

    def test_root_endpoint(self, client: TestClient) -> None:
        """Verify GET / returns app metadata."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "PhishGuard"
        assert data["status"] == "online"

    def test_health_endpoint(self, client: TestClient) -> None:
        """Verify GET /api/v1/health returns system health and model versions."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "loaded_models" in data
        assert "fusion_model" in data["loaded_models"]

    def test_analyze_endpoint_success(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify POST /api/v1/analyze returns valid prediction schema."""
        mock_result = AdaptiveDecisionResult(
            url="https://google.com",
            prediction="benign",
            confidence=0.98,
            risk_level="low",
            stage_reached="stage1",
            modalities_used=3,
            early_stopped=True,
            total_latency_ms=15.4,
            stage_latencies_ms={"stage1_ms": 15.4},
            explanation={"info": "stage1 clean"},
        )
        monkeypatch.setattr(engine, "analyze_url", AsyncMock(return_value=mock_result))

        payload = {"url": "https://google.com"}
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["prediction"] == "benign"
        assert data["confidence"] == 0.98
        assert data["stage_reached"] == "stage1"
        assert data["modalities_used"] == 3

    def test_analyze_endpoint_empty_url(self, client: TestClient) -> None:
        """Verify empty URL submission returns 400 Bad Request."""
        payload = {"url": "   "}
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 400

    def test_history_endpoint(self, client: TestClient) -> None:
        """Verify GET /api/v1/history returns log items."""
        response = client.get("/api/v1/history?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    def test_experiments_endpoint(self, client: TestClient) -> None:
        """Verify GET /api/v1/experiments returns metrics dict."""
        response = client.get("/api/v1/experiments")
        assert response.status_code == 200
        data = response.json()
        assert "experiments_1_to_5_baselines" in data
        assert "experiment_6_full_multimodal_fusion" in data
        assert "experiment_7_adaptive_system" in data
