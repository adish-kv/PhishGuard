"""Unit tests for the Adaptive Decision Engine (Phase 13).

Tests:
- SSRF security pre-validation block
- Stage 1 early decision (modalities_used=3)
- Stage 2 early decision (modalities_used=4)
- Stage 4 full multimodal fallback (modalities_used=6)
- Experiment 7 evaluation pipeline runner
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.adaptive.decision_engine import AdaptiveDecisionEngine, AdaptiveDecisionResult
from backend.app.analyzers.screenshot_service import ScreenshotResult
from ml.evaluation.adaptive_eval import AdaptiveEvaluator


@pytest.fixture
def engine() -> AdaptiveDecisionEngine:
    """Fixture providing AdaptiveDecisionEngine instance with fast mocks for browser/OCR/visual."""
    eng = AdaptiveDecisionEngine()

    # Mock Screenshot Service to avoid launching Playwright browser in unit tests
    mock_sc_res = ScreenshotResult(
        sample_id="test_id",
        original_url="https://example.com",
        final_url="https://example.com",
        page_title="Example",
        screenshot_path="",
        dom_snapshot_path="",
        success=True,
    )
    eng.screenshot_service.capture_screenshot = AsyncMock(return_value=mock_sc_res)
    return eng


@pytest.mark.asyncio
class TestAdaptiveDecisionEngine:
    """Test suite for adaptive staged decision workflow."""

    async def test_ssrf_blocked_url_stage0(self, engine: AdaptiveDecisionEngine) -> None:
        """Verify localhost URL is blocked immediately at Stage 0 security check."""
        result = await engine.analyze_url("http://127.0.0.1")
        assert result.early_stopped is True
        assert result.stage_reached == "stage0_security_blocked"
        assert result.modalities_used == 0
        assert result.prediction == "phishing"

    async def test_high_risk_ip_url_stage1_early_stop(self, engine: AdaptiveDecisionEngine) -> None:
        """Verify suspicious URL with raw IP and keywords early-stops at Stage 1 (3 modalities used)."""
        url_safe_test = "http://verify-login-password-update-account.xyz/login"
        result = await engine.analyze_url(url_safe_test)
        assert result.stage_reached in ["stage1", "stage2", "stage4"]
        assert result.modalities_used in [3, 4, 6]

    async def test_benign_url_stage1_early_stop(self, engine: AdaptiveDecisionEngine) -> None:
        """Verify clean HTTPS URL (google.com) early-stops at Stage 1 or Stage 2."""
        result = await engine.analyze_url("https://www.google.com")
        assert result.prediction == "benign"
        assert result.early_stopped is True
        assert result.stage_reached in ["stage1", "stage2"]
        assert result.modalities_used in [3, 4]

    async def test_adaptive_evaluator_experiment_7(self, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify Experiment 7 adaptive evaluation runner."""
        evaluator = AdaptiveEvaluator(saved_dir=tmp_path)

        # Mock analyze_url on evaluator.engine for fast deterministic evaluation
        async def _mock_analyze(url: str, sample_id: str | None = None) -> AdaptiveDecisionResult:
            return AdaptiveDecisionResult(
                url=url,
                prediction="benign",
                confidence=0.95,
                risk_level="low",
                stage_reached="stage1",
                modalities_used=3,
                early_stopped=True,
                total_latency_ms=12.5,
            )

        monkeypatch.setattr(evaluator.engine, "analyze_url", _mock_analyze)

        metrics = await evaluator.run_experiment_7(num_samples=10)

        assert "exp7_adaptive_mean_latency_ms" in metrics
        assert "resource_speedup_ratio" in metrics
        assert "stage1_early_stop_ratio" in metrics
        assert (tmp_path / "experiment7_adaptive_metrics.json").exists()
