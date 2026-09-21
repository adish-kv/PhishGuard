"""Unit tests for the Playwright Screenshot Service module.

Tests SSRF blocking before browser launch, Playwright browser navigation,
and output screenshot/HTML file generation.
"""

import os
from pathlib import Path

import pytest
from backend.app.analyzers.screenshot_service import ScreenshotResult, ScreenshotService


@pytest.fixture
def service(tmp_path: Path) -> ScreenshotService:
    """Fixture providing ScreenshotService instance with temporary output directory."""
    return ScreenshotService(output_dir=str(tmp_path))


@pytest.mark.asyncio
class TestScreenshotService:
    """Test suite for screenshot capture and security sandboxing."""

    async def test_ssrf_blocked_url_prevents_launch(self, service: ScreenshotService) -> None:
        """Verify localhost / private IP URLs are blocked immediately without launching browser."""
        result = await service.capture_screenshot("http://127.0.0.1")
        assert result.success is False
        assert result.screenshot_path == ""
        assert len(result.errors) > 0
        assert any("ssrf" in err.lower() or "blocked" in err.lower() for err in result.errors)

    async def test_aws_metadata_blocked(self, service: ScreenshotService) -> None:
        """Verify cloud metadata endpoints are blocked immediately."""
        result = await service.capture_screenshot("http://169.254.169.254/latest/meta-data/")
        assert result.success is False
        assert len(result.errors) > 0

    async def test_successful_screenshot_capture(self, service: ScreenshotService, tmp_path: Path) -> None:
        """Verify screenshot capture on a safe public website (example.com)."""
        result = await service.capture_screenshot("https://example.com", sample_id="test_sample_123")
        assert result.success is True
        assert result.sample_id == "test_sample_123"
        assert result.status_code == 200
        assert os.path.exists(result.screenshot_path)
        assert os.path.exists(result.dom_snapshot_path)
        assert "Example Domain" in result.page_title
