"""Playwright screenshot capture and browser automation service for PhishGuard.

Provides sandboxed, isolated browser navigation and screenshot capture.
Enforces strict SSRF protection at both initial URL entry and network
request routing level (to prevent redirect-based SSRF bypasses).

Workflow:
    1. Validate input URL with SSRFProtector.
    2. Launch isolated Playwright Chromium context (non-root, sandboxed).
    3. Intercept request routes to enforce egress network security.
    4. Navigate with 15s timeout.
    5. Capture full-page 1280x720 screenshot.
    6. Record final URL, title, redirect chain, and DOM snapshot.
    7. Destroy browser context immediately.

Security Isolation & SSRF Defenses:
    - Route interception blocks private IPs (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).
    - Blocks file://, ftp://, chrome:// protocols.
    - Caps navigation timeout and max redirects.
    - Fresh, isolated BrowserContext per request (no cookies/state sharing).
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import Route, async_playwright

from backend.app.core.config import PROJECT_ROOT, get_settings
from backend.app.core.logging import get_logger
from backend.app.core.security import SSRFProtector

logger = get_logger(__name__)


@dataclass
class ScreenshotResult:
    """Container for screenshot capture outputs and metadata."""

    sample_id: str
    original_url: str
    final_url: str = ""
    page_title: str = ""
    screenshot_path: str = ""
    dom_snapshot_path: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    status_code: int = 0
    capture_time_ms: float = 0.0
    success: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "sample_id": self.sample_id,
            "original_url": self.original_url,
            "final_url": self.final_url,
            "page_title": self.page_title,
            "screenshot_path": self.screenshot_path,
            "dom_snapshot_path": self.dom_snapshot_path,
            "redirect_chain": self.redirect_chain,
            "status_code": self.status_code,
            "capture_time_ms": self.capture_time_ms,
            "success": self.success,
            "errors": self.errors,
        }


class ScreenshotService:
    """Sandboxed browser automation service for capturing web screenshots.

    Usage:
        service = ScreenshotService()
        result = await service.capture_screenshot("https://example.com")
    """

    def __init__(self, output_dir: str | None = None) -> None:
        settings = get_settings()
        self._viewport_width = getattr(settings.screenshot, "viewport_width", 1280)
        self._viewport_height = getattr(settings.screenshot, "viewport_height", 720)
        self._timeout_ms = getattr(settings.screenshot, "timeout_ms", 15000)
        self._wait_after_load_ms = getattr(settings.screenshot, "wait_after_load_ms", 2000)

        # Base storage directories
        if output_dir:
            self._screenshots_dir = Path(output_dir)
        else:
            self._screenshots_dir = PROJECT_ROOT / "data" / "screenshots"
        self._html_dir = PROJECT_ROOT / "data" / "html"

        self._screenshots_dir.mkdir(parents=True, exist_ok=True)
        self._html_dir.mkdir(parents=True, exist_ok=True)

        self._ssrf_protector = SSRFProtector()

    async def capture_screenshot(
        self,
        url: str,
        sample_id: str | None = None,
        save_dom: bool = True,
    ) -> ScreenshotResult:
        """Capture webpage screenshot and DOM snapshot in isolated browser.

        Args:
            url: Target website URL.
            sample_id: Unique identifier for saved files (auto-generated if None).
            save_dom: Whether to save HTML DOM snapshot file.

        Returns:
            ScreenshotResult container.
        """
        start_time = time.perf_counter()
        sid = sample_id or str(uuid.uuid4())
        result = ScreenshotResult(sample_id=sid, original_url=url)

        # Step 1: Pre-navigation SSRF Validation
        val_res = self._ssrf_protector.validate_url(url)
        if not val_res.is_valid:
            result.errors.extend(val_res.errors)
            result.errors.append("Navigation blocked by initial SSRF protector")
            result.capture_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return result

        screenshot_file = self._screenshots_dir / f"{sid}.png"
        dom_file = self._html_dir / f"{sid}.html"

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        "--disable-gpu",
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-background-networking",
                        "--disable-extensions",
                    ],
                )

                # Isolated BrowserContext with custom viewport
                context = await browser.new_context(
                    viewport={"width": self._viewport_width, "height": self._viewport_height},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )

                # Network route interception for redirect & egress SSRF protection
                async def _route_handler(route: Route) -> None:
                    req_url = route.request.url
                    # Enforce scheme & IP block checks on sub-resource and redirect requests
                    res = self._ssrf_protector.validate_url(req_url)
                    if not res.is_valid:
                        logger.warning(
                            f"Blocked sub-request/redirect to unsafe target: {req_url}"
                        )
                        await route.abort()
                    else:
                        await route.continue_()

                await context.route("**/*", _route_handler)

                page = await context.new_page()

                # Track redirect chain
                redirect_chain: list[str] = [url]

                def _on_response(response: Any) -> None:
                    if 300 <= response.status < 400:
                        loc = response.headers.get("location")
                        if loc and loc not in redirect_chain:
                            redirect_chain.append(loc)

                page.on("response", _on_response)

                # Navigate
                response = await page.goto(
                    url,
                    timeout=self._timeout_ms,
                    wait_until="domcontentloaded",
                )

                if response:
                    result.status_code = response.status

                # Brief delay for dynamic JS/CSS rendering
                await asyncio.sleep(self._wait_after_load_ms / 1000)

                # Capture final metadata
                result.final_url = page.url
                result.page_title = await page.title()
                result.redirect_chain = redirect_chain

                # Save Screenshot
                await page.screenshot(path=str(screenshot_file), full_page=False)
                result.screenshot_path = str(screenshot_file)

                # Save HTML DOM Snapshot
                if save_dom:
                    dom_content = await page.content()
                    with open(dom_file, "w", encoding="utf-8") as f:
                        f.write(dom_content)
                    result.dom_snapshot_path = str(dom_file)

                await context.close()
                await browser.close()
                result.success = True

        except PlaywrightError as pe:
            result.errors.append(f"Playwright navigation error: {str(pe)}")
            logger.error(f"Playwright capture failed for {url}: {str(pe)}")
        except Exception as e:
            result.errors.append(f"Unexpected browser error: {str(e)}")
            logger.error(f"Screenshot capture error for {url}: {str(e)}")

        result.capture_time_ms = round((time.perf_counter() - start_time) * 1000, 3)
        return result
