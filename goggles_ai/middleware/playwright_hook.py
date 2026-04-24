"""Playwright page.route() interceptor for goggles-ai.

Intercepts all HTTP responses in a Playwright browser session, scans content
for threats, and either blocks, sanitizes, or passes through based on scan results.

Usage (sync):
    from playwright.sync_api import sync_playwright
    from goggles_ai.middleware.playwright_hook import install_sync

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        hook = install_sync(page, on_threat=print)
        page.goto("https://example.com")
        browser.close()

Usage (async):
    from playwright.async_api import async_playwright
    from goggles_ai.middleware.playwright_hook import install_async

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        hook = await install_async(page, on_threat=my_handler)
        await page.goto("https://example.com")
        await browser.close()

on_threat callback signature:
    def on_threat(event: ThreatEvent) -> None

ThreatEvent fields:
    url, content_type, threats, sanitized_content, scan_result
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass, field
from typing import Callable, Optional

from goggles_ai.scanner import scan
from goggles_ai.models import ScanResult, Threat


@dataclass
class ThreatEvent:
    url: str
    content_type: str
    threats: list[Threat]
    sanitized_content: Optional[str]
    scan_result: ScanResult


@dataclass
class HookConfig:
    """Configuration for the Playwright intercept hook."""
    block_on_critical: bool = True
    sanitize_html: bool = True
    sanitize_images: bool = True
    deep_scan: bool = False
    # Content types to intercept (None = intercept all text/* and image/*)
    intercept_types: Optional[list[str]] = None
    # Minimum severity to trigger on_threat callback ("low", "medium", "high", "critical")
    alert_severity: str = "medium"

    def should_intercept(self, content_type: str) -> bool:
        ct = content_type.split(";")[0].strip().lower()
        if self.intercept_types is not None:
            return ct in self.intercept_types
        return ct.startswith("text/") or ct.startswith("image/")

    def should_alert(self, result: ScanResult) -> bool:
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = severity_order.get(self.alert_severity, 1)
        for t in result.threats:
            if severity_order.get(t.severity, 0) >= threshold:
                return True
        return False


_BLOCKED_HTML = """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Blocked by goggles-ai</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto;padding:24px">
<h1 style="color:#dc2626">Blocked by goggles-ai</h1>
<p>This page was blocked because it contains threats that could compromise AI agent safety.</p>
<p id="detail"></p>
</body>
</html>"""


def _blocked_html(threats: list[Threat]) -> str:
    summary = "; ".join(t.plain_summary for t in threats[:3])
    return _BLOCKED_HTML.replace(
        '<p id="detail"></p>',
        f'<p style="color:#7f1d1d">{summary}</p>',
    )


# ── Sync hook ─────────────────────────────────────────────────────────────────

class SyncPlaywrightHook:
    def __init__(
        self,
        config: HookConfig,
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    ):
        self.config = config
        self.on_threat = on_threat
        self._scan_count = 0
        self._threat_count = 0
        self._blocked_count = 0

    def handle_route(self, route, request=None) -> None:
        try:
            response = route.fetch()
        except Exception:
            route.continue_()
            return

        content_type = response.headers.get("content-type", "text/plain")
        if not self.config.should_intercept(content_type):
            route.fulfill(response=response)
            return

        body = response.body()
        self._scan_count += 1

        ct_base = content_type.split(";")[0].strip().lower()
        result = scan(body, content_type=ct_base, deep=self.config.deep_scan)

        if result.threats:
            self._threat_count += 1
            url = route.request.url

            if self.on_threat and self.config.should_alert(result):
                event = ThreatEvent(
                    url=url,
                    content_type=ct_base,
                    threats=result.threats,
                    sanitized_content=result.sanitized_content,
                    scan_result=result,
                )
                try:
                    self.on_threat(event)
                except Exception:
                    pass

            if self.config.block_on_critical and result.has_critical:
                self._blocked_count += 1
                route.fulfill(
                    status=403,
                    content_type="text/html",
                    body=_blocked_html(result.threats),
                )
                return

            if result.sanitized_content and ct_base == "text/html" and self.config.sanitize_html:
                route.fulfill(
                    status=response.status,
                    headers=dict(response.headers),
                    body=result.sanitized_content.encode("utf-8"),
                )
                return

        route.fulfill(response=response)

    @property
    def stats(self) -> dict:
        return {
            "scanned": self._scan_count,
            "threats_found": self._threat_count,
            "blocked": self._blocked_count,
        }


# ── Async hook ────────────────────────────────────────────────────────────────

class AsyncPlaywrightHook:
    def __init__(
        self,
        config: HookConfig,
        on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    ):
        self.config = config
        self.on_threat = on_threat
        self._scan_count = 0
        self._threat_count = 0
        self._blocked_count = 0

    async def handle_route(self, route, request=None) -> None:
        import asyncio

        try:
            response = await route.fetch()
        except Exception:
            await route.continue_()
            return

        content_type = response.headers.get("content-type", "text/plain")
        if not self.config.should_intercept(content_type):
            await route.fulfill(response=response)
            return

        body = await response.body()
        self._scan_count += 1

        ct_base = content_type.split(";")[0].strip().lower()
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: scan(body, content_type=ct_base, deep=self.config.deep_scan)
        )

        if result.threats:
            self._threat_count += 1
            url = route.request.url

            if self.on_threat and self.config.should_alert(result):
                event = ThreatEvent(
                    url=url,
                    content_type=ct_base,
                    threats=result.threats,
                    sanitized_content=result.sanitized_content,
                    scan_result=result,
                )
                try:
                    if asyncio.iscoroutinefunction(self.on_threat):
                        await self.on_threat(event)
                    else:
                        self.on_threat(event)
                except Exception:
                    pass

            if self.config.block_on_critical and result.has_critical:
                self._blocked_count += 1
                await route.fulfill(
                    status=403,
                    content_type="text/html",
                    body=_blocked_html(result.threats),
                )
                return

            if result.sanitized_content and ct_base == "text/html" and self.config.sanitize_html:
                await route.fulfill(
                    status=response.status,
                    headers=dict(response.headers),
                    body=result.sanitized_content.encode("utf-8"),
                )
                return

        await route.fulfill(response=response)

    @property
    def stats(self) -> dict:
        return {
            "scanned": self._scan_count,
            "threats_found": self._threat_count,
            "blocked": self._blocked_count,
        }


# ── Public install helpers ────────────────────────────────────────────────────

def install_sync(
    page,
    config: Optional[HookConfig] = None,
    on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    url_pattern: str = "**/*",
) -> SyncPlaywrightHook:
    """Install the goggles-ai intercept hook on a Playwright sync Page.

    Args:
        page: Playwright sync Page object.
        config: HookConfig instance (defaults used if None).
        on_threat: Callback invoked for each detected threat.
        url_pattern: Glob pattern of URLs to intercept (default: all).

    Returns:
        SyncPlaywrightHook with .stats property.
    """
    cfg = config or HookConfig()
    hook = SyncPlaywrightHook(cfg, on_threat)
    page.route(url_pattern, hook.handle_route)
    return hook


async def install_async(
    page,
    config: Optional[HookConfig] = None,
    on_threat: Optional[Callable[[ThreatEvent], None]] = None,
    url_pattern: str = "**/*",
) -> AsyncPlaywrightHook:
    """Install the goggles-ai intercept hook on a Playwright async Page.

    Args:
        page: Playwright async Page object.
        config: HookConfig instance (defaults used if None).
        on_threat: Async or sync callback invoked for each detected threat.
        url_pattern: Glob pattern of URLs to intercept (default: all).

    Returns:
        AsyncPlaywrightHook with .stats property.
    """
    cfg = config or HookConfig()
    hook = AsyncPlaywrightHook(cfg, on_threat)
    await page.route(url_pattern, hook.handle_route)
    return hook
