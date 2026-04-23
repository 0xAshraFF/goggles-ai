"""Main scanner orchestrator.

Provides three entry points:
  scan()      — scan raw content string or bytes
  scan_url()  — fetch a URL and scan (also runs cloaking detection)
  scan_file() — scan a local file

Tier escalation: T1 always runs. T2 runs if T1 flags image content. T3 runs
if T2 flags an image as suspicious.
"""

from __future__ import annotations

import io
import logging
import mimetypes
import os
import time
import uuid
from pathlib import Path
from typing import Optional, Union

import requests

from agentshield.models import ScanResult, Threat, ThreatType
from agentshield.detectors import css_hidden_text, html_injection, unicode_stego
from agentshield.detectors import image_triage, stego_deep, cloaking
from agentshield.sanitizers import html_sanitizer, image_sanitizer, text_sanitizer

logger = logging.getLogger(__name__)

# Content-type categories
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_TEXT_TYPES = frozenset({"text/plain", "text/markdown", "text/csv"})
_IMAGE_TYPES = frozenset({
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "image/bmp", "image/tiff",
})

_REQUEST_TIMEOUT = 15
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def scan(
    content: Union[str, bytes],
    content_type: str = "text/html",
    filename: str = "",
    deep: bool = False,
) -> ScanResult:
    """Scan raw content for prompt injection and steganography threats.

    Args:
        content: HTML string, plain text, or raw image bytes.
        content_type: MIME type hint (e.g. 'text/html', 'image/png').
        filename: Optional filename for extension-based type detection.
        deep: If True, force Tier 3 analysis even if Tier 2 score is borderline.

    Returns:
        ScanResult with threats, sanitized content, and timing info.
    """
    start = time.monotonic()
    all_threats: list[Threat] = []
    tier_timings: dict[str, int] = {}
    sanitized: Optional[str] = None

    ct = content_type.lower().split(";")[0].strip()

    # ── Tier 1 ────────────────────────────────────────────────────────────
    t1_start = time.monotonic()

    if ct in _HTML_TYPES or (isinstance(content, str) and _looks_like_html(content)):
        html = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
        ct = "text/html"

        css_result = css_hidden_text.detect(html)
        all_threats.extend(css_result.threats)

        html_result = html_injection.detect(html)
        all_threats.extend(html_result.threats)

        # Also scan visible text for unicode stego
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
            visible_text = soup.get_text(separator=" ")
        except Exception:
            visible_text = html

        uni_result = unicode_stego.detect(visible_text)
        all_threats.extend(uni_result.threats)

    elif ct in _TEXT_TYPES or isinstance(content, str):
        text = content if isinstance(content, str) else content.decode("utf-8", errors="replace")
        ct = ct if ct in _TEXT_TYPES else "text/plain"

        uni_result = unicode_stego.detect(text)
        all_threats.extend(uni_result.threats)

    elif ct in _IMAGE_TYPES or isinstance(content, bytes):
        # Image: skip to Tier 2
        pass

    tier_timings["t1"] = _ms(t1_start)

    # ── Tier 2: image analysis ─────────────────────────────────────────────
    image_data: Optional[bytes] = None
    triage_result = None

    if ct in _IMAGE_TYPES or isinstance(content, bytes):
        image_data = content if isinstance(content, bytes) else content.encode()

        t2_start = time.monotonic()
        triage_result = image_triage.detect(image_data, filename=filename)
        all_threats.extend(triage_result.threats)
        tier_timings["t2"] = _ms(t2_start)

    # ── Tier 3: deep stego (only if Tier 2 flagged something) ─────────────
    if triage_result and (triage_result.is_suspicious or deep) and image_data:
        t3_start = time.monotonic()
        deep_result = stego_deep.detect(image_data)

        if deep_result.verdict == "stego":
            all_threats.append(
                Threat(
                    type=ThreatType.LSB_STEGANOGRAPHY.value,
                    label="LSB Pixel Steganography (Deep Learning)",
                    severity="critical",
                    tier=3,
                    detail=deep_result.detail,
                    plain_summary=(
                        "Neural network analysis confirms this image contains hidden data "
                        "embedded at the pixel level. Your AI agent may decode and act on "
                        "instructions invisible to the human eye."
                    ),
                    technique=f"SRNet/deep learning detection (confidence {deep_result.confidence:.2%})",
                    outcome="quarantined",
                    location="pixel data (deep analysis)",
                )
            )

        tier_timings["t3"] = _ms(t3_start)

    # ── Sanitize ───────────────────────────────────────────────────────────
    if ct in _HTML_TYPES and isinstance(content, str):
        sanitized = html_sanitizer.sanitize(content)
    elif ct in _TEXT_TYPES and isinstance(content, str):
        sanitized = text_sanitizer.sanitize(content)

    # ── Build result ───────────────────────────────────────────────────────
    total_ms = _ms(start)
    confidence = _compute_confidence(all_threats)

    return ScanResult(
        safe=len(all_threats) == 0,
        confidence=confidence,
        scan_time_ms=total_ms,
        threats=all_threats,
        sanitized_content=sanitized,
        tier_timings=tier_timings,
    )


def scan_url(
    url: str,
    deep: bool = False,
    session: Optional[requests.Session] = None,
) -> ScanResult:
    """Fetch a URL and scan it. Also runs cloaking detection.

    Args:
        url: Target URL.
        deep: Force Tier 3 analysis.
        session: Optional requests.Session for testing.

    Returns:
        ScanResult with all detected threats including cloaking.
    """
    start = time.monotonic()
    all_threats: list[Threat] = []
    tier_timings: dict[str, int] = {}
    sanitized: Optional[str] = None

    s = session or requests.Session()

    # Fetch content
    try:
        resp = s.get(
            url,
            headers={"User-Agent": _BROWSER_UA},
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        resp.raise_for_status()
        content = resp.content
        content_type = resp.headers.get("Content-Type", "text/html").split(";")[0].strip()
    except requests.RequestException as exc:
        logger.warning("scan_url fetch failed for %s: %s", url, exc)
        return ScanResult(
            safe=True,
            confidence=0.5,
            scan_time_ms=_ms(start),
            threats=[],
            sanitized_content=None,
            tier_timings={},
        )

    # Determine filename hint from URL
    filename = url.rsplit("/", 1)[-1].split("?")[0] if "/" in url else ""

    # Scan content
    result = scan(content, content_type=content_type, filename=filename, deep=deep)
    all_threats.extend(result.threats)
    tier_timings.update(result.tier_timings)
    sanitized = result.sanitized_content

    # ── Cloaking detection (Tier 1 supplemental) ──────────────────────────
    if content_type in ("text/html", "application/xhtml+xml"):
        t1_cloak_start = time.monotonic()
        cloak_result = cloaking.detect(url, session=s)
        all_threats.extend(cloak_result.threats)
        tier_timings["t1_cloaking"] = _ms(t1_cloak_start)

    total_ms = _ms(start)
    confidence = _compute_confidence(all_threats)

    return ScanResult(
        safe=len(all_threats) == 0,
        confidence=confidence,
        scan_time_ms=total_ms,
        threats=all_threats,
        sanitized_content=sanitized,
        tier_timings=tier_timings,
    )


def scan_file(path: Union[str, Path], deep: bool = False) -> ScanResult:
    """Scan a local file.

    Args:
        path: Path to the file.
        deep: Force Tier 3 analysis for images.

    Returns:
        ScanResult with all detected threats.
    """
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    filename = file_path.name
    content = file_path.read_bytes()

    # Detect content type from extension and/or magic bytes
    mime, _ = mimetypes.guess_type(filename)
    if not mime:
        # Try magic bytes
        from agentshield.detectors.image_triage import _detect_mime_from_magic
        mime = _detect_mime_from_magic(content) or "application/octet-stream"

    # Try to decode as text if MIME says so
    if mime and mime.startswith("text/"):
        try:
            text_content = content.decode("utf-8")
            return scan(text_content, content_type=mime, filename=filename, deep=deep)
        except UnicodeDecodeError:
            pass

    return scan(content, content_type=mime or "application/octet-stream", filename=filename, deep=deep)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ms(start: float) -> int:
    """Return milliseconds elapsed since *start*."""
    return max(0, int((time.monotonic() - start) * 1000))


def _looks_like_html(text: str) -> bool:
    """Heuristic: does this string look like HTML?"""
    t = text.lstrip()[:200]
    return "<" in t and ">" in t and any(
        tag in t.lower() for tag in ("<html", "<body", "<div", "<p>", "<span", "<!doctype")
    )


def _compute_confidence(threats: list[Threat]) -> float:
    """Compute overall confidence score from detected threats.

    Higher severity and more threats → confidence in the UNSAFE verdict approaches 1.
    No threats → confidence in SAFE verdict is 1.0.
    """
    if not threats:
        return 1.0

    severity_weights = {"critical": 0.95, "high": 0.85, "medium": 0.65, "low": 0.45}

    # Use the max severity as the base, then boost slightly per additional threat
    max_weight = max(severity_weights.get(t.severity, 0.5) for t in threats)
    extra = min(0.05, (len(threats) - 1) * 0.01)
    return min(0.99, max_weight + extra)
