"""Text sanitizer: removes zero-width characters and normalizes homoglyphs."""

from __future__ import annotations

import unicodedata

from agentshield.detectors.unicode_stego import ZW_SET
from agentshield.utils.unicode_confusables import normalize_text


def sanitize(text: str, normalize_homoglyphs: bool = True) -> str:
    """Remove all zero-width characters and optionally normalize homoglyphs.

    Args:
        text: Input string potentially containing zero-width characters,
              variation selectors, or homoglyph substitutions.
        normalize_homoglyphs: If True, replace known confusable characters
                              with their ASCII equivalents.

    Returns:
        Cleaned string with invisible characters removed.
    """
    if not text:
        return text

    # Remove zero-width and invisible characters
    result = _strip_zero_width(text)

    # Remove variation selectors (U+FE00–FE0F and U+E0100–E01EF)
    result = _strip_variation_selectors(result)

    # Normalize homoglyphs to ASCII equivalents
    if normalize_homoglyphs:
        result = normalize_text(result)

    return result


def _strip_zero_width(text: str) -> str:
    """Remove all zero-width and invisible Unicode characters."""
    return "".join(ch for ch in text if ch not in ZW_SET)


def _strip_variation_selectors(text: str) -> str:
    """Remove Unicode variation selector characters."""
    cleaned = []
    for ch in text:
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            continue
        if 0xE0100 <= cp <= 0xE01EF:
            continue
        cleaned.append(ch)
    return "".join(cleaned)


def normalize_unicode(text: str) -> str:
    """Apply NFC normalization to canonicalize Unicode representations."""
    return unicodedata.normalize("NFC", text)


def sanitize_html_text(html: str) -> str:
    """Extract text from HTML, then apply full text sanitization."""
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "lxml")
        text = soup.get_text(separator=" ", strip=True)
        return sanitize(text)
    except Exception:
        return sanitize(html)
