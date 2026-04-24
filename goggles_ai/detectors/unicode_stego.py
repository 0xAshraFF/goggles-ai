"""Tier 1: Unicode steganography detection.

Detects zero-width characters, variation selectors, and homoglyph substitutions
used to embed hidden messages in text content.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from goggles_ai.models import Threat, ThreatType
from goggles_ai.utils.unicode_confusables import find_mixed_scripts, get_confusables

# ── Zero-width and invisible characters ──────────────────────────────────────

ZERO_WIDTH_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE (U+200B)",
    "‌": "ZERO WIDTH NON-JOINER (U+200C)",
    "‍": "ZERO WIDTH JOINER (U+200D)",
    "⁠": "WORD JOINER (U+2060)",
    "﻿": "ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF)",
    "­": "SOFT HYPHEN (U+00AD)",
    "‎": "LEFT-TO-RIGHT MARK (U+200E)",
    "‏": "RIGHT-TO-LEFT MARK (U+200F)",
    "⁡": "FUNCTION APPLICATION (U+2061)",
    "⁢": "INVISIBLE TIMES (U+2062)",
    "⁣": "INVISIBLE SEPARATOR (U+2063)",
    "⁤": "INVISIBLE PLUS (U+2064)",
    " ": "LINE SEPARATOR (U+2028)",
    " ": "PARAGRAPH SEPARATOR (U+2029)",
    "᠎": "MONGOLIAN VOWEL SEPARATOR (U+180E)",
}

# Variation selectors used in steganography
VARIATION_SELECTOR_RANGE = range(0xFE00, 0xFE10)  # VS1–VS16

ZW_SET: frozenset[str] = frozenset(ZERO_WIDTH_CHARS.keys())

# Density threshold: flag if zero-width chars exceed this many per 100 visible chars
ZW_DENSITY_THRESHOLD = 5

# Minimum zero-width character count before we attempt decoding
ZW_DECODE_MIN = 8


def _count_visible_chars(text: str) -> int:
    """Count printable non-whitespace characters."""
    return sum(1 for c in text if not unicodedata.category(c).startswith("C") and c not in ZW_SET)


def _extract_zw_chars(text: str) -> list[str]:
    """Extract all zero-width characters from text in order."""
    return [c for c in text if c in ZW_SET]


def _decode_zw_binary(zw_chars: list[str]) -> str:
    """Attempt to decode a zero-width sequence as a binary-encoded ASCII message.

    Convention: U+200B (ZWSP) = bit 1, U+200C (ZWNJ) = bit 0.
    Groups of 8 bits → one ASCII character.
    """
    bits = []
    for c in zw_chars:
        if c == "​":
            bits.append("1")
        elif c == "‌":
            bits.append("0")
        # Other zero-width chars are separators — ignored

    decoded = []
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i : i + 8]
        val = int("".join(byte), 2)
        if 32 <= val < 127:  # Printable ASCII
            decoded.append(chr(val))

    result = "".join(decoded)
    # Only return if we decoded enough readable content
    return result if len(result) >= 4 else ""


def _detect_variation_selectors(text: str) -> list[tuple[int, str]]:
    """Find variation selector characters and their positions."""
    found = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if 0xFE00 <= cp <= 0xFE0F:
            found.append((i, f"VS{cp - 0xFE00 + 1} (U+{cp:04X})"))
        elif 0xE0100 <= cp <= 0xE01EF:
            found.append((i, f"VS{cp - 0xE0100 + 17} (U+{cp:05X})"))
    return found


@dataclass
class UnicodeStegoResult:
    """Result from Unicode steganography analysis."""

    threats: list[Threat] = field(default_factory=list)
    decoded_message: str = ""
    zw_count: int = 0
    zw_density: float = 0.0


def detect(text: str) -> UnicodeStegoResult:
    """Analyse text for zero-width steganography, variation selectors, and homoglyphs.

    Args:
        text: Plaintext or HTML-extracted text to analyse.

    Returns:
        UnicodeStegoResult with detected threats.
    """
    result = UnicodeStegoResult()

    if not text or not text.strip():
        return result

    # ── 1. Zero-width character detection ─────────────────────────────────

    zw_chars = _extract_zw_chars(text)
    visible_count = _count_visible_chars(text)
    result.zw_count = len(zw_chars)

    if visible_count > 0:
        result.zw_density = (len(zw_chars) / visible_count) * 100
    else:
        result.zw_density = 100.0 if zw_chars else 0.0

    if zw_chars:
        # Count distinct zero-width types
        zw_types: dict[str, int] = {}
        for c in zw_chars:
            name = ZERO_WIDTH_CHARS.get(c, f"U+{ord(c):04X}")
            zw_types[name] = zw_types.get(name, 0) + 1

        type_summary = ", ".join(f"{v}× {k}" for k, v in list(zw_types.items())[:4])

        # Attempt to decode the hidden message
        decoded = ""
        if len(zw_chars) >= ZW_DECODE_MIN:
            decoded = _decode_zw_binary(zw_chars)
            result.decoded_message = decoded

        is_high_density = result.zw_density > ZW_DENSITY_THRESHOLD

        if is_high_density or len(zw_chars) >= ZW_DECODE_MIN:
            detail = (
                f"Found {len(zw_chars)} zero-width characters ({type_summary}). "
                f"Density: {result.zw_density:.1f} ZW chars per 100 visible chars."
            )
            if decoded:
                detail += f" Decoded hidden message: {decoded!r}"

            result.threats.append(
                Threat.from_type(
                    ThreatType.ZERO_WIDTH_CHARS,
                    detail=detail,
                    technique=type_summary,
                    outcome="stripped",
                    location=f"chars 0–{len(text)} (density {result.zw_density:.1f}%)",
                )
            )

    # ── 2. Variation selector detection ───────────────────────────────────

    vs_found = _detect_variation_selectors(text)
    if vs_found:
        vs_summary = ", ".join(f"pos {pos}: {name}" for pos, name in vs_found[:5])
        if len(vs_found) > 5:
            vs_summary += f" (+{len(vs_found) - 5} more)"

        result.threats.append(
            Threat.from_type(
                ThreatType.VARIATION_SELECTOR,
                detail=(
                    f"Found {len(vs_found)} variation selector characters: {vs_summary}. "
                    "These can encode hidden bit-strings."
                ),
                technique=f"Unicode variation selectors ({len(vs_found)} total)",
                outcome="stripped",
                location=f"positions {[p for p, _ in vs_found[:3]]}",
            )
        )

    # ── 3. Homoglyph / mixed-script detection ─────────────────────────────

    _detect_homoglyphs(text, result)

    return result


def _detect_homoglyphs(text: str, result: UnicodeStegoResult) -> None:
    """Detect confusable Unicode characters mixed with Latin text."""
    confusables = get_confusables()
    mixed_scripts = find_mixed_scripts(text)

    # Find individual confusable characters
    confusable_chars: list[tuple[int, str, str]] = []
    for i, ch in enumerate(text):
        if ch in confusables and ord(ch) > 127:
            confusable_chars.append((i, ch, confusables[ch]))

    if confusable_chars:
        samples = [
            f"pos {i}: {repr(ch)} → {repr(ascii_eq)}"
            for i, ch, ascii_eq in confusable_chars[:6]
        ]
        result.threats.append(
            Threat.from_type(
                ThreatType.HOMOGLYPH,
                detail=(
                    f"Found {len(confusable_chars)} confusable Unicode characters "
                    f"({', '.join(mixed_scripts or ['unknown script'])}). "
                    f"Examples: {'; '.join(samples)}"
                ),
                technique=f"Mixed-script homoglyphs ({', '.join(mixed_scripts or ['non-Latin'])})",
                outcome="normalized",
                location=f"{len(confusable_chars)} positions across text",
            )
        )
    elif mixed_scripts:
        # Mixed scripts without known confusables still worth reporting
        sample_chars = [
            repr(ch)
            for ch in text
            if ch.isalpha() and ord(ch) > 127
        ][:6]
        result.threats.append(
            Threat.from_type(
                ThreatType.HOMOGLYPH,
                detail=(
                    f"Text mixes Latin with {', '.join(mixed_scripts)} scripts. "
                    f"Non-ASCII letters: {', '.join(sample_chars)}"
                ),
                technique=f"Mixed scripts: {', '.join(mixed_scripts)}",
                outcome="flagged",
                location="throughout text",
            )
        )


def decode_zw_message(text: str) -> str:
    """Public helper: attempt to extract a hidden message from zero-width chars."""
    zw_chars = _extract_zw_chars(text)
    if len(zw_chars) < ZW_DECODE_MIN:
        return ""
    return _decode_zw_binary(zw_chars)
