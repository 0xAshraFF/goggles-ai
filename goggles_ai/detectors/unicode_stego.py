"""Tier 1: Unicode steganography detection.

Detects zero-width characters, variation selectors, and homoglyph substitutions
used to embed hidden messages in text content.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

from goggles_ai.models import Threat, ThreatType
from goggles_ai.utils.unicode_confusables import (
    detect_script,
    find_suspicious_tokens,
    get_confusables,
)

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
    "‪": "LEFT-TO-RIGHT EMBEDDING (U+202A)",
    "‫": "RIGHT-TO-LEFT EMBEDDING (U+202B)",
    "‬": "POP DIRECTIONAL FORMATTING (U+202C)",
    "‭": "LEFT-TO-RIGHT OVERRIDE (U+202D)",
    "‮": "RIGHT-TO-LEFT OVERRIDE (U+202E)",
    "⁦": "LEFT-TO-RIGHT ISOLATE (U+2066)",
    "⁧": "RIGHT-TO-LEFT ISOLATE (U+2067)",
    "⁨": "FIRST STRONG ISOLATE (U+2068)",
    "⁩": "POP DIRECTIONAL ISOLATE (U+2069)",
}

# Bidi overrides reorder what a human sees (Trojan Source); one is enough to flag
BIDI_OVERRIDES: frozenset[str] = frozenset({"‭", "‮"})

# Variation selectors used in steganography
VARIATION_SELECTOR_RANGE = range(0xFE00, 0xFE10)  # VS1–VS16

ZW_SET: frozenset[str] = frozenset(ZERO_WIDTH_CHARS.keys())

# Density threshold: flag if zero-width chars exceed this many per 100 visible chars
ZW_DENSITY_THRESHOLD = 5

# Density alone needs at least this many chars, so one stray ZWSP in a short string isn't flagged
ZW_DENSITY_MIN_COUNT = 3

# Minimum zero-width character count before we attempt decoding
ZW_DECODE_MIN = 8

_ZWJ, _ZWNJ, _ZWSP, _SOFT_HYPHEN = "‍", "‌", "​", "­"

# Bidi marks, embeddings, and isolates have everyday uses in RTL and UI text (overrides excluded)
_BIDI_MARKS: frozenset[str] = frozenset(
    {"‎", "‏", "‪", "‫", "‬", "⁦", "⁧", "⁨", "⁩"}
)

# Invisible chars that never belong inside a Latin word
INTRA_WORD_ZW: frozenset[str] = frozenset({_ZWSP, "⁠", "﻿", _ZWNJ, _ZWJ}) | _BIDI_MARKS


def _is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return (
        0x1F000 <= cp <= 0x1FAFF          # emoji, incl. skin-tone modifiers
        or 0x2600 <= cp <= 0x27BF         # misc symbols, dingbats
        or cp in (0xFE0F, 0x20E3)         # emoji presentation selector, keycap
        or unicodedata.category(ch) == "So"
    )


def _is_joining_script(ch: str) -> bool:
    """Letters/marks of scripts that legitimately use ZWJ/ZWNJ (Arabic, Indic, etc.)."""
    cp = ord(ch)
    in_range = (
        0x0590 <= cp <= 0x1CFF
        or 0xA800 <= cp <= 0xABFF
        or 0xFB1D <= cp <= 0xFDFF
        or 0xFE70 <= cp <= 0xFEFC
    )
    return in_range and unicodedata.category(ch)[0] in "LM"


def _is_no_space_script(ch: str) -> bool:
    """Letters/marks of scripts written without spaces, where ZWSP marks word breaks
    (Thai, Lao, Tibetan, Myanmar, Khmer, Tai scripts, Japanese kana, CJK, Javanese, Balinese)."""
    cp = ord(ch)
    in_range = (
        0x0E00 <= cp <= 0x0FFF
        or 0x1000 <= cp <= 0x109F
        or 0x1780 <= cp <= 0x17FF
        or 0x1950 <= cp <= 0x19FF
        or 0x1A20 <= cp <= 0x1AAF
        or 0x1B00 <= cp <= 0x1B7F
        or 0x3040 <= cp <= 0x30FF
        or 0x3400 <= cp <= 0x4DBF
        or 0x4E00 <= cp <= 0x9FFF
        or 0xA980 <= cp <= 0xA9DF
    )
    return in_range and unicodedata.category(ch)[0] in "LM"


def _is_latin_letter(ch: str) -> bool:
    return ch.isalpha() and (ord(ch) < 128 or detect_script(ch) == "latin")


def _is_legitimate_zw(text: str, i: int) -> bool:
    """Everyday uses of invisible chars that shouldn't be flagged or stripped:

    - ZWJ/ZWNJ inside emoji sequences or joining scripts (Arabic, Indic, ...)
    - ZWSP between words of scripts written without spaces (Thai, Khmer, Japanese, ...)
    - soft hyphens between letters (hyphenation hints)
    - bidi marks and isolates, unless they split a Latin word
    - a leading BOM
    """
    ch = text[i]
    if ch == "﻿" and i == 0:
        return True
    if ch in _BIDI_MARKS:
        return not _is_intra_word(text, i)
    if i == 0 or i + 1 >= len(text):
        return False
    prev, nxt = text[i - 1], text[i + 1]
    if ch == _SOFT_HYPHEN:
        return prev.isalpha() and nxt.isalpha()
    if ch == _ZWSP:
        return _is_no_space_script(prev) and _is_no_space_script(nxt)
    if ch not in (_ZWJ, _ZWNJ):
        return False
    if ch == _ZWJ and _is_emoji(prev) and _is_emoji(nxt):
        return True
    return _is_joining_script(prev) and _is_joining_script(nxt)


def _neighbor(text: str, i: int, step: int) -> str:
    """Nearest char from *i* in direction *step* that isn't zero-width."""
    j = i + step
    while 0 <= j < len(text) and text[j] in ZW_SET:
        j += step
    return text[j] if 0 <= j < len(text) else ""


def _is_intra_word(text: str, i: int) -> bool:
    """Invisible char wedged between two Latin letters, e.g. 'I​gnore'."""
    return (
        text[i] in INTRA_WORD_ZW
        and _is_latin_letter(_neighbor(text, i, -1))
        and _is_latin_letter(_neighbor(text, i, 1))
    )


def _is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _is_legitimate_tag(text: str, i: int) -> bool:
    """Tag chars are only legitimate in subdivision flags (U+1F3F4 + tags + U+E007F)."""
    j = i
    while j > 0 and _is_tag(text[j - 1]):
        j -= 1
    return j > 0 and text[j - 1] == "🏴"


def _zw_name(ch: str) -> str:
    if _is_tag(ch):
        return "UNICODE TAG CHARACTER (U+E0000–E007F)"
    return ZERO_WIDTH_CHARS.get(ch, f"U+{ord(ch):04X}")


def _decode_tags(text: str, positions: list[int]) -> str:
    """Tag chars mirror ASCII (U+E0020–E007E → ' '–'~'), so hidden text decodes directly."""
    return "".join(chr(ord(text[i]) - 0xE0000) for i in positions if 0xE0020 <= ord(text[i]) <= 0xE007E)


def suspicious_zw_positions(text: str) -> list[int]:
    """Positions of invisible chars (zero-width, bidi, tags) that aren't legitimate.

    If all the zero-width chars together decode as a hidden binary message, every one
    of them is suspicious, including ones that would otherwise look like joiners.
    """
    zw = [i for i, c in enumerate(text) if c in ZW_SET]
    if len(zw) >= ZW_DECODE_MIN and _looks_like_zw_message([text[i] for i in zw]):
        flagged = set(zw)
    else:
        flagged = {i for i in zw if not _is_legitimate_zw(text, i)}
    flagged.update(i for i, c in enumerate(text) if _is_tag(c) and not _is_legitimate_tag(text, i))
    return sorted(flagged)


def _is_legitimate_vs(text: str, i: int) -> bool:
    """A single text/emoji presentation selector (VS15/VS16) after an emoji-capable base."""
    if ord(text[i]) not in (0xFE0E, 0xFE0F) or i == 0:
        return False
    prev = text[i - 1]
    if 0xFE00 <= ord(prev) <= 0xFE0F:
        return False
    return _is_emoji(prev) or prev in "#*0123456789"


def _count_visible_chars(text: str) -> int:
    """Count printable non-whitespace characters."""
    return sum(1 for c in text if not unicodedata.category(c).startswith("C") and c not in ZW_SET)


def _looks_like_zw_message(zw_chars: list[str]) -> bool:
    """Stricter than _decode_zw_binary: most decoded bytes must be printable ASCII."""
    bits = "".join("1" if c == _ZWSP else "0" for c in zw_chars if c in (_ZWSP, _ZWNJ))
    values = [int(bits[i : i + 8], 2) for i in range(0, len(bits) - 7, 8)]
    printable = sum(32 <= v < 127 for v in values)
    return printable >= 4 and printable >= 0.8 * len(values)


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
    """Find suspicious variation selector characters and their positions."""
    found = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if _is_legitimate_vs(text, i):
            continue
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

    positions = suspicious_zw_positions(text)
    zw_chars = [text[i] for i in positions]
    intra_word = [i for i in positions if _is_intra_word(text, i)]
    tags = [i for i in positions if _is_tag(text[i])]
    overrides = [i for i in positions if text[i] in BIDI_OVERRIDES]
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
            name = _zw_name(c)
            zw_types[name] = zw_types.get(name, 0) + 1

        type_summary = ", ".join(f"{v}× {k}" for k, v in list(zw_types.items())[:4])

        # Attempt to decode the hidden message
        decoded = ""
        if len(zw_chars) >= ZW_DECODE_MIN:
            decoded = _decode_zw_binary(zw_chars)
            result.decoded_message = decoded

        is_high_density = (
            result.zw_density > ZW_DENSITY_THRESHOLD and len(zw_chars) >= ZW_DENSITY_MIN_COUNT
        )
        # Many chars of mixed types suggest an encoding; stray CMS ZWSPs are one type
        many_mixed = len(zw_chars) >= ZW_DECODE_MIN and len(set(zw_chars)) >= 2

        if is_high_density or many_mixed or decoded or intra_word or tags or overrides:
            detail = (
                f"Found {len(zw_chars)} zero-width characters ({type_summary}). "
                f"Density: {result.zw_density:.1f} ZW chars per 100 visible chars."
            )
            if intra_word:
                detail += f" {len(intra_word)} split a Latin word (token-evasion pattern)."
            if tags:
                detail += f" Hidden tag-character text: {_decode_tags(text, tags)!r}"
            if overrides:
                detail += f" {len(overrides)} bidi override(s) reorder the displayed text."
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
    """Detect homoglyph tokens: Latin words with lookalike letters swapped in.

    Checked per token, so whole-script Cyrillic or Greek text is not flagged.
    """
    spans = find_suspicious_tokens(text)
    if not spans:
        return

    confusables = get_confusables()
    scripts = sorted({
        detect_script(ch) if not ("＀" <= ch <= "￯") else "fullwidth"
        for s, e in spans for ch in text[s:e]
        if ch.isalpha() and ord(ch) > 127 and detect_script(ch) != "latin"
    }) or ["non-Latin"]
    samples = [repr(text[s:e]) for s, e in spans[:6]]
    has_known = any(ch in confusables and ord(ch) > 127 for s, e in spans for ch in text[s:e])

    result.threats.append(
        Threat.from_type(
            ThreatType.HOMOGLYPH,
            detail=(
                f"Found {len(spans)} token(s) mixing Latin with {', '.join(scripts)} "
                f"confusable characters. Examples: {'; '.join(samples)}"
            ),
            technique=f"Mixed-script homoglyphs ({', '.join(scripts)})",
            outcome="normalized" if has_known else "flagged",
            location=f"{len(spans)} token(s), first at chars {spans[0][0]}–{spans[0][1]}",
        )
    )


def decode_zw_message(text: str) -> str:
    """Public helper: attempt to extract a hidden message from zero-width chars."""
    zw_chars = [text[i] for i in suspicious_zw_positions(text)]
    if len(zw_chars) < ZW_DECODE_MIN:
        return ""
    return _decode_zw_binary(zw_chars)
