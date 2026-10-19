"""Unicode confusables database and homoglyph normalization utilities.

Covers the most common Latin–Cyrillic and Latin–Greek visual confusables used
in homoglyph attacks. This is a curated subset; the full Unicode confusables.txt
is subset to ASCII targets in confusables_ascii.txt (tools/build_confusables.py)
and merged in at load time.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Optional

# Curated high-risk confusables: char → ASCII equivalent
# Cyrillic characters that look like Latin letters
_CYRILLIC_TO_LATIN: dict[str, str] = {
    "А": "A",  # А CYRILLIC CAPITAL A
    "а": "a",  # а CYRILLIC SMALL A
    "В": "B",  # В CYRILLIC CAPITAL VE
    "С": "C",  # С CYRILLIC CAPITAL ES
    "с": "c",  # с CYRILLIC SMALL ES
    "Д": "D",  # Д (partial — looks like D)
    "Е": "E",  # Е CYRILLIC CAPITAL IE
    "е": "e",  # е CYRILLIC SMALL IE
    "Ё": "E",  # Ё CYRILLIC CAPITAL IO
    "ё": "e",  # ё CYRILLIC SMALL IO
    "Н": "H",  # Н CYRILLIC CAPITAL EN
    "И": "I",  # И (partial)
    "Й": "J",  # Й (partial)
    "К": "K",  # К CYRILLIC CAPITAL KA
    "М": "M",  # М CYRILLIC CAPITAL EM
    "О": "O",  # О CYRILLIC CAPITAL O
    "о": "o",  # о CYRILLIC SMALL O
    "Р": "P",  # Р CYRILLIC CAPITAL ER
    "р": "p",  # р CYRILLIC SMALL ER
    "Т": "T",  # Т CYRILLIC CAPITAL TE
    "Х": "X",  # Х CYRILLIC CAPITAL HA
    "х": "x",  # х CYRILLIC SMALL HA
    "У": "Y",  # У CYRILLIC CAPITAL U (looks like Y)
    "у": "y",  # у CYRILLIC SMALL U
    "в": "B",  # в CYRILLIC SMALL VE (looks like 6 or B)
    "Ѕ": "S",  # Ѕ CYRILLIC CAPITAL DZE
    "І": "I",  # І CYRILLIC CAPITAL BYELORUSSIAN-UKRAINIAN I
    "Ј": "J",  # Ј CYRILLIC CAPITAL JE
    "Һ": "H",  # Һ CYRILLIC CAPITAL SHHA
    "һ": "h",  # һ CYRILLIC SMALL SHHA
    "Ԛ": "Q",  # Ԛ CYRILLIC CAPITAL QA
    "ԛ": "q",  # ԛ CYRILLIC SMALL QA
    "Ԝ": "W",  # Ԝ CYRILLIC CAPITAL WE
    "ԝ": "w",  # ԝ CYRILLIC SMALL WE
    "ѕ": "s",  # ѕ CYRILLIC SMALL DZE
    "і": "i",  # і CYRILLIC SMALL I
    "ј": "j",  # ј CYRILLIC SMALL JE
    "љ": "љ",  # not ASCII but common confusable
    "њ": "њ",
    "ѡ": "w",  # ѡ CYRILLIC SMALL OMEGA
    "Ҁ": "o",  # Ѿ (partial)
    "ӏ": "i",  # ӏ CYRILLIC SMALL PALOCHKA
    "հ": "h",  # հ ARMENIAN SMALL HO
    "ց": "p",  # փ ARMENIAN SMALL PEH
}

# Greek characters that look like Latin letters
_GREEK_TO_LATIN: dict[str, str] = {
    "Α": "A",  # Α GREEK CAPITAL ALPHA
    "Β": "B",  # Β GREEK CAPITAL BETA
    "Ε": "E",  # Ε GREEK CAPITAL EPSILON
    "Ζ": "Z",  # Ζ GREEK CAPITAL ZETA
    "Η": "H",  # Η GREEK CAPITAL ETA
    "Ι": "I",  # Ι GREEK CAPITAL IOTA
    "Κ": "K",  # Κ GREEK CAPITAL KAPPA
    "Μ": "M",  # Μ GREEK CAPITAL MU
    "Ν": "N",  # Ν GREEK CAPITAL NU
    "Ο": "O",  # Ο GREEK CAPITAL OMICRON
    "ο": "o",  # ο GREEK SMALL OMICRON
    "Ρ": "P",  # Ρ GREEK CAPITAL RHO
    "Τ": "T",  # Τ GREEK CAPITAL TAU
    "Υ": "Y",  # Υ GREEK CAPITAL UPSILON
    "Χ": "X",  # Χ GREEK CAPITAL CHI
    "ν": "v",  # ν GREEK SMALL NU
    "ρ": "p",  # ρ GREEK SMALL RHO
    "κ": "k",  # κ GREEK SMALL KAPPA
    "υ": "u",  # υ GREEK SMALL UPSILON
    "ι": "i",  # ι GREEK SMALL IOTA
    "χ": "x",  # χ GREEK SMALL CHI
}

# Additional lookalikes from various scripts
_OTHER_CONFUSABLES: dict[str, str] = {
    "ɡ": "g",   # ɡ LATIN SMALL SCRIPT G
    "ʌ": "v",   # ʌ LATIN SMALL TURNED V
    "ʀ": "r",   # ʀ LATIN LETTER SMALL CAPITAL R
    "ᴀ": "a",   # ᴀ LATIN LETTER SMALL CAPITAL A
    "ᴇ": "e",   # ᴇ LATIN LETTER SMALL CAPITAL E
    "ᴜ": "u",   # ᴜ LATIN LETTER SMALL CAPITAL U
    "ⲟ": "O",   # Ⲟ COPTIC CAPITAL LETTER O
    "Ⲟ": "O",   # Ⲏ partial
    "ａ": "a",   # ａ FULLWIDTH LATIN SMALL A
    "ｂ": "b",   # ｂ FULLWIDTH LATIN SMALL B
    "ｃ": "c",   # ｃ FULLWIDTH
    "ｄ": "d",   # ｄ
    "ｅ": "e",   # ｅ
    "ｆ": "f",   # ｆ
    "ｇ": "g",   # ｇ
    "ｈ": "h",   # ｈ
    "ｉ": "i",   # ｉ
    "ｊ": "j",   # ｊ
    "ｋ": "k",   # ｋ
    "ｌ": "l",   # ｌ
    "ｍ": "m",   # ｍ
    "ｎ": "n",   # ｎ
    "ｏ": "o",   # ｏ
    "ｐ": "p",   # ｐ
    "ｑ": "q",   # ｑ
    "ｒ": "r",   # ｒ
    "ｓ": "s",   # ｓ
    "ｔ": "t",   # ｔ
    "ｕ": "u",   # ｕ
    "ｖ": "v",   # ｖ
    "ｗ": "w",   # ｗ
    "ｘ": "x",   # ｘ
    "ｙ": "y",   # ｙ
    "ｚ": "z",   # ｚ
    "Ａ": "A",   # Ａ FULLWIDTH LATIN CAPITAL A
    "Ｂ": "B",   # Ｂ
    "Ｃ": "C",   # Ｃ
    "Ｄ": "D",   # Ｄ
    "Ｅ": "E",   # Ｅ
    "Ｆ": "F",   # Ｆ
    "Ｇ": "G",   # Ｇ
    "Ｈ": "H",   # Ｈ
    "Ｉ": "I",   # Ｉ
    "Ｊ": "J",   # Ｊ
    "Ｋ": "K",   # Ｋ
    "Ｌ": "L",   # Ｌ
    "Ｍ": "M",   # Ｍ
    "Ｎ": "N",   # Ｎ
    "Ｏ": "O",   # Ｏ
    "Ｐ": "P",   # Ｐ
    "Ｑ": "Q",   # Ｑ
    "Ｒ": "R",   # Ｒ
    "Ｓ": "S",   # Ｓ
    "Ｔ": "T",   # Ｔ
    "Ｕ": "U",   # Ｕ
    "Ｖ": "V",   # Ｖ
    "Ｗ": "W",   # Ｗ
    "Ｘ": "X",   # Ｘ
    "Ｙ": "Y",   # Ｙ
    "Ｚ": "Z",   # Ｚ
}

# Merged confusables map
CONFUSABLES: dict[str, str] = {
    **_CYRILLIC_TO_LATIN,
    **_GREEK_TO_LATIN,
    **_OTHER_CONFUSABLES,
}

# Script blocks used to identify mixed-script text
SCRIPT_RANGES: dict[str, tuple[int, int]] = {
    "latin": (0x0041, 0x024F),
    "cyrillic": (0x0400, 0x04FF),
    "greek": (0x0370, 0x03FF),
    "armenian": (0x0530, 0x058F),
    "georgian": (0x10A0, 0x10FF),
    "arabic": (0x0600, 0x06FF),
    "hebrew": (0x0590, 0x05FF),
    "cjk": (0x4E00, 0x9FFF),
}


@lru_cache(maxsize=1)
def get_confusables() -> dict[str, str]:
    """Return the curated map merged with the bundled TR39 ASCII subset."""
    mapping = dict(CONFUSABLES)

    confusables_path = Path(__file__).parent / "confusables_ascii.txt"
    if confusables_path.exists():
        _load_unicode_confusables_txt(confusables_path, mapping)

    return mapping


def _load_unicode_confusables_txt(path: Path, mapping: dict[str, str]) -> None:
    """Parse Unicode confusables.txt and add entries to mapping."""
    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(";")
                if len(parts) < 2:
                    continue
                src_hex = parts[0].strip()
                dst_hex = parts[1].strip()
                try:
                    src_char = chr(int(src_hex, 16))
                    dst_char = chr(int(dst_hex.split()[0], 16))
                    # Only map to ASCII
                    if ord(dst_char) < 128 and src_char not in mapping:
                        mapping[src_char] = dst_char
                except (ValueError, IndexError):
                    continue
    except OSError:
        pass


def normalize_text(text: str) -> str:
    """Replace confusable characters with ASCII equivalents inside suspicious tokens.

    Only tokens flagged by find_suspicious_tokens() are rewritten, so legitimate
    Cyrillic, Greek, or fullwidth text is left untouched.

    Args:
        text: Input string potentially containing homoglyph attacks.

    Returns:
        Normalized string with confusables replaced by ASCII equivalents.
    """
    mapping = get_confusables()
    spans = find_suspicious_tokens(text)
    if not spans:
        return text
    out: list[str] = []
    last = 0
    for start, end in spans:
        out.append(text[last:start])
        out.append("".join(mapping.get(ch, ch) for ch in text[start:end]))
        last = end
    out.append(text[last:])
    return "".join(out)


# Scripts whose letters are used to impersonate Latin inside a word
_LOOKALIKE_SCRIPTS = frozenset({"cyrillic", "greek", "armenian", "georgian"})


def _is_fullwidth_latin(ch: str) -> bool:
    return 0xFF21 <= ord(ch) <= 0xFF3A or 0xFF41 <= ord(ch) <= 0xFF5A


def _is_token_char(ch: str) -> bool:
    # Letters, marks, digits, and invisible format chars (so "I​gnore" is one token)
    return unicodedata.category(ch)[0] in "LMN" or unicodedata.category(ch) == "Cf"


def _tokens(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = None
    for i, ch in enumerate(text):
        if _is_token_char(ch):
            if start is None:
                start = i
        elif start is not None:
            spans.append((start, i))
            start = None
    if start is not None:
        spans.append((start, len(text)))
    return spans


def _units(text: str) -> list[tuple[int, int]]:
    """Tokens, with letter-spaced runs ("S a y t h a t", 3+ single letters) merged into one."""
    units: list[tuple[int, int]] = []
    run: list[tuple[int, int]] = []

    def flush() -> None:
        if len(run) >= 3:
            units.append((run[0][0], run[-1][1]))
        else:
            units.extend(run)
        run.clear()

    for start, end in _tokens(text):
        single = sum(ch.isalpha() for ch in text[start:end]) == 1
        if single and run and text[run[-1][1]:start] == " ":
            run.append((start, end))
            continue
        flush()
        if single:
            run.append((start, end))
        else:
            units.append((start, end))
    flush()
    return units


def _latin_dominant(text: str) -> bool:
    """True if at least half the letters in *text* are Latin (fullwidth Latin counts)."""
    latin = total = 0
    for ch in text:
        if not ch.isalpha():
            continue
        total += 1
        if detect_script(ch) == "latin" or _is_fullwidth_latin(ch):
            latin += 1
    return total > 0 and latin * 2 >= total


def find_suspicious_tokens(text: str) -> list[tuple[int, int]]:
    """Return (start, end) spans of tokens that look like homoglyph attacks.

    A token is suspicious when it:
      - mixes Latin letters with confusables or lookalike-script letters
        ("pаypal" with Cyrillic а), or
      - consists only of 2+ non-ASCII confusables while the surrounding text is
        predominantly Latin ("The ΑΙ system", fullwidth "ｉｇｎｏｒｅ").

    Short Greek+Latin symbols (μm, Δx, μmol) and single letters (α, Ω) are exempt,
    except inside letter-spaced runs ("S а y"), which are checked as one word.

    Whole-script text such as a Russian or Greek sentence is not flagged.
    """
    mapping = get_confusables()
    latin_context: Optional[bool] = None
    spans: list[tuple[int, int]] = []

    for start, end in _units(text):
        letters = [ch for ch in text[start:end] if ch.isalpha()]
        if not letters:
            continue
        has_latin = any(ord(ch) < 128 or (detect_script(ch) == "latin" and ch not in mapping)
                        for ch in letters)
        foreign = [ch for ch in letters
                   if (ord(ch) > 127 and ch in mapping) or detect_script(ch) in _LOOKALIKE_SCRIPTS]
        if not foreign:
            continue
        if has_latin:
            # Short Greek+Latin symbols are scientific notation (μm, Δx, πr), not attacks
            if len(letters) <= 3 and all(detect_script(ch) == "greek" for ch in foreign):
                continue
            # Micro prefix on a unit: μmol, μg
            if foreign == ["μ"] and letters[0] == "μ" and len(letters) <= 4:
                continue
            spans.append((start, end))
            continue
        # Single letters are variables or symbols (α, β, Ω), not disguised words
        if len(letters) >= 2 and all(ord(ch) > 127 and ch in mapping for ch in letters):
            if latin_context is None:
                latin_context = _latin_dominant(text)
            if latin_context:
                spans.append((start, end))
    return spans


def detect_script(char: str) -> str:
    """Return the Unicode script block name for a single character."""
    cp = ord(char)
    for script, (lo, hi) in SCRIPT_RANGES.items():
        if lo <= cp <= hi:
            return script
    cat = unicodedata.category(char)
    if cat.startswith("L"):
        return "other_letter"
    return "other"


def find_mixed_scripts(text: str) -> set[str]:
    """Return the set of distinct non-Latin scripts present in a Latin text.

    Only reports scripts that appear mixed in with Latin characters — purely
    non-Latin text (e.g. legitimate Arabic) is not flagged.
    """
    scripts: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        s = detect_script(ch)
        if s not in ("latin", "other", "other_letter"):
            scripts.add(s)

    # Only flag as mixed if we also have Latin characters
    has_latin = any(detect_script(ch) == "latin" for ch in text if ch.isalpha())
    if not has_latin:
        return set()

    return scripts
