"""Unicode confusables database and homoglyph normalization utilities.

Covers the most common Latin–Cyrillic and Latin–Greek visual confusables used
in homoglyph attacks. This is a curated subset; the full Unicode confusables.txt
(~7500 entries) can be loaded via load_full_confusables() if the file is present.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from pathlib import Path


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
    "ǐ": "i",   # ǐ LATIN SMALL I WITH CARON
    "ı": "i",   # ı LATIN SMALL DOTLESS I
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
    """Return the full confusables mapping, augmenting with any local file."""
    mapping = dict(CONFUSABLES)

    confusables_path = Path(__file__).parent / "confusables.txt"
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
    """Replace known confusable characters with their ASCII equivalents.

    Args:
        text: Input string potentially containing homoglyph attacks.

    Returns:
        Normalized string with confusables replaced by ASCII equivalents.
    """
    mapping = get_confusables()
    result = []
    for ch in text:
        result.append(mapping.get(ch, ch))
    return "".join(result)


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
