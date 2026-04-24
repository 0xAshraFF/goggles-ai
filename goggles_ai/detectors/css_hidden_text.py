"""Tier 1: CSS-based hidden text detection.

Detects content invisible to human viewers but readable by AI agents:
display:none, visibility:hidden, opacity:0, font-size:0, colour matching,
extreme off-screen positioning, clip-rect tricks, and height/width:0.

Also resolves class/ID-based CSS rules from <style> blocks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from bs4 import BeautifulSoup, Tag

from goggles_ai.models import Threat, ThreatType

# Regex matching prompt-injection payloads inside hidden text
_INSTRUCTION_RE = re.compile(
    r"(ignore\s+(previous|above|all|prior)\s+(instructions?|prompts?|context)|"
    r"system\s*:\s*|you\s+are\s+now\s+|you\s+are\s+a\s+|"
    r"override\s+(safety|filter|restriction|all|previous)|"
    r"IMPORTANT\s*:\s*|instruction\s*:\s*|"
    r"disregard\s+(all|previous|above|prior)|"
    r"forget\s+(previous|above|prior|all)|"
    r"new\s+instructions?\s*:|act\s+as\s+(if|a\s+)|"
    r"pretend\s+(to\s+be|you\s+are)|roleplay\s+as\s+|"
    r"your\s+new\s+role|your\s+task\s+is|"
    r"you\s+must\s+(now|immediately)|"
    r"confidential\s+instructions?\s*:|"
    r"hidden\s+instructions?\s*:|secret\s+instructions?\s*:)",
    re.IGNORECASE | re.DOTALL,
)

# CSS properties that hide elements from visual rendering
_HIDING_CHECKS = {
    "display": lambda v: v.strip().lower() == "none",
    "visibility": lambda v: v.strip().lower() == "hidden",
    "opacity": lambda v: _parse_numeric(v) == 0.0,
    "font-size": lambda v: v.strip().lower() in ("0", "0px", "0pt", "0em", "0rem", "0vw", "0vh"),
}


def _parse_numeric(value: str) -> Optional[float]:
    """Extract the numeric portion from a CSS value string."""
    m = re.match(r"^\s*([+-]?\d+(?:\.\d+)?)", value.strip())
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _parse_px(value: str) -> Optional[float]:
    """Return the pixel value of a CSS length, or None if not parseable."""
    v = value.strip().lower()
    if v.endswith("px"):
        return _parse_numeric(v[:-2])
    if v in ("0", "auto", "inherit", "initial", "unset"):
        return 0.0 if v == "0" else None
    return None


def _normalize_color(value: str) -> str:
    """Normalise a CSS color string for equality comparison."""
    return re.sub(r"\s+", "", value.strip().lower())


def _check_style_dict(props: dict[str, str]) -> list[str]:
    """Return a list of hiding techniques found in a dict of CSS properties."""
    techniques: list[str] = []

    for prop, checker in _HIDING_CHECKS.items():
        if prop in props and checker(props[prop]):
            techniques.append(f"{prop}:{props[prop].strip()}")

    # color == background-color
    color = _normalize_color(props.get("color", ""))
    bg = _normalize_color(props.get("background-color", props.get("background", "")))
    if color and bg and color == bg and color not in ("transparent", "inherit", "initial"):
        techniques.append("color==background-color")

    # position:absolute|fixed + extreme offset
    pos = props.get("position", "").strip().lower()
    if pos in ("absolute", "fixed"):
        left = _parse_px(props.get("left", "0"))
        top = _parse_px(props.get("top", "0"))
        right = _parse_px(props.get("right", "0"))
        bottom = _parse_px(props.get("bottom", "0"))
        for name, val in (("left", left), ("top", top), ("right", right), ("bottom", bottom)):
            if val is not None and abs(val) > 9999:
                techniques.append(f"position:{pos}+extreme-{name}({val}px)")

    # text-indent: extreme negative (≤ -9999 or ≤ -999 as common attack threshold)
    indent = _parse_px(props.get("text-indent", "0"))
    if indent is not None and indent <= -9999:
        techniques.append(f"text-indent:{int(indent)}px")

    # height:0 or width:0 with overflow hidden/clip
    overflow = props.get("overflow", props.get("overflow-y", "")).strip().lower()
    height = _parse_px(props.get("height", "auto"))
    width = _parse_px(props.get("width", "auto"))
    if overflow in ("hidden", "clip") and height == 0.0:
        techniques.append("height:0+overflow:hidden")
    if overflow in ("hidden", "clip") and width == 0.0:
        techniques.append("width:0+overflow:hidden")

    # clip: rect(0,0,0,0)
    clip = re.sub(r"\s+", "", props.get("clip", "")).lower()
    if "rect(0,0,0,0)" in clip or "rect(0px,0px,0px,0px)" in clip:
        techniques.append("clip:rect(0,0,0,0)")

    return techniques


def _parse_inline_style(style_str: str) -> dict[str, str]:
    """Parse an inline CSS style string into a property dict."""
    props: dict[str, str] = {}
    for part in style_str.split(";"):
        if ":" in part:
            key, _, val = part.partition(":")
            key = key.strip().lower()
            # Strip !important flag before storing
            val = re.sub(r"\s*!important\s*$", "", val.strip()).strip()
            if key:
                props[key] = val
    return props


def _parse_style_block(css_text: str) -> dict[str, dict[str, str]]:
    """Parse a CSS <style> block into {selector: {property: value}}.

    Handles simple selectors: .class, #id, tag, tag.class, [attr] — ignores
    complex combinators and pseudo-classes for performance.
    """
    rules: dict[str, dict[str, str]] = {}

    # Strip comments
    css_text = re.sub(r"/\*.*?\*/", "", css_text, flags=re.DOTALL)

    for match in re.finditer(r"([^{@][^{]*)\{([^}]+)\}", css_text):
        raw_selectors = match.group(1).strip()
        props = _parse_inline_style(match.group(2).replace(";", ";"))

        for selector in raw_selectors.split(","):
            sel = selector.strip()
            if sel:
                if sel not in rules:
                    rules[sel] = {}
                rules[sel].update(props)

    return rules


def _element_matches(element: Tag, selector: str) -> bool:
    """Check whether an element matches a simple CSS selector."""
    sel = selector.strip()

    # Strip pseudo-elements and pseudo-classes
    sel = re.split(r"::?[\w-]+", sel)[0].strip()
    if not sel:
        return False

    # Descendant/child combinators — skip complex selectors
    if re.search(r"[\s>+~]", sel):
        return False

    # #id
    if sel.startswith("#"):
        return element.get("id") == sel[1:]

    # .class
    if sel.startswith("."):
        return sel[1:] in (element.get("class") or [])

    # tag.class
    if "." in sel and not sel.startswith("."):
        tag_part, _, cls_part = sel.partition(".")
        return (
            element.name == tag_part.lower()
            and cls_part in (element.get("class") or [])
        )

    # tag#id
    if "#" in sel and not sel.startswith("#"):
        tag_part, _, id_part = sel.partition("#")
        return element.name == tag_part.lower() and element.get("id") == id_part

    # Bare tag name
    if element.name and sel.lower() == element.name.lower():
        return True

    # [attribute] or [attribute=value]
    attr_match = re.match(r'^\[(\w[\w-]*)(?:=["\']?([^"\']+)["\']?)?\]$', sel)
    if attr_match:
        attr_name = attr_match.group(1)
        attr_val = attr_match.group(2)
        elem_val = element.get(attr_name)
        if attr_val is None:
            return elem_val is not None
        return elem_val == attr_val

    return False


@dataclass
class CssHiddenTextResult:
    """Result from CSS hidden text analysis."""

    threats: list[Threat] = field(default_factory=list)
    hidden_texts: list[str] = field(default_factory=list)


def detect(html: str) -> CssHiddenTextResult:
    """Scan HTML for CSS-hidden text containing prompt injection payloads.

    Args:
        html: Raw HTML string to analyse.

    Returns:
        CssHiddenTextResult with any detected threats.
    """
    result = CssHiddenTextResult()

    if not html or not html.strip():
        return result

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return result

    # Build CSS rule map from <style> blocks
    style_rules: dict[str, dict[str, str]] = {}
    for style_tag in soup.find_all("style"):
        text = style_tag.get_text() if style_tag else ""
        if text:
            style_rules.update(_parse_style_block(text))

    def _get_applied_props(element: Tag) -> dict[str, str]:
        """Merge inline style + matching CSS rules for an element."""
        props: dict[str, str] = {}
        # Apply CSS rules first (lower specificity)
        for selector, rule_props in style_rules.items():
            try:
                if _element_matches(element, selector):
                    props.update(rule_props)
            except Exception:
                pass
        # Inline style overrides
        inline = element.get("style", "")
        if inline:
            props.update(_parse_inline_style(inline))
        return props

    seen_texts: set[str] = set()

    for element in soup.find_all(True):
        if element.name in ("style", "script", "head", "meta", "link"):
            continue

        props = _get_applied_props(element)
        if not props:
            continue

        techniques = _check_style_dict(props)
        if not techniques:
            continue

        text = element.get_text(separator=" ", strip=True)
        if not text or len(text) < 3:
            continue

        # Deduplicate by (technique, text) to avoid redundant parent/child reports
        key = (tuple(sorted(techniques)), text[:80])
        if key in seen_texts:
            continue
        seen_texts.add(key)

        result.hidden_texts.append(text)

        technique_str = ", ".join(techniques)
        has_payload = bool(_INSTRUCTION_RE.search(text))
        severity_bump = "critical" if has_payload else None

        detail = (
            f"Element <{element.name}> hidden via {technique_str}. "
            f"Hidden text ({len(text)} chars): {text[:120]!r}"
            + (" — contains prompt injection pattern" if has_payload else "")
        )

        selector_hint = ""
        if element.get("id"):
            selector_hint = f"#{element['id']}"
        elif element.get("class"):
            cls = element["class"]
            selector_hint = f".{cls[0]}" if isinstance(cls, list) else f".{cls}"
        else:
            selector_hint = f"<{element.name}>"

        threat = Threat.from_type(
            ThreatType.CSS_HIDDEN_TEXT,
            detail=detail,
            technique=technique_str,
            outcome="stripped",
            location=selector_hint,
        )
        if severity_bump:
            threat = threat.model_copy(update={"severity": severity_bump})

        result.threats.append(threat)

    return result
