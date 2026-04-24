"""HTML sanitizer: strips hidden elements, suspicious attributes, and injected comments."""

from __future__ import annotations

import re

from bs4 import BeautifulSoup, Comment, Tag

from goggles_ai.detectors.css_hidden_text import _check_style_dict, _parse_inline_style, _parse_style_block, _element_matches

# Attributes safe to keep on visible elements
_SAFE_ATTRS = frozenset({
    "href", "src", "alt", "title", "id", "class", "type", "name",
    "value", "placeholder", "action", "method", "target", "rel",
    "width", "height", "colspan", "rowspan", "for", "role",
})

# Attributes to always strip (may carry hidden payloads)
_STRIP_ATTRS = frozenset({
    "aria-description", "aria-details", "data-prompt", "data-instruction",
    "data-system", "data-ai", "data-llm",
})

_INSTRUCTION_RE = re.compile(
    r"(ignore\s+(previous|above|all|prior)\s+(instructions?|prompts?)|"
    r"system\s*:\s*|you\s+are\s+(now|a\s)|override\s+(safety|filter)|"
    r"IMPORTANT\s*:|disregard|forget\s+previous|act\s+as\s+|pretend\s+to\s+be)",
    re.IGNORECASE | re.DOTALL,
)


def sanitize(html: str) -> str:
    """Remove hidden elements and suspicious attributes from HTML.

    Args:
        html: Raw HTML string to clean.

    Returns:
        Sanitized HTML string with threats removed.
    """
    if not html or not html.strip():
        return html

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return html

    # Build CSS rule map
    style_rules: dict[str, dict[str, str]] = {}
    for style_tag in soup.find_all("style"):
        text = style_tag.get_text() if style_tag else ""
        if text:
            style_rules.update(_parse_style_block(text))

    elements_to_remove: list[Tag] = []

    for element in soup.find_all(True):
        if element.name in ("style", "script", "head", "meta", "link"):
            continue

        # Collect applied CSS
        props: dict[str, str] = {}
        for selector, rule_props in style_rules.items():
            try:
                if _element_matches(element, selector):
                    props.update(rule_props)
            except Exception:
                pass
        inline = element.get("style", "")
        if inline:
            props.update(_parse_inline_style(inline))

        # Remove elements that are visually hidden
        if props and _check_style_dict(props):
            elements_to_remove.append(element)
            continue

        # Strip suspicious attributes
        _clean_element_attrs(element)

    for el in elements_to_remove:
        try:
            el.decompose()
        except Exception:
            pass

    # Remove HTML comments
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        comment.extract()

    # Remove noscript blocks with injected content
    for ns in soup.find_all("noscript"):
        text = ns.get_text(separator=" ", strip=True)
        if text and _INSTRUCTION_RE.search(text):
            ns.decompose()

    # Remove misplaced meta tags in body with suspicious content
    body = soup.find("body")
    if body:
        for meta in body.find_all("meta"):
            content = meta.get("content", "")
            if content and _INSTRUCTION_RE.search(content):
                meta.decompose()

    return str(soup)


def _clean_element_attrs(element: Tag) -> None:
    """Strip suspicious or instruction-bearing attributes from an element."""
    attrs_to_remove = []
    for attr, val in list(element.attrs.items()):
        val_str = val if isinstance(val, str) else " ".join(val) if isinstance(val, list) else ""

        # Always strip known bad attrs
        if attr in _STRIP_ATTRS:
            attrs_to_remove.append(attr)
            continue

        # Strip data-* attrs with instruction patterns
        if attr.startswith("data-") and val_str and _INSTRUCTION_RE.search(val_str):
            attrs_to_remove.append(attr)
            continue

        # Strip aria-* and title/alt with instruction patterns
        if attr in ("aria-label", "aria-description", "title", "alt", "placeholder"):
            if val_str and _INSTRUCTION_RE.search(val_str):
                attrs_to_remove.append(attr)

    for attr in attrs_to_remove:
        del element[attr]
