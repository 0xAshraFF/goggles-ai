"""Tier 1: HTML comment and attribute injection detection.

Detects prompt injection payloads hidden in HTML comments, ARIA attributes,
data-* attributes, title/alt tags, noscript blocks, and misplaced meta tags.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment, Tag

from agentshield.models import Threat, ThreatType

# Instruction patterns common to prompt injection attacks
_INSTRUCTION_RE = re.compile(
    r"(ignore\s+(previous|above|all|prior)\s+(instructions?|prompts?|context)|"
    r"system\s*:\s*|you\s+are\s+now\s+|you\s+are\s+(a|an)\s+|"
    r"override\s+(safety|filter|restriction|all|previous|instructions?)|"
    r"\bIMPORTANT\b.*?:|instruction\s*:\s*|"
    r"disregard\s+(all|previous|above|prior)|"
    r"forget\s+(previous|above|prior|all)|"
    r"new\s+instructions?\s*:?|act\s+as\s+(if|a\s+)|"
    r"pretend\s+(to\s+be|you\s+are)|roleplay\s+as\s+|"
    r"your\s+new\s+(role|task|purpose)|"
    r"you\s+must\s+(now|immediately)|"
    r"(confidential|hidden|secret)\s+instructions?\s*:|"
    r"\[INST\]|\[SYSTEM\]|<\|system\|>|<\|user\|>|<\|im_start\|>)",
    re.IGNORECASE | re.DOTALL,
)

# Attributes that carry semantic meaning accessible to AI agents
_AGENT_READABLE_ATTRS = frozenset({
    "aria-label",
    "aria-description",
    "aria-labelledby",
    "aria-describedby",
    "aria-details",
    "aria-placeholder",
    "aria-roledescription",
    "title",
    "alt",
    "placeholder",
    "summary",
})

# Meta tags that are legitimate in <head> context
_STANDARD_META_NAMES = frozenset({
    "description", "keywords", "author", "viewport", "robots",
    "theme-color", "generator", "application-name", "referrer",
    "color-scheme", "format-detection",
})


def _looks_like_injection(text: str) -> bool:
    """Return True if text matches known prompt injection patterns."""
    return bool(_INSTRUCTION_RE.search(text))


def _is_long_suspicious(text: str, min_len: int = 30) -> bool:
    """Return True for long attribute values that are unusual for UI labels."""
    return len(text.strip()) > min_len


@dataclass
class HtmlInjectionResult:
    """Result from HTML injection analysis."""

    threats: list[Threat] = field(default_factory=list)
    comment_count: int = 0
    suspicious_attrs: list[tuple[str, str, str]] = field(default_factory=list)


def detect(html: str) -> HtmlInjectionResult:
    """Scan HTML for comment and attribute-based injection attacks.

    Args:
        html: Raw HTML string to analyse.

    Returns:
        HtmlInjectionResult with detected threats.
    """
    result = HtmlInjectionResult()

    if not html or not html.strip():
        return result

    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return result

    _check_html_comments(soup, result)
    _check_agent_readable_attrs(soup, result)
    _check_data_attrs(soup, result)
    _check_meta_injection(soup, result)
    _check_noscript_blocks(soup, result)

    return result


def _check_html_comments(soup: BeautifulSoup, result: HtmlInjectionResult) -> None:
    """Check all HTML comments for injection payloads."""
    comments = soup.find_all(string=lambda t: isinstance(t, Comment))
    result.comment_count = len(comments)

    flagged = []
    for comment in comments:
        text = str(comment).strip()
        if _looks_like_injection(text):
            flagged.append(text)

    if flagged:
        samples = [f[:120] for f in flagged[:3]]
        result.threats.append(
            Threat.from_type(
                ThreatType.HTML_COMMENT_INJECTION,
                detail=(
                    f"Found {len(flagged)} HTML comment(s) containing injection patterns. "
                    f"Sample: {samples[0]!r}"
                ),
                technique=f"HTML comment injection ({len(flagged)} comment(s))",
                outcome="stripped",
                location="HTML comment nodes",
            )
        )


def _check_agent_readable_attrs(soup: BeautifulSoup, result: HtmlInjectionResult) -> None:
    """Check aria-label, title, alt, and related attributes."""
    flagged: list[tuple[str, str, str]] = []

    for element in soup.find_all(True):
        for attr in _AGENT_READABLE_ATTRS:
            val = element.get(attr, "")
            if not val or not isinstance(val, str):
                continue
            val = val.strip()
            if _looks_like_injection(val) or (
                _is_long_suspicious(val, 80) and not _value_looks_legitimate(val, attr)
            ):
                tag_id = element.get("id") or element.get("class") or element.name
                flagged.append((f"<{element.name} {attr}=...>", attr, val[:120]))
                result.suspicious_attrs.append((str(tag_id), attr, val[:120]))

    if flagged:
        sample_loc, sample_attr, sample_val = flagged[0]
        result.threats.append(
            Threat.from_type(
                ThreatType.ARIA_ATTRIBUTE_INJECTION,
                detail=(
                    f"Found {len(flagged)} element(s) with suspicious {sample_attr} "
                    f"and similar attributes. Sample ({sample_loc}): {sample_val!r}"
                ),
                technique=f"ARIA/attribute injection in {', '.join(set(a for _, a, _ in flagged[:5]))}",
                outcome="stripped",
                location=", ".join(loc for loc, _, _ in flagged[:3]),
            )
        )


def _value_looks_legitimate(value: str, attr: str) -> bool:
    """Heuristic: return True if a long attribute value looks like normal UI text."""
    # Short sentences without imperative patterns are usually legit
    if re.match(r'^[\w\s,.\-/:()]{1,120}$', value):
        return True
    return False


def _check_data_attrs(soup: BeautifulSoup, result: HtmlInjectionResult) -> None:
    """Check data-* attributes for injection payloads."""
    flagged: list[tuple[str, str, str]] = []

    for element in soup.find_all(True):
        for attr, val in element.attrs.items():
            if not attr.startswith("data-"):
                continue
            if not isinstance(val, str):
                continue
            val = val.strip()
            if _looks_like_injection(val):
                flagged.append((f"<{element.name}>", attr, val[:120]))

    if flagged:
        sample_loc, sample_attr, sample_val = flagged[0]
        result.threats.append(
            Threat.from_type(
                ThreatType.ARIA_ATTRIBUTE_INJECTION,
                detail=(
                    f"Found {len(flagged)} data-* attribute(s) containing injection patterns. "
                    f"Sample: <{sample_loc} {sample_attr}={sample_val!r}>"
                ),
                technique=f"data-* attribute injection ({len(flagged)} instances)",
                outcome="stripped",
                location=", ".join(f"{loc} [{a}]" for loc, a, _ in flagged[:3]),
            )
        )


def _check_meta_injection(soup: BeautifulSoup, result: HtmlInjectionResult) -> None:
    """Detect <meta> tags placed outside <head> or with non-standard content."""
    flagged = []

    head = soup.find("head")
    body = soup.find("body")

    # Meta tags in body — abnormal
    for meta in soup.find_all("meta"):
        parent = meta.parent
        is_in_body = body and body in (meta.parents)
        is_in_head = head and head in (meta.parents)

        content = meta.get("content", "")
        name = (meta.get("name") or meta.get("property") or "").lower()

        if is_in_body and not is_in_head:
            if content and _looks_like_injection(content):
                flagged.append(f"body <meta name={name!r} content={content[:80]!r}>")
        elif content and name not in _STANDARD_META_NAMES and _looks_like_injection(content):
            flagged.append(f"<meta name={name!r} content={content[:80]!r}>")

    if flagged:
        result.threats.append(
            Threat.from_type(
                ThreatType.META_INJECTION,
                detail=(
                    f"Found {len(flagged)} suspicious <meta> tag(s). Sample: {flagged[0]}"
                ),
                technique="Meta tag content injection",
                outcome="stripped",
                location="<meta> tags",
            )
        )


def _check_noscript_blocks(soup: BeautifulSoup, result: HtmlInjectionResult) -> None:
    """Check <noscript> blocks for injection payloads."""
    flagged = []

    for ns in soup.find_all("noscript"):
        text = ns.get_text(separator=" ", strip=True)
        if not text:
            # Check inner HTML for hidden elements
            inner_html = str(ns)
            text = inner_html

        if _looks_like_injection(text) or _is_long_suspicious(text, 100):
            flagged.append(text[:120])

    if flagged:
        result.threats.append(
            Threat.from_type(
                ThreatType.NOSCRIPT_INJECTION,
                detail=(
                    f"Found {len(flagged)} <noscript> block(s) containing injection patterns. "
                    f"Sample: {flagged[0]!r}"
                ),
                technique="NoScript block injection (targets JS-disabled agents)",
                outcome="stripped",
                location="<noscript> blocks",
            )
        )
