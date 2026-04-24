"""Tier 1: Dynamic content cloaking detection.

Fetches a URL twice — once with a legitimate browser user-agent and once with
an automation/bot user-agent — then compares the resulting DOMs. Significant
divergence indicates that the server is delivering different content to AI
agents than to human visitors.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from goggles_ai.models import Threat, ThreatType

logger = logging.getLogger(__name__)

# User-agents
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_BOT_UA = (
    "Mozilla/5.0 (compatible; python-httpx/0.27; +https://github.com/0xAshraFF/goggles-ai)"
)

_HEADLESS_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "HeadlessChrome/124.0.0.0 Safari/537.36"
)

# Minimum content divergence (0–1) that triggers a cloaking flag
DIVERGENCE_THRESHOLD = 0.05

# Request timeout in seconds
REQUEST_TIMEOUT = 10


@dataclass
class CloakingResult:
    """Result from cloaking detection."""

    threats: list[Threat] = field(default_factory=list)
    human_content: str = ""
    agent_content: str = ""
    divergence_score: float = 0.0
    agent_exclusive_text: list[str] = field(default_factory=list)


def detect(
    url: str,
    session: Optional[requests.Session] = None,
    browser_ua: str = _BROWSER_UA,
    bot_ua: str = _BOT_UA,
) -> CloakingResult:
    """Fetch *url* with two different user-agents and compare responses.

    Args:
        url: Target URL to check for cloaking.
        session: Optional requests.Session (used for testing / mocking).
        browser_ua: User-Agent string used for the "human" request.
        bot_ua: User-Agent string used for the "agent/bot" request.

    Returns:
        CloakingResult with divergence score and any detected threats.
    """
    result = CloakingResult()

    if not url:
        return result

    # Basic URL validation
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return result
    except Exception:
        return result

    s = session or requests.Session()

    human_html = _fetch(s, url, browser_ua)
    agent_html = _fetch(s, url, bot_ua)

    if not human_html or not agent_html:
        return result

    result.human_content = human_html
    result.agent_content = agent_html

    # Compare the two responses
    divergence, agent_exclusive = _compare_content(human_html, agent_html)
    result.divergence_score = divergence
    result.agent_exclusive_text = agent_exclusive

    if divergence >= DIVERGENCE_THRESHOLD and agent_exclusive:
        exclusive_preview = "; ".join(t[:80] for t in agent_exclusive[:3])
        result.threats.append(
            Threat.from_type(
                ThreatType.DYNAMIC_CLOAKING,
                detail=(
                    f"URL {url!r} returns {divergence:.1%} different content to bots vs humans. "
                    f"Agent-only text samples: {exclusive_preview!r}"
                ),
                technique=f"User-agent differential cloaking (divergence {divergence:.1%})",
                outcome="flagged",
                location=url,
            )
        )

    return result


def _fetch(session: requests.Session, url: str, user_agent: str) -> str:
    """Fetch a URL with the given user-agent. Returns empty string on error."""
    try:
        resp = session.get(
            url,
            headers={"User-Agent": user_agent},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as exc:
        logger.debug("Cloaking fetch failed for %s: %s", url, exc)
        return ""
    except Exception as exc:
        logger.debug("Unexpected error fetching %s: %s", url, exc)
        return ""


def _extract_text_blocks(html: str) -> set[str]:
    """Extract all non-trivial text blocks from HTML."""
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    blocks: set[str] = set()
    for element in soup.find_all(["p", "div", "span", "li", "h1", "h2", "h3", "h4", "section"]):
        text = element.get_text(separator=" ", strip=True)
        # Keep blocks with enough content to be meaningful
        if len(text) > 20:
            blocks.add(text[:200])
    return blocks


def _compare_content(human_html: str, agent_html: str) -> tuple[float, list[str]]:
    """Return (divergence_score, agent_exclusive_blocks).

    divergence_score is in [0, 1]; higher = more different content.
    agent_exclusive_blocks contains text present in the agent response but not
    the human response.
    """
    human_blocks = _extract_text_blocks(human_html)
    agent_blocks = _extract_text_blocks(agent_html)

    if not human_blocks and not agent_blocks:
        return 0.0, []

    # Jaccard distance as divergence measure
    union = human_blocks | agent_blocks
    intersection = human_blocks & agent_blocks
    divergence = 1.0 - (len(intersection) / len(union)) if union else 0.0

    # Content only seen by the agent
    exclusive = sorted(agent_blocks - human_blocks, key=len, reverse=True)

    return divergence, exclusive
