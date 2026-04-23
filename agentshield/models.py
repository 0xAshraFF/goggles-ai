"""Pydantic models for GogglesAI scan results and threat representations."""

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class ThreatType(str, Enum):
    CSS_HIDDEN_TEXT = "css_hidden_text"
    ZERO_WIDTH_CHARS = "zero_width_chars"
    HOMOGLYPH = "homoglyph"
    VARIATION_SELECTOR = "variation_selector"
    HTML_COMMENT_INJECTION = "html_comment_injection"
    ARIA_ATTRIBUTE_INJECTION = "aria_attribute_injection"
    META_INJECTION = "meta_injection"
    NOSCRIPT_INJECTION = "noscript_injection"
    EXIF_PAYLOAD = "exif_payload"
    HIGH_ENTROPY_METADATA = "high_entropy_metadata"
    LSB_STEGANOGRAPHY = "lsb_steganography"
    HIGH_ENTROPY_PIXELS = "high_entropy_pixels"
    DYNAMIC_CLOAKING = "dynamic_cloaking"
    MAGIC_BYTE_MISMATCH = "magic_byte_mismatch"


# Human-readable labels for each threat type
THREAT_LABELS: dict[ThreatType, str] = {
    ThreatType.CSS_HIDDEN_TEXT: "CSS Hidden Text Injection",
    ThreatType.ZERO_WIDTH_CHARS: "Zero-Width Character Steganography",
    ThreatType.HOMOGLYPH: "Unicode Homoglyph Substitution",
    ThreatType.VARIATION_SELECTOR: "Variation Selector Injection",
    ThreatType.HTML_COMMENT_INJECTION: "HTML Comment Injection",
    ThreatType.ARIA_ATTRIBUTE_INJECTION: "ARIA/Attribute Injection",
    ThreatType.META_INJECTION: "Meta Tag Injection",
    ThreatType.NOSCRIPT_INJECTION: "NoScript Block Injection",
    ThreatType.EXIF_PAYLOAD: "EXIF Metadata Payload",
    ThreatType.HIGH_ENTROPY_METADATA: "High-Entropy Image Metadata",
    ThreatType.LSB_STEGANOGRAPHY: "LSB Pixel Steganography",
    ThreatType.HIGH_ENTROPY_PIXELS: "Anomalous Pixel Entropy",
    ThreatType.DYNAMIC_CLOAKING: "Dynamic Content Cloaking",
    ThreatType.MAGIC_BYTE_MISMATCH: "File Type Magic Byte Mismatch",
}


# Non-technical plain English summaries explaining real-world impact
THREAT_PLAIN_SUMMARIES: dict[ThreatType, str] = {
    ThreatType.CSS_HIDDEN_TEXT: (
        "This page contains invisible text hidden from your view but readable by AI. "
        "An attacker could use this to secretly instruct your AI assistant to do things "
        "you didn't ask for — like sharing private information or giving biased answers."
    ),
    ThreatType.ZERO_WIDTH_CHARS: (
        "Someone embedded invisible characters inside the text on this page. These characters "
        "carry a hidden message that only your AI can decode — it may be trying to steal your "
        "data, override your AI's instructions, or manipulate its behavior without your knowledge."
    ),
    ThreatType.HOMOGLYPH: (
        "Some letters on this page look normal but are actually foreign characters designed to "
        "confuse your AI. It's like someone replacing letters in a document with identical-looking "
        "characters from another alphabet to sneak past security checks."
    ),
    ThreatType.VARIATION_SELECTOR: (
        "Hidden Unicode variation selectors are embedded in this text. These invisible characters "
        "can encode secret messages or commands that your AI will process without you knowing — "
        "like a hidden watermark that only machines can read."
    ),
    ThreatType.HTML_COMMENT_INJECTION: (
        "Someone hid instructions inside the page's code that are invisible when you view the page "
        "but get passed directly to your AI. It's like someone slipping a note into a sealed letter "
        "that only the mail carrier can read."
    ),
    ThreatType.ARIA_ATTRIBUTE_INJECTION: (
        "Hidden instructions are embedded in accessibility attributes on this page. These attributes "
        "are meant for screen readers but are also read by AI agents, allowing attackers to deliver "
        "secret commands through seemingly harmless HTML."
    ),
    ThreatType.META_INJECTION: (
        "Injected meta tags in unusual locations on this page contain instructions targeting AI "
        "agents. These are invisible to normal users but can influence how your AI interprets "
        "and acts on the page content."
    ),
    ThreatType.NOSCRIPT_INJECTION: (
        "Hidden instructions are embedded in a NoScript block on this page. These only activate "
        "when JavaScript is disabled — exactly the condition many AI agents operate under — "
        "letting attackers target AI specifically while staying hidden from human browsers."
    ),
    ThreatType.EXIF_PAYLOAD: (
        "The images on this page have hidden instructions stuffed into their metadata — the digital "
        "equivalent of writing secret notes on the back of a photograph. Your AI would read these "
        "notes and might follow the instructions without you realizing it."
    ),
    ThreatType.HIGH_ENTROPY_METADATA: (
        "Image metadata on this page contains unusually complex or encrypted data. This is a "
        "common sign that someone has hidden a secret message or set of instructions in the "
        "image's metadata fields."
    ),
    ThreatType.LSB_STEGANOGRAPHY: (
        "This image appears normal but has a secret message hidden in its pixels — changes so "
        "tiny the human eye can't detect them. Your AI, however, might decode and follow hidden "
        "instructions embedded in the image."
    ),
    ThreatType.HIGH_ENTROPY_PIXELS: (
        "The pixel data in this image shows unusual statistical patterns that may indicate hidden "
        "content. The image may have been modified to carry a covert message invisible to the "
        "human eye but detectable by AI."
    ),
    ThreatType.DYNAMIC_CLOAKING: (
        "This website shows different content to AI agents than what you see as a human. Think "
        "of it like a con artist showing a fake ID — your AI is being shown a completely "
        "different page designed to manipulate it."
    ),
    ThreatType.MAGIC_BYTE_MISMATCH: (
        "This file claims to be one type but is actually another — like a disguised executable "
        "that presents itself as an image. This could be used to trick your AI into processing "
        "malicious content it would otherwise reject."
    ),
}

THREAT_TIERS: dict[ThreatType, Literal[1, 2, 3]] = {
    ThreatType.CSS_HIDDEN_TEXT: 1,
    ThreatType.ZERO_WIDTH_CHARS: 1,
    ThreatType.HOMOGLYPH: 1,
    ThreatType.VARIATION_SELECTOR: 1,
    ThreatType.HTML_COMMENT_INJECTION: 1,
    ThreatType.ARIA_ATTRIBUTE_INJECTION: 1,
    ThreatType.META_INJECTION: 1,
    ThreatType.NOSCRIPT_INJECTION: 1,
    ThreatType.EXIF_PAYLOAD: 2,
    ThreatType.HIGH_ENTROPY_METADATA: 2,
    ThreatType.LSB_STEGANOGRAPHY: 2,
    ThreatType.HIGH_ENTROPY_PIXELS: 2,
    ThreatType.DYNAMIC_CLOAKING: 1,
    ThreatType.MAGIC_BYTE_MISMATCH: 2,
}

THREAT_SEVERITIES: dict[ThreatType, Literal["critical", "high", "medium", "low"]] = {
    ThreatType.CSS_HIDDEN_TEXT: "critical",
    ThreatType.ZERO_WIDTH_CHARS: "high",
    ThreatType.HOMOGLYPH: "medium",
    ThreatType.VARIATION_SELECTOR: "medium",
    ThreatType.HTML_COMMENT_INJECTION: "critical",
    ThreatType.ARIA_ATTRIBUTE_INJECTION: "high",
    ThreatType.META_INJECTION: "high",
    ThreatType.NOSCRIPT_INJECTION: "high",
    ThreatType.EXIF_PAYLOAD: "high",
    ThreatType.HIGH_ENTROPY_METADATA: "medium",
    ThreatType.LSB_STEGANOGRAPHY: "critical",
    ThreatType.HIGH_ENTROPY_PIXELS: "medium",
    ThreatType.DYNAMIC_CLOAKING: "critical",
    ThreatType.MAGIC_BYTE_MISMATCH: "high",
}


class Threat(BaseModel):
    """A single detected threat with full technical and plain-English details."""

    type: str = Field(description="Machine-readable threat type identifier")
    label: str = Field(description="Human-readable threat label")
    severity: Literal["critical", "high", "medium", "low"]
    tier: Literal[1, 2, 3] = Field(description="Detection tier: 1=rule, 2=statistical, 3=ML")
    detail: str = Field(description="Technical detail for security researchers")
    plain_summary: str = Field(description="Non-technical plain English impact description")
    technique: str = Field(description="Specific technique used by the attacker")
    outcome: str = Field(description="What AgentShield did about it")
    location: Optional[str] = Field(None, description="Where in the content (selector, offset)")

    @classmethod
    def from_type(
        cls,
        threat_type: ThreatType,
        detail: str,
        technique: str,
        outcome: str,
        location: Optional[str] = None,
    ) -> "Threat":
        """Construct a Threat from a ThreatType enum, auto-populating metadata."""
        return cls(
            type=threat_type.value,
            label=THREAT_LABELS[threat_type],
            severity=THREAT_SEVERITIES[threat_type],
            tier=THREAT_TIERS[threat_type],
            detail=detail,
            plain_summary=THREAT_PLAIN_SUMMARIES[threat_type],
            technique=technique,
            outcome=outcome,
            location=location,
        )


class ScanResult(BaseModel):
    """Complete scan result including all detected threats and sanitized content."""

    safe: bool = Field(description="True if no threats were detected")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the verdict (0–1)")
    scan_time_ms: int = Field(description="Total scan time in milliseconds")
    threats: list[Threat] = Field(default_factory=list)
    sanitized_content: Optional[str] = Field(None, description="Cleaned content after threat removal")
    tier_timings: dict[str, int] = Field(
        default_factory=dict, description="Per-tier timing in ms: {t1: 23, t2: 18, t3: 4200}"
    )

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    @property
    def max_severity(self) -> Optional[str]:
        if not self.threats:
            return None
        for sev in ("critical", "high", "medium", "low"):
            if any(t.severity == sev for t in self.threats):
                return sev
        return None

    @property
    def has_critical(self) -> bool:
        return any(t.severity == "critical" for t in self.threats)


class ScanSummary(BaseModel):
    """Lightweight scan summary for history views."""

    scan_id: str
    url: Optional[str] = None
    filename: Optional[str] = None
    timestamp: str
    safe: bool
    threat_count: int
    max_severity: Optional[str] = None
    scan_time_ms: int
