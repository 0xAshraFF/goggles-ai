"""Tier 2: Image triage — statistical steganography and metadata analysis.

Performs magic-byte verification, EXIF/XMP extraction with entropy scoring,
and three classical LSB detection algorithms (chi-square, RS analysis, SPA).
Returns a structured verdict used to decide Tier 3 escalation.
"""

from __future__ import annotations

import io
import re
import struct
from dataclasses import dataclass, field
from typing import Literal, Optional

import numpy as np

from agentshield.models import Threat, ThreatType
from agentshield.utils.entropy import channel_entropy, chi_square_lsb_score, rs_analysis_score, spa_score

# ── Magic byte signatures ─────────────────────────────────────────────────────

_MAGIC_BYTES: dict[str, list[bytes]] = {
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/gif": [b"GIF87a", b"GIF89a"],
    "image/webp": [],  # checked separately (RIFF....WEBP)
    "image/bmp": [b"BM"],
    "image/tiff": [b"\x49\x49\x2a\x00", b"\x4d\x4d\x00\x2a"],
}

# Entropy threshold for flagging metadata fields (bits/byte)
EXIF_ENTROPY_THRESHOLD = 6.5
# Statistical score above which an image is considered suspicious
LSB_SCORE_THRESHOLD = 0.60
# Combined multi-test threshold
COMBINED_THRESHOLD = 0.55


def _detect_mime_from_magic(data: bytes) -> Optional[str]:
    """Return MIME type inferred from magic bytes, or None if unknown."""
    if len(data) < 12:
        return None

    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:2] == b"BM":
        return "image/bmp"
    if data[:4] in (b"\x49\x49\x2a\x00", b"\x4d\x4d\x00\x2a"):
        return "image/tiff"
    return None


def _extension_to_mime(ext: str) -> Optional[str]:
    mapping = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
        ".tiff": "image/tiff",
        ".tif": "image/tiff",
    }
    return mapping.get(ext.lower())


@dataclass
class ImageTriageResult:
    """Result from image triage analysis."""

    threats: list[Threat] = field(default_factory=list)
    is_suspicious: bool = False
    scores: dict[str, float] = field(default_factory=dict)
    recommended_action: Literal["clean", "deep_scan", "quarantine"] = "clean"
    detected_mime: Optional[str] = None
    claimed_mime: Optional[str] = None


def detect(image_data: bytes, filename: str = "") -> ImageTriageResult:
    """Run Tier 2 image triage on raw image bytes.

    Args:
        image_data: Raw bytes of the image file.
        filename: Optional filename used for extension-based MIME hint.

    Returns:
        ImageTriageResult with suspicion scores and recommended action.
    """
    result = ImageTriageResult()

    if not image_data or len(image_data) < 16:
        return result

    # ── 1. Magic byte / MIME mismatch ─────────────────────────────────────

    detected_mime = _detect_mime_from_magic(image_data)
    result.detected_mime = detected_mime

    if filename:
        import os
        ext = os.path.splitext(filename)[1]
        claimed_mime = _extension_to_mime(ext)
        result.claimed_mime = claimed_mime

        if detected_mime and claimed_mime and detected_mime != claimed_mime:
            result.threats.append(
                Threat.from_type(
                    ThreatType.MAGIC_BYTE_MISMATCH,
                    detail=(
                        f"File extension suggests {claimed_mime} but magic bytes "
                        f"indicate {detected_mime}. Filename: {filename!r}"
                    ),
                    technique="File type spoofing via extension mismatch",
                    outcome="quarantined",
                    location=f"file header (first 12 bytes)",
                )
            )
            result.is_suspicious = True
            result.recommended_action = "quarantine"

    # ── 2. EXIF / metadata analysis ───────────────────────────────────────

    _analyze_metadata(image_data, result)

    # ── 3. Statistical LSB analysis ───────────────────────────────────────

    _analyze_pixels(image_data, result)

    # ── 4. Determine recommended action ──────────────────────────────────

    if not result.is_suspicious:
        result.recommended_action = "clean"
    else:
        scores = result.scores
        lsb_score = max(
            scores.get("chi_square_lsb", 0),
            scores.get("rs_analysis", 0),
            scores.get("spa", 0),
        )
        if lsb_score > 0.75 or result.recommended_action == "quarantine":
            result.recommended_action = "quarantine"
        else:
            result.recommended_action = "deep_scan"

    return result


_INSTR_RE = re.compile(
    r"ignore\s+(previous|all|prior)|system\s*:|you\s+are\s+(now|a\s)|"
    r"override\s+(safety|filter|instruction)|instruction\s*:|IMPORTANT\s*:|"
    r"disregard|forget\s+previous|act\s+as\s+|pretend\s+(to\s+be|you\s+are)|"
    r"roleplay\s+as|your\s+new\s+role|new\s+instructions?",
    re.IGNORECASE,
)


def _analyze_metadata(image_data: bytes, result: ImageTriageResult) -> None:
    """Extract EXIF/metadata; flag high-entropy fields AND instruction payloads."""
    try:
        from PIL import Image
        import piexif
    except ImportError:
        return

    try:
        img = Image.open(io.BytesIO(image_data))
    except Exception:
        return

    from agentshield.utils.entropy import shannon_entropy

    # (tag_name, entropy, raw_preview, is_instruction_payload)
    flagged_fields: list[tuple[str, float, str, bool]] = []

    def _check_field(tag_name: str, raw: bytes) -> None:
        ent = shannon_entropy(raw)
        text_repr = repr(raw[:80])
        is_instr = bool(_INSTR_RE.search(raw.decode("utf-8", errors="replace")))
        if ent >= EXIF_ENTROPY_THRESHOLD or is_instr:
            flagged_fields.append((tag_name, ent, text_repr, is_instr))

    # ── PIL EXIF (JPEG) ────────────────────────────────────────────────
    try:
        exif_data = img.info.get("exif", b"")
        if exif_data:
            exif_dict = piexif.load(exif_data)
            for ifd_name, ifd in exif_dict.items():
                if not isinstance(ifd, dict):
                    continue
                for tag_id, val in ifd.items():
                    tag_name = _exif_tag_name(ifd_name, tag_id)
                    if isinstance(val, bytes) and len(val) > 4:
                        _check_field(tag_name, val)
                    elif isinstance(val, str) and len(val) > 4:
                        _check_field(tag_name, val.encode("utf-8", errors="replace"))
    except Exception:
        pass

    # ── PNG / other text chunks ──────────────────────────────────────
    try:
        for key, val in (img.info or {}).items():
            if key == "exif":
                continue
            if isinstance(val, str) and len(val) > 4:
                _check_field(f"IMG:{key}", val.encode("utf-8", errors="replace"))
            elif isinstance(val, bytes) and len(val) > 4:
                _check_field(f"IMG:{key}", val)
    except Exception:
        pass

    if flagged_fields:
        result.is_suspicious = True
        top = sorted(flagged_fields, key=lambda x: -x[1])

        has_instruction_payload = any(is_instr for _, _, _, is_instr in flagged_fields)
        threat_type = ThreatType.EXIF_PAYLOAD if has_instruction_payload else ThreatType.HIGH_ENTROPY_METADATA

        top_name, top_ent, top_raw, _ = top[0]
        result.threats.append(
            Threat.from_type(
                threat_type,
                detail=(
                    f"Found {len(flagged_fields)} suspicious metadata field(s). "
                    f"Top: {top_name} (entropy {top_ent:.2f} bits/byte): {top_raw}"
                ),
                technique=f"Metadata payload in {', '.join(f for f, _, _, _ in top[:3])}",
                outcome="stripped",
                location=f"EXIF/metadata ({len(flagged_fields)} fields)",
            )
        )

        result.scores["max_metadata_entropy"] = top_ent


def _analyze_pixels(image_data: bytes, result: ImageTriageResult) -> None:
    """Run chi-square, RS, and SPA tests on pixel data."""
    try:
        from PIL import Image
    except ImportError:
        return

    try:
        img = Image.open(io.BytesIO(image_data)).convert("RGB")
    except Exception:
        return

    arr = np.array(img)
    if arr.size == 0:
        return

    # Per-channel entropy
    entropies = channel_entropy(arr)
    result.scores.update({f"entropy_{k}": v for k, v in entropies.items()})

    # Use the red channel for statistical tests (most common in literature)
    red_channel = arr[:, :, 0]

    chi_score = chi_square_lsb_score(red_channel)
    rs_score = rs_analysis_score(red_channel)
    spa = spa_score(red_channel)

    result.scores["chi_square_lsb"] = chi_score
    result.scores["rs_analysis"] = rs_score
    result.scores["spa"] = spa

    # Weighted combined score
    combined = 0.4 * chi_score + 0.4 * rs_score + 0.2 * spa
    result.scores["combined_lsb"] = combined

    if combined >= COMBINED_THRESHOLD or chi_score >= LSB_SCORE_THRESHOLD:
        result.is_suspicious = True
        detail_parts = [
            f"chi-square={chi_score:.3f}",
            f"RS={rs_score:.3f}",
            f"SPA={spa:.3f}",
            f"combined={combined:.3f}",
        ]
        result.threats.append(
            Threat.from_type(
                ThreatType.LSB_STEGANOGRAPHY,
                detail=(
                    f"Statistical analysis indicates likely LSB steganography. "
                    f"Scores: {', '.join(detail_parts)}. "
                    f"Image: {arr.shape[1]}×{arr.shape[0]}px"
                ),
                technique="LSB replacement (chi-square + RS + SPA statistical detection)",
                outcome="deep_scan_recommended",
                location=f"pixel data ({arr.size // 3} pixels)",
            )
        )

    elif max(chi_score, rs_score, spa) >= 0.35:
        # Borderline — flag entropy anomaly without full LSB verdict
        result.is_suspicious = True
        result.scores["borderline"] = True
        result.threats.append(
            Threat.from_type(
                ThreatType.HIGH_ENTROPY_PIXELS,
                detail=(
                    f"Pixel entropy anomaly detected but below LSB threshold. "
                    f"chi-square={chi_score:.3f}, RS={rs_score:.3f}, SPA={spa:.3f}"
                ),
                technique="Pixel entropy anomaly (borderline statistical detection)",
                outcome="flagged",
                location="pixel data",
            )
        )


def _exif_tag_name(ifd_name: str, tag_id: int) -> str:
    """Return a readable tag name from IFD name and tag ID."""
    try:
        import piexif
        ifd_map = {
            "0th": piexif.ImageIFD,
            "1st": piexif.ImageIFD,
            "Exif": piexif.ExifIFD,
            "GPS": piexif.GPSIFD,
        }
        ifd_obj = ifd_map.get(ifd_name)
        if ifd_obj:
            for attr in dir(ifd_obj):
                if getattr(ifd_obj, attr) == tag_id:
                    return f"{ifd_name}/{attr}"
    except Exception:
        pass
    return f"{ifd_name}/0x{tag_id:04X}"
