"""Tier 3: Deep learning steganography detection.

Wraps SRNet (a convolutional steganalysis network) and optionally the Aletheia
CLI tool. Only activated for images flagged by Tier 2 triage.

Both backends are optional: if PyTorch weights are missing or Aletheia is not
installed, this module returns an "inconclusive" verdict rather than crashing.
"""

from __future__ import annotations

import io
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

logger = logging.getLogger(__name__)

# Path where SRNet weights should be placed
_DEFAULT_WEIGHTS_PATH = Path(__file__).parent.parent.parent / "srnet_weights" / "srnet.pth"


@dataclass
class StegoDeepResult:
    """Result from Tier 3 deep-learning analysis."""

    verdict: Literal["clean", "stego", "inconclusive"]
    confidence: float  # [0, 1]
    method: str  # "srnet", "aletheia", or "unavailable"
    detail: str


def detect(image_data: bytes, weights_path: Optional[Path] = None) -> StegoDeepResult:
    """Run Tier 3 deep-learning steganography detection.

    Tries backends in order: SRNet → Aletheia → inconclusive.

    Args:
        image_data: Raw image bytes (already flagged by Tier 2).
        weights_path: Optional override for SRNet weight file location.

    Returns:
        StegoDeepResult with verdict and confidence.
    """
    if not image_data:
        return StegoDeepResult(
            verdict="inconclusive",
            confidence=0.0,
            method="unavailable",
            detail="Empty image data",
        )

    # Try SRNet first
    result = _try_srnet(image_data, weights_path or _DEFAULT_WEIGHTS_PATH)
    if result is not None:
        return result

    # Try Aletheia CLI
    result = _try_aletheia(image_data)
    if result is not None:
        return result

    return StegoDeepResult(
        verdict="inconclusive",
        confidence=0.0,
        method="unavailable",
        detail=(
            "Tier 3 analysis unavailable. Neither SRNet weights nor Aletheia CLI found. "
            "Install PyTorch + place srnet.pth in srnet_weights/, or pip install aletheia."
        ),
    )


# ── SRNet backend ─────────────────────────────────────────────────────────────

class _SRNet:
    """Simplified SRNet architecture for JPEG/PNG steganalysis.

    SRNet (Boroumand et al., 2019) is a deep residual network designed for
    image steganography detection. This implementation follows the original
    architecture as closely as practical without the full training setup.
    """

    def __init__(self) -> None:
        import torch.nn as nn

        self.model = nn.Sequential(
            # Type I: simple conv + BN + ReLU
            nn.Conv2d(1, 64, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            # Type II: residual blocks
            *self._make_residual_blocks(64, 64, 3),
            *self._make_residual_blocks(64, 128, 2),
            *self._make_residual_blocks(128, 256, 2),
            # Reduction
            nn.AdaptiveAvgPool2d((8, 8)),
            nn.Flatten(),
            nn.Linear(256 * 8 * 8, 512),
            nn.ReLU(inplace=True),
            nn.Dropout(0.5),
            nn.Linear(512, 2),
        )

    @staticmethod
    def _make_residual_blocks(in_ch: int, out_ch: int, n: int):
        import torch.nn as nn
        layers = []
        for i in range(n):
            ch_in = in_ch if i == 0 else out_ch
            layers += [
                nn.Conv2d(ch_in, out_ch, kernel_size=3, padding=1, bias=False),
                nn.BatchNorm2d(out_ch),
                nn.ReLU(inplace=True),
            ]
        return layers

    def predict(self, image_array) -> tuple[str, float]:
        """Return (verdict, confidence) for a preprocessed image array."""
        import torch
        import torch.nn.functional as F

        self.model.eval()
        with torch.no_grad():
            t = torch.from_numpy(image_array).float().unsqueeze(0).unsqueeze(0)
            t = t / 255.0
            logits = self.model(t)
            probs = F.softmax(logits, dim=1)
            stego_prob = float(probs[0, 1])

        verdict = "stego" if stego_prob > 0.5 else "clean"
        return verdict, stego_prob


def _preprocess_for_srnet(image_data: bytes):
    """Convert raw image bytes to a single-channel 256×256 numpy array."""
    from PIL import Image
    import numpy as np

    img = Image.open(io.BytesIO(image_data)).convert("L")  # Grayscale
    img = img.resize((256, 256))
    return np.array(img, dtype=np.float32)


def _try_srnet(image_data: bytes, weights_path: Path) -> Optional[StegoDeepResult]:
    """Attempt SRNet inference. Returns None if unavailable."""
    try:
        import torch
    except ImportError:
        logger.debug("Tier 3: PyTorch not available, skipping SRNet")
        return None

    if not weights_path.exists():
        logger.debug("Tier 3: SRNet weights not found at %s", weights_path)
        return None

    try:
        from PIL import Image
        import numpy as np

        net = _SRNet()
        state = torch.load(str(weights_path), map_location="cpu")
        net.model.load_state_dict(state)

        arr = _preprocess_for_srnet(image_data)
        verdict, confidence = net.predict(arr)

        return StegoDeepResult(
            verdict=verdict,
            confidence=confidence,
            method="srnet",
            detail=(
                f"SRNet inference: {verdict} (confidence {confidence:.3f}). "
                f"Weights: {weights_path.name}"
            ),
        )
    except Exception as exc:
        logger.warning("Tier 3: SRNet inference failed: %s", exc)
        return None


# ── Aletheia backend ──────────────────────────────────────────────────────────

def _aletheia_available() -> bool:
    return shutil.which("aletheia") is not None


def _try_aletheia(image_data: bytes) -> Optional[StegoDeepResult]:
    """Attempt Aletheia CLI detection. Returns None if unavailable."""
    if not _aletheia_available():
        return None

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp.write(image_data)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["aletheia", "spa", tmp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).lower()

        # Parse Aletheia output
        stego_detected = any(
            kw in output for kw in ("steganography detected", "stego", "embedded")
        )
        clean = "no hidden" in output or "not stego" in output

        if stego_detected:
            confidence = 0.85
            verdict = "stego"
        elif clean:
            confidence = 0.8
            verdict = "clean"
        else:
            confidence = 0.0
            verdict = "inconclusive"

        return StegoDeepResult(
            verdict=verdict,
            confidence=confidence,
            method="aletheia",
            detail=f"Aletheia output: {output[:200].strip()}",
        )
    except subprocess.TimeoutExpired:
        logger.warning("Tier 3: Aletheia timed out")
        return None
    except Exception as exc:
        logger.warning("Tier 3: Aletheia failed: %s", exc)
        return None
    finally:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass
