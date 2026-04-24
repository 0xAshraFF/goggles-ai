"""Image sanitizer: strips all metadata and optionally adds a Gaussian blur."""

from __future__ import annotations

import io
from typing import Optional


def sanitize(
    image_data: bytes,
    recompress_quality: int = 85,
    apply_blur: bool = False,
    blur_sigma: float = 0.5,
) -> bytes:
    """Strip all metadata from an image and optionally recompress/blur it.

    Args:
        image_data: Raw image bytes (any PIL-supported format).
        recompress_quality: JPEG quality for recompressed output (1–95).
        apply_blur: If True, apply a Gaussian blur to destroy pixel-level stego.
        blur_sigma: Standard deviation for the Gaussian blur kernel.

    Returns:
        Sanitized image bytes (JPEG format, all metadata stripped).
        Returns original bytes on failure.
    """
    if not image_data:
        return image_data

    try:
        from PIL import Image, ImageFilter
    except ImportError:
        return image_data

    try:
        img = Image.open(io.BytesIO(image_data))

        # Convert to RGB to ensure consistent output and drop alpha/palette modes
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # Re-create the image from pixel data — this drops ALL metadata
        # (EXIF, XMP, IPTC, ICC profiles, custom chunks)
        clean_data = list(img.getdata())
        clean_img = Image.new(img.mode, img.size)
        clean_img.putdata(clean_data)

        if apply_blur:
            import numpy as np

            # Gaussian blur using PIL's built-in filter
            radius = max(1, int(blur_sigma * 2))
            clean_img = clean_img.filter(ImageFilter.GaussianBlur(radius=radius))

        buf = io.BytesIO()
        clean_img.save(buf, format="JPEG", quality=recompress_quality, optimize=True)
        return buf.getvalue()

    except Exception:
        return image_data


def strip_metadata_only(image_data: bytes) -> bytes:
    """Strip metadata while preserving original format and pixel data.

    Useful when you want to remove EXIF payloads without changing pixel data
    (and thus without destroying legitimate image quality).

    Returns original bytes on failure.
    """
    if not image_data:
        return image_data

    try:
        from PIL import Image
    except ImportError:
        return image_data

    try:
        img = Image.open(io.BytesIO(image_data))
        fmt = img.format or "PNG"

        # Detect format and preserve it
        buf = io.BytesIO()
        # Save without EXIF/metadata by not passing exif/info kwargs
        save_kwargs: dict = {}
        if fmt.upper() == "JPEG":
            save_kwargs["quality"] = 95
        img.save(buf, format=fmt, **save_kwargs)
        return buf.getvalue()
    except Exception:
        return image_data
