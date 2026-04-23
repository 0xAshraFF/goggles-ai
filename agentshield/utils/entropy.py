"""Shannon entropy, chi-square, and related statistical helpers."""

import math
from typing import Union

import numpy as np


def shannon_entropy(data: Union[bytes, np.ndarray]) -> float:
    """Compute Shannon entropy of data in bits per symbol.

    Args:
        data: Raw bytes or a numpy array of uint8 values.

    Returns:
        Entropy in bits per byte/element. Range: [0, 8].
        High entropy (>7.0) suggests compressed, encrypted, or hidden data.
    """
    if isinstance(data, bytes):
        if len(data) == 0:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    else:
        arr = np.asarray(data).flatten()
        if arr.size == 0:
            return 0.0
        counts = np.bincount(arr.astype(np.uint8), minlength=256)

    total = counts.sum()
    if total == 0:
        return 0.0

    probs = counts[counts > 0] / total
    return float(-np.sum(probs * np.log2(probs)))


def channel_entropy(image_array: np.ndarray) -> dict[str, float]:
    """Compute Shannon entropy per channel for an image array.

    Args:
        image_array: H×W grayscale or H×W×C RGB/RGBA array.

    Returns:
        Dict mapping channel name to entropy value.
    """
    if image_array.ndim == 2:
        return {"gray": shannon_entropy(image_array.flatten())}

    if image_array.ndim == 3:
        names = ["R", "G", "B", "A"][: image_array.shape[2]]
        return {name: shannon_entropy(image_array[:, :, i].flatten()) for i, name in enumerate(names)}

    return {}


def chi_square_lsb_score(channel: np.ndarray) -> float:
    """Chi-square test for LSB replacement steganography.

    Under LSB replacement, adjacent histogram pairs (2i, 2i+1) are forced to
    equalize. A clean natural image has significantly unequal pairs; a stego
    image has near-equal pairs.

    Returns:
        Score in [0, 1]. Higher = more likely to contain LSB steganography.
        Threshold: >0.5 is suspicious, >0.7 is likely stego.
    """
    flat = np.asarray(channel).flatten().astype(np.int32)
    if flat.size == 0:
        return 0.0

    hist = np.bincount(flat, minlength=256)

    chi_sq = 0.0
    k = 0

    for i in range(0, 255, 2):
        n1 = int(hist[i])
        n2 = int(hist[i + 1])
        total = n1 + n2
        if total < 5:
            continue
        expected = total / 2.0
        chi_sq += (n1 - expected) ** 2 / expected
        chi_sq += (n2 - expected) ** 2 / expected
        k += 1

    if k == 0:
        return 0.0

    # Low chi_sq → pairs equalized → steganography likely → high score
    # Use exponential decay: score ≈ 1 when chi_sq≈0, drops as chi_sq grows
    score = math.exp(-chi_sq / (max(k, 1) * 2.0))
    return float(min(1.0, max(0.0, score)))


def rs_analysis_score(channel: np.ndarray) -> float:
    """Regular-Singular (RS) steganalysis for estimating LSB embedding rate.

    Groups pixels into horizontal blocks and measures regularity under LSB
    flipping. A higher score indicates more LSB embedding.

    Returns:
        Estimated embedding fraction in [0, 1].
    """
    arr = np.asarray(channel).astype(np.int32)
    if arr.ndim > 2:
        arr = arr[:, :, 0]
    if arr.size == 0:
        return 0.0

    height, width = arr.shape
    block_size = 4

    r_m = s_m = r_neg_m = s_neg_m = n_blocks = 0

    for row in range(height):
        for col in range(0, width - block_size + 1, block_size):
            block = arr[row, col : col + block_size].copy()

            def _smooth(b: np.ndarray) -> float:
                return float(np.sum(np.abs(np.diff(b))))

            f_orig = _smooth(block)

            # Positive mask: flip LSB of even-indexed pixels
            bm = block.copy()
            bm[::2] = np.clip(bm[::2] ^ 1, 0, 255)
            f_pos = _smooth(bm)

            # Negative mask: flip LSB of odd-indexed pixels
            bn = block.copy()
            bn[1::2] = np.clip(bn[1::2] ^ 1, 0, 255)
            f_neg = _smooth(bn)

            if f_pos > f_orig:
                r_m += 1
            elif f_pos < f_orig:
                s_m += 1

            if f_neg > f_orig:
                r_neg_m += 1
            elif f_neg < f_orig:
                s_neg_m += 1

            n_blocks += 1

    if n_blocks == 0:
        return 0.0

    rm = r_m / n_blocks
    sm = s_m / n_blocks
    rn = r_neg_m / n_blocks
    sn = s_neg_m / n_blocks

    denom = 2 * (rm - rn - sm + sn)
    if abs(denom) < 1e-9:
        return 0.0

    # Estimated embedding rate (fraction of LSBs replaced)
    p_hat = (rn - rm) / denom
    return float(min(1.0, max(0.0, abs(p_hat))))


def spa_score(channel: np.ndarray) -> float:
    """Sample Pairs Analysis (SPA) for LSB steganography detection.

    Counts the relative proportion of horizontally adjacent pixel pairs that
    differ only in their LSB. Under LSB embedding this proportion increases.

    Returns:
        Score in [0, 1]. Higher = more LSB modification detected.
    """
    arr = np.asarray(channel).astype(np.int32)
    if arr.ndim > 2:
        arr = arr[:, :, 0]
    if arr.size < 2:
        return 0.0

    # Flatten to row pairs
    left = arr[:, :-1].flatten()
    right = arr[:, 1:].flatten()

    diff = np.abs(left - right)
    n_total = len(diff)
    if n_total == 0:
        return 0.0

    # Count pairs that are equal (diff=0) or differ by 1 in LSB (diff=1)
    n_close = int(np.sum(diff <= 1))
    close_ratio = n_close / n_total

    # Natural images: close_ratio ≈ 0.2–0.4
    # Heavy LSB embedding: close_ratio → 0.5+
    baseline = 0.35
    score = max(0.0, (close_ratio - baseline) / (0.5 - baseline))
    return float(min(1.0, score))
