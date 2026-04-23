"""GogglesAI — perception-layer security suite for AI agents."""

from agentshield.models import ScanResult, Threat, ThreatType
from agentshield.scanner import scan, scan_file, scan_url

__version__ = "0.1.0"

__all__ = [
    "scan",
    "scan_url",
    "scan_file",
    "ScanResult",
    "Threat",
    "ThreatType",
]
