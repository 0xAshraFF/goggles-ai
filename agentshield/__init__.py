"""goggles-ai — inspection layer for AI agent inputs."""

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
