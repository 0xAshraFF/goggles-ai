# GogglesAI — Perception-Layer Security for AI Agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-pytest-green.svg)](tests/)

**GogglesAI** is the first open-source perception-layer security suite for AI agents. It sits between raw web content and an LLM's context window, scanning for hidden attacks that humans can't see but agents will process.

## What it detects

| Attack | Tier | Description |
|--------|------|-------------|
| CSS Hidden Text | T1 | `display:none`, `opacity:0`, off-screen positioning |
| Zero-Width Chars | T1 | ZWSP, ZWNJ, ZWJ, directional marks |
| Unicode Homoglyphs | T1 | Cyrillic/Greek chars disguised as Latin |
| HTML Comment Injection | T1 | Instructions hidden in `<!-- -->` blocks |
| ARIA/Attribute Injection | T1 | `aria-label`, `data-*`, `alt` attribute abuse |
| Dynamic Cloaking | T1 | Different content for bots vs humans |
| EXIF Payload | T2 | Instructions embedded in image metadata |
| LSB Steganography | T2 | Pixel-level hidden data (chi-square, RS, SPA) |
| Deep Stego | T3 | SRNet neural network detection |

## Quickstart

```bash
pip install agentshield
```

```python
from agentshield import scan, scan_url

# Scan raw HTML
result = scan('<html>...malicious page...</html>', content_type='text/html')
print(result.safe)          # False
print(result.threats[0].plain_summary)  # Plain English explanation
print(result.sanitized_content)         # Cleaned HTML

# Scan a URL (also runs cloaking detection)
result = scan_url('https://example.com/job-posting')
for threat in result.threats:
    print(f"[{threat.severity.upper()}] {threat.label}")
    print(f"  {threat.plain_summary}")
```

## Architecture

```
Raw content → [Tier 1: Rule-based, <50ms] → [Tier 2: Statistical, <500ms] → [Tier 3: DL, <5s]
                                                                                       ↓
                                                               ScanResult (threats + sanitized content)
```

## Running Tests

```bash
pip install -e ".[test]"
pytest tests/ -v --cov=agentshield
```

## Project Structure

```
agentshield/          Python package
  detectors/          Attack detectors (Tier 1–3)
  sanitizers/         Content cleaning modules
  utils/              Entropy, unicode helpers
  middleware/         MCP server, LangChain, Playwright hooks (Task 3)
eval/                 Evaluation dataset generators and harness
dashboard/            React dashboard (Task 3)
tests/                Pytest test suite
```

## License

MIT — see [LICENSE](LICENSE).
