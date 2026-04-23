"""LangChain tool wrappers for GogglesAI.

Provides three BaseTool subclasses that plug into any LangChain agent:

    from agentshield.middleware.langchain import ScanUrlTool, ScanContentTool, ScanFileTool
    from langchain.agents import initialize_agent, AgentType
    from langchain_openai import ChatOpenAI

    tools = [ScanUrlTool(), ScanContentTool(), ScanFileTool()]
    agent = initialize_agent(tools, ChatOpenAI(), agent=AgentType.OPENAI_FUNCTIONS)
    agent.run("Is https://example.com safe for my AI agent to read?")

All tools return a compact plain-text summary (safe for agent context windows) and
attach the full ScanResult JSON as a structured artifact when LangChain supports it.

Requires: pip install langchain langchain-core
"""

from __future__ import annotations

import base64
import json
from typing import Optional, Type

_LANGCHAIN_AVAILABLE = False
try:
    from langchain_core.tools import BaseTool
    from langchain_core.callbacks import CallbackManagerForToolRun
    from pydantic import BaseModel, Field
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    pass

from agentshield.scanner import scan, scan_url as _scan_url, scan_file as _scan_file
from agentshield.models import ScanResult


def _format_result(result: ScanResult, include_json: bool = False) -> str:
    lines: list[str] = []

    if result.safe:
        lines.append("SAFE — no threats detected.")
    else:
        lines.append(f"UNSAFE — {len(result.threats)} threat(s) found (max severity: {result.max_severity}).")

    lines.append(f"Confidence: {result.confidence:.0%}  |  Scan time: {result.scan_time_ms:.1f}ms")

    for t in result.threats:
        lines.append(f"\n[{t.severity.upper()}] {t.label}")
        lines.append(f"  {t.plain_summary}")
        lines.append(f"  Location: {t.location} | Technique: {t.technique}")

    if include_json:
        lines.append("\n--- Full JSON ---")
        lines.append(result.model_dump_json(indent=2))

    return "\n".join(lines)


# ── Input schemas ─────────────────────────────────────────────────────────────

if _LANGCHAIN_AVAILABLE:

    class _ScanUrlInput(BaseModel):
        url: str = Field(description="The URL to fetch and scan for threats.")
        deep: bool = Field(default=False, description="Enable Tier 3 deep neural-network analysis.")

    class _ScanContentInput(BaseModel):
        content: str = Field(
            description="Text or HTML to scan. For images, provide base64-encoded bytes."
        )
        content_type: str = Field(
            default="text/html",
            description="MIME type: text/html, text/plain, image/png, image/jpeg, etc.",
        )
        filename: str = Field(default="", description="Optional filename for MIME hint.")
        deep: bool = Field(default=False, description="Enable Tier 3 deep analysis.")

    class _ScanFileInput(BaseModel):
        path: str = Field(description="Absolute or relative path to the file to scan.")
        deep: bool = Field(default=False, description="Enable Tier 3 deep analysis.")

    # ── Tools ─────────────────────────────────────────────────────────────────

    class ScanUrlTool(BaseTool):
        name: str = "scan_url"
        description: str = (
            "Fetch a URL and scan it for prompt injection attacks, steganography in images, "
            "cloaking (serving different content to AI agents vs humans), and other perception-layer "
            "threats. Use this before letting an AI agent read content from an untrusted URL."
        )
        args_schema: Type[BaseModel] = _ScanUrlInput

        def _run(
            self,
            url: str,
            deep: bool = False,
            run_manager: Optional[CallbackManagerForToolRun] = None,
        ) -> str:
            result = _scan_url(url, deep=deep)
            return _format_result(result)

        async def _arun(
            self,
            url: str,
            deep: bool = False,
            run_manager=None,
        ) -> str:
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, lambda: _scan_url(url, deep=deep))
            return _format_result(result)

    class ScanContentTool(BaseTool):
        name: str = "scan_content"
        description: str = (
            "Scan raw text, HTML, or image content for prompt injection, hidden instructions, "
            "unicode steganography, and image-based attacks. Pass text directly as a string; "
            "pass images as base64-encoded strings with content_type='image/png' or 'image/jpeg'."
        )
        args_schema: Type[BaseModel] = _ScanContentInput

        def _run(
            self,
            content: str,
            content_type: str = "text/html",
            filename: str = "",
            deep: bool = False,
            run_manager: Optional[CallbackManagerForToolRun] = None,
        ) -> str:
            raw: str | bytes = content
            if content_type.startswith("image/"):
                try:
                    raw = base64.b64decode(content)
                except Exception:
                    pass
            result = scan(raw, content_type=content_type, filename=filename, deep=deep)
            return _format_result(result)

        async def _arun(self, content: str, content_type: str = "text/html",
                        filename: str = "", deep: bool = False, run_manager=None) -> str:
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._run(content, content_type, filename, deep),
            )
            return result

    class ScanFileTool(BaseTool):
        name: str = "scan_file"
        description: str = (
            "Scan a local file for prompt injection, steganography, and other threats. "
            "Supports HTML, plain text, PNG, JPEG, GIF, WebP, BMP, and TIFF files. "
            "Provide an absolute or relative file path."
        )
        args_schema: Type[BaseModel] = _ScanFileInput

        def _run(
            self,
            path: str,
            deep: bool = False,
            run_manager: Optional[CallbackManagerForToolRun] = None,
        ) -> str:
            result = _scan_file(path, deep=deep)
            return _format_result(result)

        async def _arun(self, path: str, deep: bool = False, run_manager=None) -> str:
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, lambda: _scan_file(path, deep=deep))
            return _format_result(result)

else:
    # Graceful stub when langchain is not installed
    class _Stub:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "langchain-core is required: pip install langchain langchain-core"
            )

    ScanUrlTool = _Stub        # type: ignore[misc,assignment]
    ScanContentTool = _Stub    # type: ignore[misc,assignment]
    ScanFileTool = _Stub       # type: ignore[misc,assignment]


def get_tools(deep: bool = False):
    """Return all three AgentShield LangChain tools as a list."""
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError("langchain-core is required: pip install langchain langchain-core")
    return [ScanUrlTool(), ScanContentTool(), ScanFileTool()]
