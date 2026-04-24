"""MCP (Model Context Protocol) server for goggles-ai.

Exposes three tools that any MCP-compatible agent can call:
  - scan_url     : fetch + scan a URL (runs all tiers including cloaking)
  - scan_content : scan raw text / HTML / image bytes (base64 for binary)
  - scan_file    : scan a file at a local path

Run standalone:
    python -m goggles_ai.middleware.mcp_server
    python -m goggles_ai.middleware.mcp_server --port 8765

Protocol: newline-delimited JSON over stdin/stdout (stdio transport) OR
          HTTP+SSE transport when --port is given.

Message format (stdio):
  Input:  {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_url","arguments":{...}}}
  Output: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"..."}]}}
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import Any

from goggles_ai.scanner import scan, scan_url as _scan_url, scan_file as _scan_file
from goggles_ai.models import ScanResult

# ── Tool definitions (MCP schema) ─────────────────────────────────────────────

TOOLS = [
    {
        "name": "scan_url",
        "description": (
            "Fetch a URL and scan it for prompt injection, steganography, and cloaking attacks. "
            "Returns a structured threat report with severity ratings and plain-English summaries."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch and scan.",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Enable Tier 3 deep neural-network analysis (slower, requires torch).",
                    "default": False,
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "scan_content",
        "description": (
            "Scan raw content for threats. Accepts text/HTML as a string or binary data "
            "(images) as a base64-encoded string."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Text/HTML string, or base64-encoded binary for images.",
                },
                "content_type": {
                    "type": "string",
                    "description": "MIME type: text/html, text/plain, image/png, image/jpeg, etc.",
                    "default": "text/html",
                },
                "filename": {
                    "type": "string",
                    "description": "Optional filename hint (used for extension-based MIME detection).",
                    "default": "",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Enable Tier 3 deep analysis.",
                    "default": False,
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": "scan_file",
        "description": "Scan a file at a local filesystem path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file.",
                },
                "deep": {
                    "type": "boolean",
                    "description": "Enable Tier 3 deep analysis.",
                    "default": False,
                },
            },
            "required": ["path"],
        },
    },
]


# ── Result serialisation ──────────────────────────────────────────────────────

def _result_to_text(result: ScanResult) -> str:
    lines: list[str] = []
    status = "SAFE" if result.safe else f"UNSAFE — {len(result.threats)} threat(s)"
    lines.append(f"Status: {status}")
    lines.append(f"Confidence: {result.confidence:.0%}")
    lines.append(f"Scan time: {result.scan_time_ms:.1f}ms")

    if result.threats:
        lines.append("")
        lines.append("Threats:")
        for t in result.threats:
            lines.append(f"  [{t.severity.upper()}] {t.label} (Tier {t.tier})")
            lines.append(f"    {t.plain_summary}")
            lines.append(f"    Location: {t.location}")
            lines.append(f"    Technique: {t.technique}")
            lines.append(f"    Outcome: {t.outcome}")

    if result.sanitized_content:
        lines.append("")
        lines.append(f"Sanitized content available ({len(result.sanitized_content)} chars)")

    return "\n".join(lines)


def _result_to_mcp(result: ScanResult) -> dict:
    return {
        "content": [
            {"type": "text", "text": _result_to_text(result)},
            {
                "type": "text",
                "text": result.model_dump_json(indent=2),
                "annotations": {"role": "assistant", "audience": ["developer"]},
            },
        ],
        "isError": False,
    }


def _error_to_mcp(message: str) -> dict:
    return {
        "content": [{"type": "text", "text": f"Error: {message}"}],
        "isError": True,
    }


# ── Tool dispatch ─────────────────────────────────────────────────────────────

async def _dispatch(name: str, arguments: dict) -> dict:
    try:
        if name == "scan_url":
            url = arguments["url"]
            deep = bool(arguments.get("deep", False))
            result = await asyncio.get_event_loop().run_in_executor(None, lambda: _scan_url(url, deep=deep))
            return _result_to_mcp(result)

        elif name == "scan_content":
            raw = arguments["content"]
            content_type = arguments.get("content_type", "text/html")
            filename = arguments.get("filename", "")
            deep = bool(arguments.get("deep", False))

            # Attempt base64 decode for binary content types
            if content_type.startswith("image/"):
                try:
                    content: str | bytes = base64.b64decode(raw)
                except Exception:
                    content = raw
            else:
                content = raw

            result = scan(content, content_type=content_type, filename=filename, deep=deep)
            return _result_to_mcp(result)

        elif name == "scan_file":
            path = arguments["path"]
            deep = bool(arguments.get("deep", False))
            result = _scan_file(path, deep=deep)
            return _result_to_mcp(result)

        else:
            return _error_to_mcp(f"Unknown tool: {name!r}")

    except FileNotFoundError as exc:
        return _error_to_mcp(str(exc))
    except Exception as exc:
        return _error_to_mcp(f"Internal error: {exc}")


# ── JSON-RPC / MCP message handler ────────────────────────────────────────────

async def _handle_message(msg: dict) -> dict | None:
    method = msg.get("method", "")
    msg_id = msg.get("id")

    def _reply(result) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _err(code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    if method == "initialize":
        return _reply({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "goggles-ai", "version": "0.1.0"},
        })

    elif method == "tools/list":
        return _reply({"tools": TOOLS})

    elif method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        result = await _dispatch(name, arguments)
        return _reply(result)

    elif method == "notifications/initialized":
        return None  # no response for notifications

    elif method == "ping":
        return _reply({})

    else:
        return _err(-32601, f"Method not found: {method}")


# ── Stdio transport ───────────────────────────────────────────────────────────

async def _run_stdio() -> None:
    reader = asyncio.StreamReader()
    await asyncio.get_event_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
    )
    writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
        lambda: asyncio.BaseProtocol(), sys.stdout
    )

    async def _write(obj: dict) -> None:
        line = json.dumps(obj, separators=(",", ":")) + "\n"
        sys.stdout.buffer.write(line.encode())
        sys.stdout.buffer.flush()

    while True:
        try:
            line = await reader.readline()
            if not line:
                break
            msg = json.loads(line.decode())
            response = await _handle_message(msg)
            if response is not None:
                await _write(response)
        except json.JSONDecodeError:
            pass
        except Exception:
            break


# ── HTTP+SSE transport ────────────────────────────────────────────────────────

def _make_http_app(port: int):
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, StreamingResponse
    import uvicorn

    app = FastAPI(title="goggles-ai MCP Server")

    @app.post("/mcp")
    async def mcp_endpoint(request: Request):
        msg = await request.json()
        response = await _handle_message(msg)
        if response is None:
            return JSONResponse({}, status_code=204)
        return JSONResponse(response)

    @app.get("/health")
    async def health():
        return {"status": "ok", "server": "goggles-ai-mcp", "version": "0.1.0"}

    return app, port


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv=None) -> None:
    import argparse
    parser = argparse.ArgumentParser(description="goggles-ai MCP Server")
    parser.add_argument("--port", type=int, default=None, help="HTTP port (default: stdio transport)")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)

    if args.port:
        import uvicorn
        app, port = _make_http_app(args.port)
        print(f"goggles-ai MCP server -> http://{args.host}:{port}/mcp", file=sys.stderr)
        uvicorn.run(app, host=args.host, port=port)
    else:
        print("goggles-ai MCP server (stdio transport) ready", file=sys.stderr)
        asyncio.run(_run_stdio())


if __name__ == "__main__":
    main()
