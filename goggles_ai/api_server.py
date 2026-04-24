"""goggles-ai FastAPI server.

Endpoints:
  POST /scan/url        — scan a URL (JSON body: {"url": "...", "deep": false})
  POST /scan/content    — scan raw content (JSON body or multipart file)
  POST /scan/file       — scan an uploaded file (multipart)
  GET  /history         — paginated scan history
  GET  /history/{id}    — single scan result by ID
  DELETE /history       — clear all history
  GET  /stats           — aggregate statistics
  GET  /health          — health check
  WS   /ws/scan         — WebSocket: send URL/content, receive streaming scan events

Run:
    uvicorn goggles_ai.api_server:app --reload --port 8000

Or:
    python -m goggles_ai.api_server
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from collections import deque
from typing import Annotated, Deque, Optional

from fastapi import (
    FastAPI, File, Form, HTTPException, Query,
    UploadFile, WebSocket, WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from goggles_ai.scanner import scan, scan_url as _scan_url, scan_file as _scan_file
from goggles_ai.models import ScanResult, Threat

# ── In-memory history store ───────────────────────────────────────────────────

_MAX_HISTORY = 500


class _HistoryEntry(BaseModel):
    id: str
    timestamp: float
    source: str          # url / content / file
    source_hint: str     # URL, filename, or content_type
    result: ScanResult


_history: Deque[_HistoryEntry] = deque(maxlen=_MAX_HISTORY)
_history_index: dict[str, _HistoryEntry] = {}


def _record(source: str, hint: str, result: ScanResult) -> _HistoryEntry:
    entry = _HistoryEntry(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        source=source,
        source_hint=hint,
        result=result,
    )
    _history.append(entry)
    _history_index[entry.id] = entry
    # Evict index entries for items that fell off the deque
    if len(_history_index) > _MAX_HISTORY * 2:
        live_ids = {e.id for e in _history}
        stale = [k for k in _history_index if k not in live_ids]
        for k in stale:
            del _history_index[k]
    return entry


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="goggles-ai API",
    description="Inspection layer for AI agent inputs",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response models ─────────────────────────────────────────────────

class ScanUrlRequest(BaseModel):
    url: str = Field(description="URL to fetch and scan")
    deep: bool = Field(default=False, description="Enable Tier 3 deep analysis")


class ScanContentRequest(BaseModel):
    content: str = Field(description="Text/HTML string or base64-encoded binary for images")
    content_type: str = Field(default="text/html", description="MIME type of the content")
    filename: str = Field(default="", description="Optional filename hint")
    deep: bool = Field(default=False)


class ScanResponse(BaseModel):
    id: str
    timestamp: float
    safe: bool
    confidence: float
    threat_count: int
    max_severity: Optional[str]
    scan_time_ms: float
    threats: list[dict]
    sanitized_content: Optional[str] = None
    tier_timings: dict[str, float]


def _to_scan_response(entry: _HistoryEntry) -> ScanResponse:
    r = entry.result
    return ScanResponse(
        id=entry.id,
        timestamp=entry.timestamp,
        safe=r.safe,
        confidence=r.confidence,
        threat_count=len(r.threats),
        max_severity=r.max_severity,
        scan_time_ms=r.scan_time_ms,
        threats=[t.model_dump() for t in r.threats],
        sanitized_content=r.sanitized_content,
        tier_timings=r.tier_timings,
    )


# ── Scan endpoints ────────────────────────────────────────────────────────────

@app.post("/scan/url", response_model=ScanResponse, tags=["scan"])
async def scan_url_endpoint(request: ScanUrlRequest):
    """Fetch a URL and scan it for threats."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, lambda: _scan_url(request.url, deep=request.deep)
        )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    entry = _record("url", request.url, result)
    return _to_scan_response(entry)


@app.post("/scan/content", response_model=ScanResponse, tags=["scan"])
async def scan_content_endpoint(request: ScanContentRequest):
    """Scan raw content (text, HTML, or base64-encoded image)."""
    raw: str | bytes = request.content
    if request.content_type.startswith("image/"):
        try:
            raw = base64.b64decode(request.content)
        except Exception:
            pass

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: scan(raw, content_type=request.content_type, filename=request.filename, deep=request.deep),
    )
    hint = request.filename or request.content_type
    entry = _record("content", hint, result)
    return _to_scan_response(entry)


@app.post("/scan/file", response_model=ScanResponse, tags=["scan"])
async def scan_file_endpoint(
    file: UploadFile = File(description="File to scan"),
    deep: bool = Form(default=False),
):
    """Scan an uploaded file."""
    import tempfile, os

    content = await file.read()
    filename = file.filename or ""
    content_type = file.content_type or "application/octet-stream"

    # Write to temp file so scan_file can infer MIME from extension
    suffix = os.path.splitext(filename)[1] if filename else ""
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, lambda: _scan_file(tmp_path, deep=deep))
    finally:
        os.unlink(tmp_path)

    entry = _record("file", filename or "uploaded_file", result)
    return _to_scan_response(entry)


# ── History endpoints ─────────────────────────────────────────────────────────

class HistoryItem(BaseModel):
    id: str
    timestamp: float
    source: str
    source_hint: str
    safe: bool
    threat_count: int
    max_severity: Optional[str]
    scan_time_ms: float


@app.get("/history", tags=["history"])
async def get_history(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    safe_only: Optional[bool] = Query(default=None),
):
    """Return paginated scan history (newest first)."""
    items = list(reversed(list(_history)))
    if safe_only is not None:
        items = [e for e in items if e.result.safe == safe_only]

    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            HistoryItem(
                id=e.id,
                timestamp=e.timestamp,
                source=e.source,
                source_hint=e.source_hint,
                safe=e.result.safe,
                threat_count=len(e.result.threats),
                max_severity=e.result.max_severity,
                scan_time_ms=e.result.scan_time_ms,
            )
            for e in page_items
        ],
    }


@app.get("/history/{scan_id}", response_model=ScanResponse, tags=["history"])
async def get_history_item(scan_id: str):
    """Return a single scan result by ID."""
    entry = _history_index.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_scan_response(entry)


@app.delete("/history", tags=["history"])
async def clear_history():
    """Clear all scan history."""
    _history.clear()
    _history_index.clear()
    return {"cleared": True}


# ── Stats endpoint ────────────────────────────────────────────────────────────

@app.get("/stats", tags=["stats"])
async def get_stats():
    """Aggregate statistics over all scan history."""
    items = list(_history)
    if not items:
        return {
            "total_scans": 0,
            "safe_count": 0,
            "unsafe_count": 0,
            "threat_type_counts": {},
            "severity_counts": {},
            "mean_scan_time_ms": 0,
            "scan_sources": {},
        }

    safe_count = sum(1 for e in items if e.result.safe)
    threat_type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    scan_sources: dict[str, int] = {}
    total_time = 0.0

    for entry in items:
        scan_sources[entry.source] = scan_sources.get(entry.source, 0) + 1
        total_time += entry.result.scan_time_ms
        for t in entry.result.threats:
            threat_type_counts[t.type] = threat_type_counts.get(t.type, 0) + 1
            severity_counts[t.severity] = severity_counts.get(t.severity, 0) + 1

    return {
        "total_scans": len(items),
        "safe_count": safe_count,
        "unsafe_count": len(items) - safe_count,
        "threat_type_counts": dict(sorted(threat_type_counts.items(), key=lambda x: -x[1])),
        "severity_counts": severity_counts,
        "mean_scan_time_ms": round(total_time / len(items), 2),
        "scan_sources": scan_sources,
    }


# ── Health endpoint ───────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
async def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "history_count": len(_history),
    }


# ── WebSocket /ws/scan ────────────────────────────────────────────────────────

@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    """WebSocket scan endpoint.

    Client sends JSON: {"type": "scan_url"|"scan_content", ...fields}
    Server responds with a stream of events:
      {"event": "start",    "id": "...", "source": "..."}
      {"event": "tier",     "tier": 1, "time_ms": 0.3}
      {"event": "threat",   "threat": {...}}
      {"event": "complete", "result": {...}}
      {"event": "error",    "message": "..."}
    """
    await websocket.accept()

    async def _send(obj: dict) -> None:
        await websocket.send_text(json.dumps(obj))

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type", "")
            scan_id = str(uuid.uuid4())

            await _send({"event": "start", "id": scan_id, "source": msg_type})

            try:
                loop = asyncio.get_event_loop()

                if msg_type == "scan_url":
                    url = msg.get("url", "")
                    deep = bool(msg.get("deep", False))
                    await _send({"event": "progress", "message": f"Fetching {url}…"})
                    result = await loop.run_in_executor(None, lambda: _scan_url(url, deep=deep))
                    hint = url

                elif msg_type == "scan_content":
                    content = msg.get("content", "")
                    content_type = msg.get("content_type", "text/html")
                    filename = msg.get("filename", "")
                    deep = bool(msg.get("deep", False))
                    raw_content: str | bytes = content
                    if content_type.startswith("image/"):
                        try:
                            raw_content = base64.b64decode(content)
                        except Exception:
                            pass
                    await _send({"event": "progress", "message": "Scanning content…"})
                    result = await loop.run_in_executor(
                        None,
                        lambda: scan(raw_content, content_type=content_type, filename=filename, deep=deep),
                    )
                    hint = filename or content_type

                else:
                    await _send({"event": "error", "message": f"Unknown type: {msg_type!r}"})
                    continue

                # Emit tier timings
                for tier_name, timing in result.tier_timings.items():
                    await _send({"event": "tier", "tier": tier_name, "time_ms": timing})

                # Emit individual threats
                for threat in result.threats:
                    await _send({"event": "threat", "threat": threat.model_dump()})

                # Record + emit final result
                entry = _record(msg_type.replace("scan_", ""), hint, result)
                response = _to_scan_response(entry)
                await _send({
                    "event": "complete",
                    "id": entry.id,
                    "result": response.model_dump(),
                })

            except Exception as exc:
                await _send({"event": "error", "message": str(exc)})

    except WebSocketDisconnect:
        pass


# ── Dev entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("goggles_ai.api_server:app", host="0.0.0.0", port=8000, reload=True)
