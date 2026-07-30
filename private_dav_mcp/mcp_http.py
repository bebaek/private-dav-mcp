from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

MCPHandler = Callable[[dict[str, Any]], dict[str, Any] | None]
ReadinessCheck = Callable[[], None]
DEFAULT_READINESS_CACHE_TTL_SECONDS = 30.0


class CachedReadinessCheck:
    """Serialize and cache readiness probes so health polling does not hammer DAV."""

    def __init__(
        self,
        check: ReadinessCheck | None,
        *,
        ttl_seconds: float = DEFAULT_READINESS_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("readiness cache TTL must be positive")
        self._check = check
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._expires_at = 0.0
        self._ready = False

    def is_ready(self) -> bool:
        if self._check is None:
            return True
        with self._lock:
            now = self._clock()
            if now < self._expires_at:
                return self._ready
            try:
                self._check()
            except Exception:
                self._ready = False
            else:
                self._ready = True
            self._expires_at = self._clock() + self._ttl_seconds
            return self._ready


def create_mcp_app(
    *,
    title: str,
    handler: MCPHandler,
    readiness_check: ReadinessCheck | None = None,
    readiness_cache_ttl_seconds: float = DEFAULT_READINESS_CACHE_TTL_SECONDS,
) -> FastAPI:
    app = FastAPI(title=title)
    cached_readiness = CachedReadinessCheck(
        readiness_check, ttl_seconds=readiness_cache_ttl_seconds
    )

    @app.get("/health/live", response_model=None)
    async def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", response_model=None)
    async def health_ready() -> Response | dict[str, str]:
        if await asyncio.to_thread(cached_readiness.is_ready):
            return {"status": "ready"}
        return JSONResponse(status_code=503, content={"status": "not_ready"})

    @app.post("/mcp", response_model=None)
    async def mcp_endpoint(request: Request) -> Response | dict[str, Any]:
        try:
            payload = await request.json()
        except ValueError:
            return _invalid_request_response(-32700, "Invalid JSON")
        if not isinstance(payload, dict):
            return _invalid_request_response(-32600, "Payload must be an object")
        result = await asyncio.to_thread(handler, payload)
        if result is None:
            return Response(status_code=202)
        return result

    return app


def _invalid_request_response(code: int, message: str) -> Response:
    return Response(
        content=json.dumps(
            {"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}}
        ),
        status_code=400,
        media_type="application/json",
    )
