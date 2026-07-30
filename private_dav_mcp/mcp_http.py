from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response

MCPHandler = Callable[[dict[str, Any]], dict[str, Any] | None]


def create_mcp_app(*, title: str, handler: MCPHandler) -> FastAPI:
    app = FastAPI(title=title)

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
