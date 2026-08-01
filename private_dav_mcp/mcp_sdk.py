from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

import anyio
from mcp import types as mcp_types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError
from mcp.shared.message import SessionMessage
from starlette.concurrency import run_in_threadpool

from private_dav_mcp.protocol import DEFAULT_MCP_PROTOCOL_VERSION

SDK_MCP_PROTOCOL_VERSION = mcp_types.LATEST_PROTOCOL_VERSION
MCPToolHandler = Callable[[str, dict[str, Any]], dict[str, Any]]


class MCPToolCallFailure(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def extract_mcp_tool_result(response: dict[str, Any]) -> dict[str, Any]:
    error = response.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        message = error.get("message")
        raise MCPToolCallFailure(
            code if isinstance(code, int) else -32000,
            message if isinstance(message, str) else "MCP tool call failed",
        )
    result = response.get("result")
    if not isinstance(result, dict):
        raise MCPToolCallFailure(-32603, "MCP tool handler returned an invalid result")
    return result


def build_mcp_sdk_server(
    *,
    name: str,
    version: str,
    tools: Sequence[dict[str, Any]],
    tool_handler: MCPToolHandler,
) -> Server[Any]:
    """Build an SDK server whose handlers call domain tool operations directly."""

    sdk_server: Server[Any] = Server(name, version=version)
    sdk_tools = [mcp_types.Tool.model_validate(tool) for tool in tools]

    async def list_tools(
        _context: ServerRequestContext[Any, Any],
        _params: mcp_types.PaginatedRequestParams,
    ) -> mcp_types.ListToolsResult:
        return mcp_types.ListToolsResult(tools=sdk_tools)

    async def call_tool(
        _context: ServerRequestContext[Any, Any],
        params: mcp_types.CallToolRequestParams,
    ) -> mcp_types.CallToolResult:
        try:
            result = await run_in_threadpool(
                tool_handler,
                params.name,
                params.arguments or {},
            )
        except MCPToolCallFailure as exc:
            raise MCPError(code=exc.code, message=exc.message) from exc
        return mcp_types.CallToolResult.model_validate(result)

    sdk_server.add_request_handler(
        "tools/list",
        mcp_types.PaginatedRequestParams,
        list_tools,
    )
    sdk_server.add_request_handler(
        "tools/call",
        mcp_types.CallToolRequestParams,
        call_tool,
    )
    return sdk_server


async def run_mcp_sdk_request(
    sdk_server: Server[Any], payload: dict[str, Any]
) -> dict[str, object] | None:
    """Run one stateless JSON-RPC request through the MCP SDK server core."""

    if "id" not in payload:
        return None
    sdk_payload = _sdk_compatible_payload(payload)
    try:
        message = mcp_types.jsonrpc_message_adapter.validate_python(sdk_payload, by_name=False)
    except ValueError:
        return mcp_jsonrpc_error(payload.get("id"), -32600, "Invalid Request")
    if not isinstance(message, mcp_types.JSONRPCRequest):
        return mcp_jsonrpc_error(payload.get("id"), -32600, "Invalid Request")

    read_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_reader = anyio.create_memory_object_stream[SessionMessage](0)
    response: SessionMessage | None = None
    async with (
        read_writer,
        read_stream,
        write_stream,
        write_reader,
        anyio.create_task_group() as task_group,
    ):
        task_group.start_soon(
            sdk_server.run,
            read_stream,
            write_stream,
            sdk_server.create_initialization_options(),
        )
        await read_writer.send(SessionMessage(message))
        response = await write_reader.receive()
        await read_writer.aclose()
        task_group.cancel_scope.cancel()

    if response is None:  # pragma: no cover - receive() either returns or raises
        return mcp_jsonrpc_error(payload.get("id"), -32603, "MCP SDK returned no response")
    response_message = response.message
    if not isinstance(response_message, (mcp_types.JSONRPCResponse, mcp_types.JSONRPCError)):
        return mcp_jsonrpc_error(payload.get("id"), -32603, "Invalid MCP SDK response")
    return _external_response_payload(
        payload,
        response_message.model_dump(by_alias=True, mode="json", exclude_none=True),
    )


def mcp_jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _sdk_compatible_payload(payload: dict[str, Any]) -> dict[str, Any]:
    sdk_payload = dict(payload)
    raw_params = payload.get("params")
    if raw_params is not None and not isinstance(raw_params, dict):
        return sdk_payload
    params = dict(raw_params) if isinstance(raw_params, dict) else {}
    if payload.get("method") == "initialize":
        params["protocolVersion"] = SDK_MCP_PROTOCOL_VERSION
        params.setdefault("capabilities", {})
        params.setdefault(
            "clientInfo",
            {"name": "private-dav-mcp-http-client", "version": "1"},
        )
    else:
        raw_meta = params.get("_meta")
        metadata = dict(raw_meta) if isinstance(raw_meta, dict) else {}
        metadata["io.modelcontextprotocol/protocolVersion"] = SDK_MCP_PROTOCOL_VERSION
        metadata.setdefault(
            "io.modelcontextprotocol/clientInfo",
            {"name": "private-dav-mcp-http-client", "version": "1"},
        )
        metadata.setdefault("io.modelcontextprotocol/clientCapabilities", {})
        params["_meta"] = metadata
    sdk_payload["params"] = params
    return sdk_payload


def _external_response_payload(request: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    if _requested_protocol_version(request) == SDK_MCP_PROTOCOL_VERSION:
        return response
    normalized = dict(response)
    result = normalized.get("result")
    if not isinstance(result, dict):
        return normalized
    legacy_result = dict(result)
    if request.get("method") == "initialize":
        legacy_result["protocolVersion"] = DEFAULT_MCP_PROTOCOL_VERSION
        legacy_result["capabilities"] = {"tools": {}}
    for key in ("resultType", "ttlMs", "cacheScope"):
        legacy_result.pop(key, None)
    normalized["result"] = legacy_result
    return normalized


def _requested_protocol_version(payload: dict[str, Any]) -> str:
    params = payload.get("params")
    if isinstance(params, dict):
        if payload.get("method") == "initialize":
            version = params.get("protocolVersion")
            if isinstance(version, str) and version:
                return version
        metadata = params.get("_meta")
        if isinstance(metadata, dict):
            version = metadata.get("io.modelcontextprotocol/protocolVersion")
            if isinstance(version, str) and version:
                return version
    return DEFAULT_MCP_PROTOCOL_VERSION
