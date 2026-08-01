from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
from fastapi.testclient import TestClient
from mcp import Client
from mcp import types as mcp_types
from mcp.shared.message import SessionMessage

from private_dav_mcp.carddav import create_app
from private_dav_mcp.mcp_sdk import SDK_MCP_PROTOCOL_VERSION
from private_dav_mcp.protocol import DEFAULT_MCP_PROTOCOL_VERSION, PRIVATE_VALUES_META_KEY


def test_official_sdk_clients_interoperate_and_preserve_private_metadata() -> None:
    app = create_app()

    with TestClient(app) as http_client:

        async def run() -> None:
            async with Client(_test_transport(http_client, "/mcp")) as sdk_client:
                tools = await sdk_client.list_tools()
                result = await sdk_client.call_tool("contacts_list", {"limit": 10})

                assert sdk_client.protocol_version == SDK_MCP_PROTOCOL_VERSION
                assert sdk_client.server_info is not None
                assert sdk_client.server_info.name == "minigent-private-contacts"
                assert [tool.name for tool in tools.tools] == [
                    "contacts_list",
                    "contacts_get",
                    "contacts_create",
                    "contacts_update",
                    "contacts_delete",
                    "contacts_protect_text",
                ]
                _assert_private_metadata_is_separated(result)

            async with Client(_test_transport(http_client, "/mcp"), mode="legacy") as legacy_client:
                tools = await legacy_client.list_tools()
                result = await legacy_client.call_tool("contacts_list", {"limit": 10})

                assert legacy_client.protocol_version == DEFAULT_MCP_PROTOCOL_VERSION
                assert [tool.name for tool in tools.tools] == [
                    "contacts_list",
                    "contacts_get",
                    "contacts_create",
                    "contacts_update",
                    "contacts_delete",
                    "contacts_protect_text",
                ]
                _assert_private_metadata_is_separated(result)

        asyncio.run(run())


def _assert_private_metadata_is_separated(result: mcp_types.CallToolResult) -> None:
    payload = result.model_dump(by_alias=True, mode="json", exclude_none=True)
    metadata = payload["_meta"]
    assert isinstance(metadata, dict)
    private_values = metadata[PRIVATE_VALUES_META_KEY]
    assert isinstance(private_values, dict)
    assert private_values
    structured = payload["structuredContent"]
    content = payload["content"]
    for reference, private_value in private_values.items():
        assert reference in str(structured)
        assert private_value not in str(structured)
        assert private_value not in str(content)


@asynccontextmanager
async def _test_transport(client: TestClient, path: str) -> AsyncIterator[tuple[Any, Any]]:
    read_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_reader = anyio.create_memory_object_stream[SessionMessage](0)

    async def exchange() -> None:
        async with read_writer, write_reader:
            async for message in write_reader:
                payload = message.message.model_dump(
                    by_alias=True,
                    mode="json",
                    exclude_unset=True,
                )
                response = await asyncio.to_thread(client.post, path, json=payload)
                if response.status_code == 202:
                    continue
                response_message = mcp_types.jsonrpc_message_adapter.validate_python(
                    response.json(), by_name=False
                )
                await read_writer.send(SessionMessage(response_message))

    async with read_stream, write_stream, anyio.create_task_group() as task_group:
        task_group.start_soon(exchange)
        try:
            yield read_stream, write_stream
        finally:
            task_group.cancel_scope.cancel()
