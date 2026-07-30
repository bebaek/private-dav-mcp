from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

CARDDAV_URL = os.environ.get("PRIVATE_DAV_CARDDAV_CONTRACT_URL", "")
CALDAV_URL = os.environ.get("PRIVATE_DAV_CALDAV_CONTRACT_URL", "")
PRIVATE_VALUES_META_KEY = "io.minigent/private-values"
PLACEHOLDER_PATTERN = re.compile(r"\{\{pii:([a-z]+):([^{}:]+)\}\}")

pytestmark = pytest.mark.skipif(
    not CARDDAV_URL or not CALDAV_URL,
    reason=(
        "set PRIVATE_DAV_CARDDAV_CONTRACT_URL and PRIVATE_DAV_CALDAV_CONTRACT_URL "
        "to run black-box container contract tests"
    ),
)


class MCPContractClient:
    def __init__(self, url: str) -> None:
        self._url = url
        self._next_id = 1
        self._client = httpx.Client(timeout=5)

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        response = self._client.post(self._url, json=payload)
        response.raise_for_status()
        body = response.json()
        assert body["jsonrpc"] == "2.0"
        assert body["id"] == request_id
        return body

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        body = self.request("tools/call", {"name": name, "arguments": arguments})
        assert "error" not in body, body.get("error")
        return body["result"]


@pytest.fixture
def carddav() -> Iterator[MCPContractClient]:
    client = MCPContractClient(CARDDAV_URL)
    try:
        yield client
    finally:
        client.close()


@pytest.fixture
def caldav() -> Iterator[MCPContractClient]:
    client = MCPContractClient(CALDAV_URL)
    try:
        yield client
    finally:
        client.close()


def _assert_initialize(client: MCPContractClient, *, server_name: str) -> None:
    body = client.request(
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "private-dav-contract-test", "version": "1"},
        },
    )
    result = body["result"]
    assert result == {
        "protocolVersion": "2025-11-25",
        "serverInfo": {"name": server_name, "version": "0.1.0"},
        "capabilities": {"tools": {}},
    }


def _assert_tool_catalog(client: MCPContractClient, expected_names: list[str]) -> None:
    tools = client.request("tools/list")["result"]["tools"]
    assert [tool["name"] for tool in tools] == expected_names
    for tool in tools:
        assert isinstance(tool["description"], str) and tool["description"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema.get("additionalProperties") is False


def _walk_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def _assert_private_result(result: dict[str, Any]) -> dict[str, str]:
    assert result["content"] and result["content"][0]["type"] == "text"
    structured = result["structuredContent"]
    private_values = result["_meta"][PRIVATE_VALUES_META_KEY]
    assert isinstance(private_values, dict)

    placeholders = [
        match
        for value in _walk_strings(structured)
        for match in PLACEHOLDER_PATTERN.finditer(value)
    ]
    assert {match.group(2) for match in placeholders} == set(private_values)
    for private_value in private_values.values():
        assert private_value not in json.dumps(structured)
        assert private_value not in result["content"][0]["text"]
    return private_values


def test_carddav_container_contract(carddav: MCPContractClient) -> None:
    _assert_initialize(carddav, server_name="minigent-private-contacts")
    _assert_tool_catalog(
        carddav,
        [
            "contacts_list",
            "contacts_get",
            "contacts_create",
            "contacts_update",
            "contacts_delete",
            "contacts_protect_text",
        ],
    )

    listed = carddav.call_tool("contacts_list", {"limit": 10})
    listed_values = _assert_private_result(listed)
    contacts = listed["structuredContent"]["contacts"]
    assert len(contacts) == 2
    assert set(listed_values.values()) == {"Alice Smith", "Bob Jones"}
    assert listed["structuredContent"]["truncated"] is False

    selected = carddav.call_tool(
        "contacts_get",
        {"contact_ref": contacts[0]["contact_ref"], "fields": ["emails", "phones"]},
    )
    selected_values = _assert_private_result(selected)
    assert set(selected_values.values()) == {"alice@example.com", "+1 555 0100"}

    protected = carddav.call_tool("contacts_protect_text", {"text": "Email Alice Smith."})
    protected_values = _assert_private_result(protected)
    assert protected["structuredContent"]["protected_contact_count"] == 1
    assert set(protected_values.values()) == {"Alice Smith"}

    created = carddav.call_tool(
        "contacts_create",
        {"name": "Contract Person", "emails": ["contract@example.test"]},
    )
    _assert_private_result(created)
    created_content = created["structuredContent"]
    assert created_content["status"] == "created"

    updated = carddav.call_tool(
        "contacts_update",
        {"contact_ref": created_content["contact_ref"], "phones": ["+1 555 0199"]},
    )
    _assert_private_result(updated)
    assert updated["structuredContent"] == {
        "status": "updated",
        "contact_ref": created_content["contact_ref"],
    }

    deleted = carddav.call_tool("contacts_delete", {"contact_ref": created_content["contact_ref"]})
    _assert_private_result(deleted)
    assert deleted["structuredContent"] == {"status": "deleted"}

    invalid = carddav.request("tools/call", {"name": "contacts_list", "arguments": {"limit": 0}})
    assert invalid["error"]["code"] == -32602


def test_caldav_container_contract(caldav: MCPContractClient) -> None:
    _assert_initialize(caldav, server_name="minigent-private-calendar")
    _assert_tool_catalog(
        caldav,
        [
            "calendars_list",
            "events_list",
            "events_get",
            "events_create",
            "events_update",
            "events_delete",
        ],
    )

    calendars_result = caldav.call_tool("calendars_list", {})
    calendar_values = _assert_private_result(calendars_result)
    calendar = calendars_result["structuredContent"]["calendars"][0]
    assert set(calendar_values.values()) == {"Personal"}

    created = caldav.call_tool(
        "events_create",
        {
            "calendar_ref": calendar["calendar_ref"],
            "summary": "Contract planning",
            "start": "2026-03-01T09:00:00Z",
            "end": "2026-03-01T10:00:00Z",
            "description": "Contract details",
            "location": "Contract room",
            "attendees": ["attendee@example.test"],
        },
    )
    _assert_private_result(created)
    assert created["structuredContent"]["status"] == "created"

    listed = caldav.call_tool(
        "events_list",
        {
            "calendar_ref": calendar["calendar_ref"],
            "start": "2026-03-01T00:00:00Z",
            "end": "2026-03-02T00:00:00Z",
        },
    )
    listed_values = _assert_private_result(listed)
    event = listed["structuredContent"]["events"][0]
    assert set(listed_values.values()) == {"Contract planning"}
    assert event["available_fields"] == ["description", "location", "attendees"]

    selected = caldav.call_tool(
        "events_get",
        {
            "event_ref": event["event_ref"],
            "fields": ["description", "location", "attendees"],
        },
    )
    selected_values = _assert_private_result(selected)
    assert set(selected_values.values()) == {
        "Contract details",
        "Contract room",
        "attendee@example.test",
    }

    updated = caldav.call_tool(
        "events_update", {"event_ref": event["event_ref"], "summary": "Updated contract"}
    )
    _assert_private_result(updated)
    assert updated["structuredContent"] == {
        "status": "updated",
        "event_ref": event["event_ref"],
    }

    deleted = caldav.call_tool("events_delete", {"event_ref": event["event_ref"]})
    _assert_private_result(deleted)
    assert deleted["structuredContent"] == {"status": "deleted"}

    unbounded = caldav.request(
        "tools/call",
        {
            "name": "events_list",
            "arguments": {
                "calendar_ref": calendar["calendar_ref"],
                "start": "2025-01-01T00:00:00Z",
                "end": "2027-01-02T00:00:00Z",
            },
        },
    )
    assert unbounded["error"]["code"] == -32602
    assert "366 days" in unbounded["error"]["message"]


def test_http_and_json_rpc_error_contract(carddav: MCPContractClient) -> None:
    notification = httpx.post(
        CARDDAV_URL,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        timeout=5,
    )
    assert notification.status_code == 202
    assert not notification.content

    malformed = httpx.post(
        CARDDAV_URL,
        content="{",
        headers={"content-type": "application/json"},
        timeout=5,
    )
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == -32700

    unsupported = carddav.request("resources/list")
    assert unsupported["error"]["code"] == -32601
