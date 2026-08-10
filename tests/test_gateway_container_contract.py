from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest

from private_dav_mcp import __version__

GATEWAY_URL = os.environ.get("PRIVATE_DAV_GATEWAY_CONTRACT_URL", "")
SIGNING_KEY_PATH = os.environ.get("PRIVATE_DAV_GATEWAY_CONTRACT_SIGNING_KEY", "")
ISSUER = "https://contract-issuer.example"
AUDIENCE = "private-dav-contract"
OWNER_TENANT = "contract-tenant"
OWNER_USER = "contract-user"
PRIVATE_VALUES_META_KEY = "io.minigent/private-values"
_PLACEHOLDER_PATTERN = re.compile(r"\{\{pii:[a-z]+:([^{}:]+)\}\}")

pytestmark = pytest.mark.skipif(
    not GATEWAY_URL or not SIGNING_KEY_PATH,
    reason=(
        "set PRIVATE_DAV_GATEWAY_CONTRACT_URL and "
        "PRIVATE_DAV_GATEWAY_CONTRACT_SIGNING_KEY to run gateway container contracts"
    ),
)


def _token(
    *,
    tenant_id: str = OWNER_TENANT,
    user_id: str = OWNER_USER,
    scopes: str = "dav:calendar:read dav:calendar:write dav:contacts:read dav:contacts:write",
    audience: str = AUDIENCE,
) -> str:
    private_key = Path(SIGNING_KEY_PATH).read_text()
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": audience,
            "sub": user_id,
            "tenant_id": tenant_id,
            "scope": scopes,
            "iat": now,
            "exp": now + 300,
            "jti": f"contract-{tenant_id}-{user_id}-{now}",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "contract-key"},
    )


class GatewayMCPClient:
    def __init__(self, path: str, *, token: str) -> None:
        self._url = f"{GATEWAY_URL}{path}"
        self._client = httpx.Client(
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        self._next_id = 1

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
def owner_contacts() -> Iterator[GatewayMCPClient]:
    client = GatewayMCPClient("/contacts/mcp", token=_token())
    try:
        yield client
    finally:
        client.close()


@pytest.fixture
def owner_calendars() -> Iterator[GatewayMCPClient]:
    client = GatewayMCPClient("/mcp", token=_token())
    try:
        yield client
    finally:
        client.close()


def _private_values(result: dict[str, Any]) -> dict[str, str]:
    values = result["_meta"][PRIVATE_VALUES_META_KEY]
    assert isinstance(values, dict)
    serialized = json.dumps(result["structuredContent"])
    for reference, value in values.items():
        assert "{{pii:" in serialized
        assert reference in serialized
        assert value not in serialized
        assert value not in result["content"][0]["text"]
    return values


def _resolved_placeholder(value: str, private_values: dict[str, str]) -> str:
    match = _PLACEHOLDER_PATTERN.fullmatch(value)
    assert match is not None, value
    return private_values[match.group(1)]


def test_gateway_health_authentication_and_discovery() -> None:
    live = httpx.get(f"{GATEWAY_URL}/health/live", timeout=5)
    ready = httpx.get(f"{GATEWAY_URL}/health/ready", timeout=5)
    assert live.status_code == 200 and live.json() == {"status": "ok"}
    assert ready.status_code == 200 and ready.json() == {"status": "ready"}

    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert httpx.post(f"{GATEWAY_URL}/contacts/mcp", json=payload, timeout=5).status_code == 401
    wrong_audience = httpx.post(
        f"{GATEWAY_URL}/mcp",
        headers={"Authorization": f"Bearer {_token(audience='wrong-audience')}"},
        json=payload,
        timeout=5,
    )
    assert wrong_audience.status_code == 401

    discovery_token = _token(
        tenant_id="discovery-tenant",
        user_id="discovery-user",
        scopes="dav:calendar:read dav:contacts:read",
    )
    contacts = GatewayMCPClient("/contacts/mcp", token=discovery_token)
    calendars = GatewayMCPClient("/mcp", token=discovery_token)
    try:
        initialized = contacts.request("initialize", {})["result"]
        assert initialized["serverInfo"] == {
            "name": "private-dav-gateway-contacts",
            "version": __version__,
        }
        assert [tool["name"] for tool in contacts.request("tools/list")["result"]["tools"]] == [
            "contact_accounts_list",
            "contacts_list",
            "contacts_get",
            "contacts_create",
            "contacts_update",
            "contacts_delete",
            "contacts_protect_text",
        ]
        assert [tool["name"] for tool in calendars.request("tools/list")["result"]["tools"]] == [
            "calendar_accounts_list",
            "calendars_list",
            "events_list",
            "events_get",
            "free_busy",
            "events_create",
            "events_update",
            "events_delete",
        ]
    finally:
        contacts.close()
        calendars.close()


def test_gateway_static_sources_and_private_envelopes(
    owner_contacts: GatewayMCPClient,
    owner_calendars: GatewayMCPClient,
) -> None:
    listed_contacts = owner_contacts.call_tool("contacts_list", {"limit": 10})
    contact_values = _private_values(listed_contacts)
    contacts = listed_contacts["structuredContent"]["contacts"]
    assert len(contacts) == 1
    assert set(contact_values.values()) == {"Contract Contact"}

    selected_contact = owner_contacts.call_tool(
        "contacts_get",
        {"contact_ref": contacts[0]["contact_ref"], "fields": ["emails", "phones"]},
    )
    assert set(_private_values(selected_contact).values()) == {
        "contact@example.test",
        "+1 555 0198",
    }

    account_result = owner_calendars.call_tool("calendar_accounts_list", {})
    assert len(account_result["structuredContent"]["accounts"]) == 2
    assert set(_private_values(account_result).values()) == {
        "Contract CalDAV",
        "Contract ICS",
    }

    calendar_result = owner_calendars.call_tool("calendars_list", {})
    assert calendar_result["structuredContent"]["partial"] is False
    calendars = calendar_result["structuredContent"]["calendars"]
    calendar_values = _private_values(calendar_result)
    assert {_resolved_placeholder(calendar["name"], calendar_values) for calendar in calendars} == {
        "Contract Calendar",
        "Contract ICS",
    }

    summaries: set[str] = set()
    event_refs: list[str] = []
    for calendar in calendars:
        events = owner_calendars.call_tool(
            "events_list",
            {
                "calendar_ref": calendar["calendar_ref"],
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-03T00:00:00Z",
            },
        )
        values = _private_values(events)
        summaries.update(values.values())
        event_refs.extend(event["event_ref"] for event in events["structuredContent"]["events"])
    assert {"Contract Calendar Event", "Contract Subscription Event"} <= summaries
    assert len(event_refs) == 2


def test_gateway_rejects_wrong_owner_scopes_and_cross_owner_references(
    owner_contacts: GatewayMCPClient,
    owner_calendars: GatewayMCPClient,
) -> None:
    contact = owner_contacts.call_tool("contacts_list", {"limit": 10})["structuredContent"][
        "contacts"
    ][0]
    calendar = owner_calendars.call_tool("calendars_list", {})["structuredContent"]["calendars"][0]
    event = owner_calendars.call_tool(
        "events_list",
        {
            "calendar_ref": calendar["calendar_ref"],
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-03T00:00:00Z",
        },
    )["structuredContent"]["events"][0]

    other_token = _token(tenant_id="other-tenant", user_id="other-user")
    other_contacts = GatewayMCPClient("/contacts/mcp", token=other_token)
    other_calendars = GatewayMCPClient("/mcp", token=other_token)
    try:
        wrong_owner_contact = other_contacts.request(
            "tools/call",
            {"name": "contacts_get", "arguments": {"contact_ref": contact["contact_ref"]}},
        )
        assert wrong_owner_contact["error"]["code"] == -32001

        other_accounts = other_calendars.call_tool("calendar_accounts_list", {})
        assert other_accounts["structuredContent"]["accounts"] == []
        cross_owner_event = other_calendars.request(
            "tools/call",
            {"name": "events_get", "arguments": {"event_ref": event["event_ref"]}},
        )
        assert cross_owner_event["error"]["code"] == -32001

        denied_contact = httpx.post(
            f"{GATEWAY_URL}/contacts/mcp",
            headers={"Authorization": f"Bearer {_token(scopes='dav:calendar:read')}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "contacts_list", "arguments": {}},
            },
            timeout=5,
        )
        assert denied_contact.status_code == 403
        assert denied_contact.json()["error"]["code"] == "permission_denied"
        denied_calendar = httpx.post(
            f"{GATEWAY_URL}/mcp",
            headers={"Authorization": f"Bearer {_token(scopes='dav:contacts:read')}"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "calendars_list", "arguments": {}},
            },
            timeout=5,
        )
        assert denied_calendar.status_code == 403
        assert denied_calendar.json()["error"]["code"] == "permission_denied"
    finally:
        other_contacts.close()
        other_calendars.close()
