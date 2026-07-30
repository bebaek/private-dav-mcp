from __future__ import annotations

import asyncio
import base64
from typing import Any

import httpx
import pytest

from private_dav_mcp.mcp_http import create_mcp_app
from private_dav_mcp.webdav import (
    DAVHTTPClient,
    url_origin,
    validate_http_url,
    validate_same_origin_url,
    xml_headers,
)


def _dav_client(
    *,
    auth_mode: str = "auto",
    transport: httpx.BaseTransport | None = None,
    max_response_bytes: int = 100,
) -> DAVHTTPClient:
    return DAVHTTPClient(
        protocol_name="TestDAV",
        username="user",
        password="password",
        auth_mode=auth_mode,
        verify_tls=True,
        timeout_seconds=5,
        max_response_bytes=max_response_bytes,
        response_size_message="response too large",
        changed_message="resource changed",
        not_found_message="resource missing",
        transport=transport,
    )


def test_dav_http_client_configures_basic_auth_and_headers() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(207)

    dav = _dav_client(auth_mode="basic", transport=httpx.MockTransport(handler))
    with dav.client() as client:
        response, auth = dav.request_with_auth_negotiation(
            client,
            "PROPFIND",
            "https://dav.example/root/",
            headers=xml_headers(depth="0"),
            operation="discovery",
        )

    assert response.status_code == 207
    assert isinstance(auth, httpx.BasicAuth)
    assert requests[0].headers["depth"] == "0"
    encoded_credentials = base64.b64encode(b"user:password").decode()
    assert requests[0].headers["authorization"] == f"Basic {encoded_credentials}"


@pytest.mark.parametrize(
    ("status_code", "message"),
    [(404, "resource missing"), (412, "resource changed"), (500, "HTTP 500")],
)
def test_dav_http_client_translates_status_errors(status_code: int, message: str) -> None:
    dav = _dav_client(transport=httpx.MockTransport(lambda _request: httpx.Response(status_code)))

    with dav.client() as client, pytest.raises(RuntimeError, match=message):
        dav.request(
            client,
            "GET",
            "https://dav.example/root/item",
            auth=None,
            headers={},
        )


def test_dav_http_client_enforces_response_size() -> None:
    dav = _dav_client(max_response_bytes=3)

    dav.check_response_size(b"123")
    with pytest.raises(RuntimeError, match="response too large"):
        dav.check_response_size(b"1234")


def test_shared_url_validation_normalizes_default_ports_and_rejects_credentials() -> None:
    assert url_origin("https://DAV.example/path") == ("https", "dav.example", 443)
    validate_same_origin_url(
        "https://dav.example:443/other", base_url="https://dav.example/root", label="resource"
    )

    with pytest.raises(RuntimeError, match="cross-origin"):
        validate_same_origin_url(
            "https://other.example/root",
            base_url="https://dav.example/root",
            label="resource",
        )
    with pytest.raises(ValueError, match="embedded credentials"):
        validate_http_url("https://user:password@dav.example/root", label="DAV URL")


def test_shared_mcp_http_app_handles_results_notifications_and_invalid_payloads() -> None:
    def handler(payload: dict[str, Any]) -> dict[str, Any] | None:
        if payload.get("id") is None:
            return None
        return {"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}}

    async def run() -> None:
        app = create_mcp_app(title="Contract test", handler=handler)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://mcp.test"
        ) as client:
            success = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            assert success.status_code == 200
            assert success.json()["result"] == {"ok": True}

            notification = await client.post(
                "/mcp", json={"jsonrpc": "2.0", "method": "initialized"}
            )
            assert notification.status_code == 202
            assert not notification.content

            malformed = await client.post(
                "/mcp", content="{", headers={"content-type": "application/json"}
            )
            assert malformed.status_code == 400
            assert malformed.json()["error"]["code"] == -32700

            array_payload = await client.post("/mcp", json=[])
            assert array_payload.status_code == 400
            assert array_payload.json()["error"]["code"] == -32600

    asyncio.run(run())
