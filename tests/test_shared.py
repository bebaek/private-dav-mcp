from __future__ import annotations

import asyncio
import base64
from typing import Any

import httpx
import pytest

from private_dav_mcp.mcp_http import CachedReadinessCheck, create_mcp_app
from private_dav_mcp.mcp_sdk import build_mcp_sdk_server
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
    with dav.client(timeout_seconds=2) as client:
        assert client.timeout.connect == 2
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


def test_cached_readiness_check_caches_failures_and_successes() -> None:
    now = [0.0]
    failing = [True]
    calls = [0]

    def check() -> None:
        calls[0] += 1
        if failing[0]:
            raise RuntimeError("upstream unavailable")

    readiness = CachedReadinessCheck(check, ttl_seconds=30, clock=lambda: now[0])

    assert readiness.is_ready() is False
    assert readiness.is_ready() is False
    assert calls[0] == 1

    failing[0] = False
    now[0] = 30
    assert readiness.is_ready() is True
    assert readiness.is_ready() is True
    assert calls[0] == 2


def test_cached_readiness_check_without_upstream_is_ready() -> None:
    assert CachedReadinessCheck(None).is_ready() is True
    with pytest.raises(ValueError, match="TTL must be positive"):
        CachedReadinessCheck(None, ttl_seconds=0)


def _test_sdk_server():
    def tool_handler(_name: str, _arguments: dict[str, Any]) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": "ok"}],
            "structuredContent": {"ok": True},
        }

    return build_mcp_sdk_server(
        name="contract-test",
        version="1",
        tools=[
            {
                "name": "test_tool",
                "description": "A test tool.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ],
        tool_handler=tool_handler,
    )


def test_shared_mcp_http_app_handles_results_notifications_and_invalid_payloads() -> None:
    async def run() -> None:
        app = create_mcp_app(title="Contract test", sdk_server=_test_sdk_server())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://mcp.test"
        ) as client:
            live = await client.get("/health/live")
            assert live.status_code == 200
            assert live.json() == {"status": "ok"}

            ready = await client.get("/health/ready")
            assert ready.status_code == 200
            assert ready.json() == {"status": "ready"}

            success = await client.post(
                "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
            assert success.status_code == 200
            assert [tool["name"] for tool in success.json()["result"]["tools"]] == ["test_tool"]

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


def test_shared_mcp_http_app_reports_failed_readiness_without_details() -> None:
    def unavailable() -> None:
        raise RuntimeError("secret upstream details")

    async def run() -> None:
        app = create_mcp_app(
            title="Unavailable test",
            sdk_server=_test_sdk_server(),
            readiness_check=unavailable,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://mcp.test"
        ) as client:
            live = await client.get("/health/live")
            ready = await client.get("/health/ready")

        assert live.status_code == 200
        assert ready.status_code == 503
        assert ready.json() == {"status": "not_ready"}
        assert "secret" not in ready.text

    asyncio.run(run())
