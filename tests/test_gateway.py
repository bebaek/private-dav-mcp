from __future__ import annotations

import base64
import json
import stat
import time
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from private_dav_mcp.caldav import Calendar, Event, PrivateCalendarMCPServer
from private_dav_mcp.gateway import (
    AccountConnectionError,
    GatewaySettings,
    OutboundURLPolicy,
    create_gateway_app,
)
from private_dav_mcp.gateway_identity import GatewayIdentity, IdentityError, IdentityVerifier
from private_dav_mcp.gateway_mcp import (
    GatewayCalendarMCP,
    StaticCalendarAccount,
    StaticICSSubscription,
)
from private_dav_mcp.gateway_store import AccountCipher, AccountStore, GatewayAccount
from private_dav_mcp.ics import ICSSubscriptionCalendarSource

ISSUER = "https://minigent.example"
AUDIENCE = "private-dav"


class FakeConnector:
    def __init__(self) -> None:
        self.calls: list[GatewayAccount] = []

    def test(self, account: GatewayAccount) -> int:
        self.calls.append(account)
        if account.credential.password == "bad-password":
            raise AccountConnectionError("authentication_failed")
        return 2


@pytest.fixture(scope="module")
def signing_keys() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def gateway(
    tmp_path: Path, signing_keys: tuple[str, str]
) -> tuple[TestClient, str, FakeConnector, Path]:
    private_pem, public_pem = signing_keys
    verifier = IdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        public_keys={"test-key": public_pem},
        leeway_seconds=0,
    )
    db_path = tmp_path / "gateway.db"
    store = AccountStore(db_path, cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1))
    connector = FakeConnector()
    policy = OutboundURLPolicy(resolver=lambda _host: ["93.184.216.34"])
    calendar_mcp = GatewayCalendarMCP(
        store,
        server_factory=lambda _account: PrivateCalendarMCPServer(
            calendars=[Calendar("Personal", "https://dav.example/personal/")],
            events=[Event("Private meeting", "2026-08-01T14:00:00Z", "2026-08-01T15:00:00Z")],
        ),
    )
    app = create_gateway_app(
        verifier=verifier,
        store=store,
        connector=connector,
        url_policy=policy,
        calendar_mcp=calendar_mcp,
    )
    return TestClient(app), private_pem, connector, db_path


def _token(
    private_pem: str,
    *,
    tenant_id: str = "tenant-a",
    user_id: str = "user-a",
    scopes: str = ("dav:accounts:read dav:accounts:write dav:calendar:read dav:calendar:write"),
    audience: str = AUDIENCE,
) -> str:
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
            "jti": f"token-{tenant_id}-{user_id}-{now}",
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _headers(private_pem: str, **claims: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(private_pem, **claims)}"}


def _account_payload(*, password: str = "secret-canary") -> dict[str, Any]:
    return {
        "kind": "caldav",
        "label": "Private calendar canary",
        "base_url": "https://dav.example/dav.php",
        "auth": {
            "type": "password",
            "username": "alice@example.com",
            "password": password,
            "mode": "auto",
        },
        "enabled": True,
    }


def test_identity_verifier_rejects_wrong_audience(signing_keys: tuple[str, str]) -> None:
    private_pem, public_pem = signing_keys
    verifier = IdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        public_keys={"test-key": public_pem},
        leeway_seconds=0,
    )

    with pytest.raises(IdentityError):
        verifier.verify(_token(private_pem, audience="another-service"))


def test_account_lifecycle_is_owner_scoped_and_credentials_are_write_only(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, connector, db_path = gateway
    owner_headers = _headers(private_pem)
    create_response = client.post(
        "/v1/accounts",
        headers={**owner_headers, "Idempotency-Key": "create-personal"},
        json=_account_payload(),
    )

    assert create_response.status_code == 201, create_response.text
    created = create_response.json()
    account_ref = created["account_ref"]
    assert created["calendar_count"] == 2
    assert created["label"] == "Private calendar canary"
    assert created["username_hint"] == "a…@example.com"
    assert "password" not in created
    assert "secret-canary" not in create_response.text
    assert len(connector.calls) == 1
    assert "secret-canary" not in repr(connector.calls[0])
    assert "alice@example.com" not in repr(connector.calls[0].credential)

    idempotent_response = client.post(
        "/v1/accounts",
        headers={**owner_headers, "Idempotency-Key": "create-personal"},
        json=_account_payload(),
    )
    assert idempotent_response.status_code == 201
    assert idempotent_response.json()["account_ref"] == account_ref

    listed = client.get("/v1/accounts", headers=owner_headers)
    assert listed.status_code == 200
    assert [account["account_ref"] for account in listed.json()["accounts"]] == [account_ref]

    other_user = client.get(
        f"/v1/accounts/{account_ref}",
        headers=_headers(private_pem, user_id="user-b"),
    )
    assert other_user.status_code == 404
    assert other_user.json()["error"]["code"] == "not_found"

    patched = client.patch(
        f"/v1/accounts/{account_ref}",
        headers=owner_headers,
        json={"label": "Renamed calendar"},
    )
    assert patched.status_code == 200
    assert patched.json()["label"] == "Renamed calendar"

    tested = client.post(f"/v1/accounts/{account_ref}/test", headers=owner_headers)
    assert tested.status_code == 200
    assert tested.json()["calendar_count"] == 2

    failed_rotation = client.patch(
        f"/v1/accounts/{account_ref}",
        headers=owner_headers,
        json={
            "auth": {
                "type": "password",
                "username": "replacement@example.com",
                "password": "bad-password",
                "mode": "digest",
            }
        },
    )
    assert failed_rotation.status_code == 422
    assert failed_rotation.json()["error"]["code"] == "authentication_failed"

    retained = client.post(f"/v1/accounts/{account_ref}/test", headers=owner_headers)
    assert retained.status_code == 200
    assert connector.calls[-1].credential.password == "secret-canary"

    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600
    for database_file in db_path.parent.glob("gateway.db*"):
        content = database_file.read_bytes()
        assert b"secret-canary" not in content
        assert b"Private calendar canary" not in content
        assert b"alice@example.com" not in content

    deleted = client.delete(f"/v1/accounts/{account_ref}", headers=owner_headers)
    assert deleted.status_code == 204
    assert client.get(f"/v1/accounts/{account_ref}", headers=owner_headers).status_code == 404


def _mcp(
    client: TestClient,
    headers: dict[str, str],
    method: str,
    params: dict[str, Any] | None = None,
    *,
    request_id: int = 1,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    response = client.post("/mcp", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_gateway_mcp_routes_accounts_calendars_and_free_busy_by_owner(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    headers = _headers(private_pem)
    created = client.post("/v1/accounts", headers=headers, json=_account_payload())
    assert created.status_code == 201

    initialized = _mcp(client, headers, "initialize", {})
    assert initialized["result"]["serverInfo"]["name"] == "private-dav-gateway"
    tools = _mcp(client, headers, "tools/list")["result"]["tools"]
    assert [tool["name"] for tool in tools] == [
        "calendar_accounts_list",
        "calendars_list",
        "events_list",
        "events_get",
        "free_busy",
        "events_create",
        "events_update",
        "events_delete",
    ]

    accounts = _mcp(
        client,
        headers,
        "tools/call",
        {"name": "calendar_accounts_list", "arguments": {}},
    )["result"]
    assert len(accounts["structuredContent"]["accounts"]) == 1
    assert "Private calendar canary" not in str(accounts["structuredContent"])
    assert set(accounts["_meta"]["io.minigent/private-values"].values()) == {
        "Private calendar canary"
    }

    calendars = _mcp(
        client,
        headers,
        "tools/call",
        {"name": "calendars_list", "arguments": {}},
    )["result"]
    calendar_ref = calendars["structuredContent"]["calendars"][0]["calendar_ref"]
    busy = _mcp(
        client,
        headers,
        "tools/call",
        {
            "name": "free_busy",
            "arguments": {
                "calendar_refs": [calendar_ref],
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )["result"]["structuredContent"]
    assert busy == {
        "busy": [{"start": "2026-08-01T14:00:00Z", "end": "2026-08-01T15:00:00Z"}],
        "truncated": False,
        "partial": False,
        "queried_calendar_count": 1,
        "failed_calendar_count": 0,
    }

    cross_owner = _mcp(
        client,
        _headers(private_pem, user_id="user-b"),
        "tools/call",
        {
            "name": "free_busy",
            "arguments": {
                "calendar_ref": calendar_ref,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )
    assert cross_owner["error"]["code"] == -32002
    assert "Private" not in str(cross_owner)


def test_gateway_reports_per_feed_ics_health(tmp_path: Path) -> None:
    now = [100.0]
    responses = iter(
        (
            httpx.Response(200, content=b"BEGIN:VCALENDAR\nVERSION:2.0\nEND:VCALENDAR\n"),
            httpx.Response(503),
        )
    )
    source = ICSSubscriptionCalendarSource(
        url="https://calendar.example/public.ics",
        label="Public feed",
        cache_ttl_seconds=300,
        stale_if_error_seconds=600,
        clock=lambda: now[0],
        transport=httpx.MockTransport(lambda _request: next(responses)),
    )
    store = AccountStore(
        tmp_path / "health.db",
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    calendar_gateway = GatewayCalendarMCP(
        store,
        static_accounts=(
            StaticICSSubscription(
                subscription_id="public",
                label="Public feed",
                url="https://calendar.example/public.ics",
            ),
        ),
        server_factory=lambda _account: PrivateCalendarMCPServer(calendar_source=source),
    )
    identity = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-a",
        scopes=frozenset({"dav:calendar:read"}),
        token_id="token-a",
    )

    def call(name: str) -> dict[str, Any]:
        response = calendar_gateway.handle(
            identity,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": {}},
            },
        )
        assert response is not None and "error" not in response
        return response["result"]["structuredContent"]

    call("calendars_list")
    assert call("calendar_accounts_list")["accounts"][0]["status"] == "healthy"

    now[0] = 401.0
    call("calendars_list")
    assert call("calendar_accounts_list")["accounts"][0]["status"] == "stale"


def test_gateway_enforces_scopes_authentication_and_url_policy(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway

    unauthenticated = client.get("/v1/accounts")
    assert unauthenticated.status_code == 401, unauthenticated.text
    read_only = _headers(private_pem, scopes="dav:accounts:read")
    assert (
        client.post("/v1/accounts", headers=read_only, json=_account_payload()).status_code == 403
    )
    mcp_denied = client.post(
        "/mcp",
        headers=read_only,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "calendar_accounts_list", "arguments": {}},
        },
    )
    assert mcp_denied.status_code == 403
    assert mcp_denied.json()["error"]["code"] == "permission_denied"

    restricted_url = _account_payload()
    restricted_url["base_url"] = "https://127.0.0.1/dav.php"
    response = client.post(
        "/v1/accounts",
        headers=_headers(private_pem),
        json=restricted_url,
    )
    assert response.status_code == 422
    assert response.json()["error"] == {
        "code": "url_not_allowed",
        "message": "Account URL is not allowed.",
        "fields": {"base_url": "URL is not allowed."},
    }


def test_gateway_settings_load_static_caldav_account_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_JWT_ISSUER", ISSUER)
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_JWT_PUBLIC_KEYS", json.dumps({"key-1": "public"}))
    monkeypatch.setenv(
        "PRIVATE_DAV_GATEWAY_ENCRYPTION_KEYS",
        json.dumps({"1": base64.urlsafe_b64encode(b"k" * 32).decode()}),
    )
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CALDAV_URL", "https://dav.example/calendars/")
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CALDAV_USERNAME", "calendar-user")
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CALDAV_PASSWORD", "environment-secret")
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CALDAV_LABEL", "Personal")
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CALDAV_USER_ID", "user-a")
    monkeypatch.setenv(
        "PRIVATE_DAV_GATEWAY_STATIC_ICS_SUBSCRIPTIONS",
        json.dumps(
            [
                {
                    "id": "public-events",
                    "label": "Public events",
                    "url": "https://calendar.example/public/basic.ics",
                    "user_id": "user-a",
                }
            ]
        ),
    )

    settings = GatewaySettings.from_env()

    assert len(settings.static_accounts) == 2
    account = settings.static_accounts[0]
    assert isinstance(account, StaticCalendarAccount)
    assert account.account_id == "primary"
    assert account.user_id == "user-a"
    assert account.password == "environment-secret"
    assert settings.static_accounts[1].base_url == "https://calendar.example/public/basic.ics"
    assert "environment-secret" not in repr(account)


def test_static_caldav_accounts_are_owner_scoped_without_database_onboarding(
    tmp_path: Path,
) -> None:
    store = AccountStore(
        tmp_path / "static.db",
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    seen_accounts: list[GatewayAccount] = []

    def server_factory(account: GatewayAccount) -> PrivateCalendarMCPServer:
        seen_accounts.append(account)
        return PrivateCalendarMCPServer(
            calendars=[Calendar("Personal", "https://dav.example/personal/")]
        )

    broker = GatewayCalendarMCP(
        store,
        static_accounts=(
            StaticCalendarAccount(
                account_id="primary",
                label="Personal",
                base_url="https://dav.example/calendars/",
                username="calendar-user",
                password="environment-secret",
                user_id="user-a",
            ),
        ),
        server_factory=server_factory,
    )
    owner = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-a",
        token_id="owner-token",
        scopes=frozenset({"dav:calendar:read"}),
    )
    other = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-b",
        token_id="other-token",
        scopes=frozenset({"dav:calendar:read"}),
    )

    broker.check_ready()
    owner_accounts = broker.handle(
        owner,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "calendar_accounts_list", "arguments": {}},
        },
    )
    assert owner_accounts is not None
    account_ref = owner_accounts["result"]["structuredContent"]["accounts"][0]["account_ref"]
    other_accounts = broker.handle(
        other,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "calendar_accounts_list", "arguments": {}},
        },
    )
    assert other_accounts is not None
    assert other_accounts["result"]["structuredContent"]["accounts"] == []

    calendars = broker.handle(
        owner,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "calendars_list", "arguments": {"account_ref": account_ref}},
        },
    )
    assert calendars is not None
    assert len(calendars["result"]["structuredContent"]["calendars"]) == 1
    assert seen_accounts[0].credential.password == "environment-secret"
    assert store.list_accounts("tenant-a", "user-a", limit=100) == []


def test_account_cipher_detects_owner_substitution() -> None:
    cipher = AccountCipher(keyring={1: b"x" * 32}, active_version=1)
    data_key = cipher.new_data_key()
    version, wrapped = cipher.wrap_data_key(data_key, owner_aad=b"tenant-a|user-a|account")

    with pytest.raises(InvalidTag):
        cipher.unwrap_data_key(
            wrapped,
            key_version=version,
            owner_aad=b"tenant-a|user-b|account",
        )
