from __future__ import annotations

import base64
import json
import logging
import sqlite3
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

from private_dav_mcp.caldav import (
    CachedReference,
    Calendar,
    Event,
    PrivateCalendarMCPServer,
    StaticCalendarSource,
)
from private_dav_mcp.carddav import (
    CachedContact,
    Contact,
    ContactResource,
    PrivateContactsMCPServer,
    StaticContactSource,
)
from private_dav_mcp.gateway import (
    AccountConnectionError,
    DAVAccountConnector,
    DAVResource,
    GatewaySettings,
    HealthcheckAccessLogFilter,
    JSONLogFormatter,
    OutboundURLPolicy,
    _uvicorn_log_config,
    create_gateway_app,
)
from private_dav_mcp.gateway_contacts import (
    GatewayContactsMCP,
    StaticContactAccount,
    _decode_contact_reference,
    _encode_contact_reference,
)
from private_dav_mcp.gateway_identity import GatewayIdentity, IdentityError, IdentityVerifier
from private_dav_mcp.gateway_mcp import (
    GatewayCalendarMCP,
    StaticCalendarAccount,
    StaticICSSubscription,
    _decode_calendar_reference,
    _encode_calendar_reference,
)
from private_dav_mcp.gateway_references import DurableReferenceCache
from private_dav_mcp.gateway_store import (
    AccountCipher,
    AccountStore,
    GatewayAccount,
    PasswordCredential,
)
from private_dav_mcp.ics import ICSSubscriptionCalendarSource
from private_dav_mcp.mcp_sdk import SDK_MCP_PROTOCOL_VERSION, MCPToolCallFailure
from private_dav_mcp.protocol import PRIVATE_VALUES_META_KEY

ISSUER = "https://minigent.example"
AUDIENCE = "private-dav"


def test_json_log_formatter_emits_structured_event() -> None:
    formatter = JSONLogFormatter()
    record = logging.makeLogRecord(
        {
            "name": "uvicorn.access",
            "levelno": logging.INFO,
            "levelname": "INFO",
            "msg": "%s - %s",
            "args": ("127.0.0.1", "/mcp"),
            "created": 0,
        }
    )

    assert json.loads(formatter.format(record)) == {
        "timestamp": "1970-01-01T00:00:00.000Z",
        "level": "INFO",
        "logger": "uvicorn.access",
        "message": "127.0.0.1 - /mcp",
    }


def test_healthcheck_access_logs_are_suppressed() -> None:
    access_filter = HealthcheckAccessLogFilter()

    assert not access_filter.filter(
        logging.makeLogRecord({"args": ("127.0.0.1", "GET", "/health/live", "1.1", 200)})
    )
    assert not access_filter.filter(
        logging.makeLogRecord({"args": ("127.0.0.1", "GET", "/health/ready?verbose=1", "1.1", 503)})
    )
    assert access_filter.filter(
        logging.makeLogRecord({"args": ("127.0.0.1", "POST", "/mcp", "1.1", 200)})
    )


def test_uvicorn_log_config_installs_healthcheck_filter() -> None:
    log_config = _uvicorn_log_config()

    assert log_config["filters"]["healthcheck"] == {
        "()": "private_dav_mcp.gateway.HealthcheckAccessLogFilter"
    }
    assert log_config["handlers"]["access"]["filters"] == ["healthcheck"]
    json_log_config = _uvicorn_log_config(json_format=True)
    assert json_log_config["formatters"]["default"] == {
        "()": "private_dav_mcp.gateway.JSONLogFormatter"
    }
    assert json_log_config["formatters"]["access"] == {
        "()": "private_dav_mcp.gateway.JSONLogFormatter"
    }


def test_dav_account_connector_dispatches_carddav_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, str] = {}

    class ReadyCardDAVSource:
        def __init__(
            self,
            *,
            addressbook_url: str,
            username: str,
            password: str,
            auth_mode: str,
        ) -> None:
            observed.update(
                url=addressbook_url,
                username=username,
                password=password,
                mode=auth_mode,
            )

        def check_ready(self) -> None:
            observed["ready"] = "yes"

    monkeypatch.setattr("private_dav_mcp.gateway.CardDAVContactSource", ReadyCardDAVSource)
    account = GatewayAccount(
        account_ref="acct_carddav",
        tenant_id="tenant-a",
        owner_type="user",
        owner_user_id="user-a",
        kind="carddav",
        label="Address book",
        base_url="https://dav.example/addressbooks/personal/",
        credential=PasswordCredential(
            username="contact-user", password="contact-secret", mode="digest"
        ),
        status="ready",
        enabled=True,
        last_checked_at=None,
        last_error=None,
        created_at="2026-08-10T00:00:00Z",
        updated_at="2026-08-10T00:00:00Z",
    )

    assert DAVAccountConnector().test(account) == 1
    assert observed == {
        "url": "https://dav.example/addressbooks/personal/",
        "username": "contact-user",
        "password": "contact-secret",
        "mode": "digest",
        "ready": "yes",
    }


class FakeConnector:
    def __init__(self) -> None:
        self.calls: list[GatewayAccount] = []

    def discover_calendars(self, account: GatewayAccount) -> list[Calendar]:
        self.calls.append(account)
        if account.credential.password == "bad-password":
            raise AccountConnectionError("authentication_failed")
        return [
            Calendar("Personal", "https://dav.example/personal/", "#3366cc"),
            Calendar("Work", "https://dav.example/calendars/work/", None),
        ]

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
    contacts_mcp = GatewayContactsMCP(
        StaticContactAccount(
            account_id="contacts",
            addressbook_url="https://dav.example/addressbooks/",
            username="contacts-user",
            password="contacts-secret",
        ),
        store=store,
        account_server_factory=lambda _account: PrivateContactsMCPServer(
            contacts=[Contact("Managed Person", emails=("managed@example.com",))]
        ),
        server_factory=lambda _account: PrivateContactsMCPServer(
            contacts=[Contact("Private Person", emails=("private@example.com",))]
        ),
    )
    app = create_gateway_app(
        verifier=verifier,
        store=store,
        connector=connector,
        url_policy=policy,
        calendar_mcp=calendar_mcp,
        contacts_mcp=contacts_mcp,
        resource_catalog=(
            DAVResource(
                resource_id="caldav:primary",
                kind="caldav",
                label="Personal calendar",
                allowed_permissions=("read", "read_write"),
            ),
            DAVResource(
                resource_id="carddav:contacts",
                kind="carddav",
                label="Contacts",
                allowed_permissions=("read", "read_write"),
            ),
            DAVResource(
                resource_id="ics:holidays",
                kind="ics",
                label="Holidays",
                allowed_permissions=("read",),
            ),
        ),
    )
    return TestClient(app), private_pem, connector, db_path


def _token(
    private_pem: str,
    *,
    tenant_id: str = "tenant-a",
    user_id: str = "user-a",
    scopes: str = (
        "dav:accounts:read dav:accounts:write dav:calendar:read dav:calendar:write "
        "dav:contacts:read dav:contacts:write dav:grants:read dav:grants:write"
    ),
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
    assert created["owner_type"] == "user"
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


def test_calendar_preferences_are_scoped_encrypted_and_enforced_by_mcp(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, db_path = gateway
    owner = _headers(
        private_pem,
        scopes="dav:accounts:read dav:accounts:write dav:calendar:read dav:calendar:write",
    )
    created = client.post(
        "/v1/accounts",
        headers=owner,
        json=_account_payload(password="calendar-preference-secret"),
    )
    assert created.status_code == 201
    account_ref = created.json()["account_ref"]

    mcp_calendars = _mcp(
        client,
        owner,
        "tools/call",
        {"name": "calendars_list", "arguments": {"account_ref": account_ref}},
    )["result"]
    mcp_calendar_ref = mcp_calendars["structuredContent"]["calendars"][0]["calendar_ref"]

    listed = client.get(f"/v1/accounts/{account_ref}/calendars", headers=owner)
    assert listed.status_code == 200, listed.text
    calendars = listed.json()["calendars"]
    assert [(item["name"], item["enabled"]) for item in calendars] == [
        ("Personal", True),
        ("Work", True),
    ]
    personal = calendars[0]
    repeated = client.get(f"/v1/accounts/{account_ref}/calendars", headers=owner)
    assert repeated.json()["calendars"][0]["calendar_ref"] == personal["calendar_ref"]
    cross_owner = client.get(
        f"/v1/accounts/{account_ref}/calendars",
        headers=_headers(
            private_pem,
            user_id="user-b",
            scopes="dav:accounts:read",
        ),
    )
    assert cross_owner.status_code == 404

    disabled = client.patch(
        f"/v1/accounts/{account_ref}/calendars/{personal['calendar_ref']}",
        headers=owner,
        json={"enabled": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    filtered = _mcp(
        client,
        owner,
        "tools/call",
        {"name": "calendars_list", "arguments": {"account_ref": account_ref}},
    )["result"]
    assert filtered["structuredContent"]["calendars"] == []
    assert filtered["_meta"][PRIVATE_VALUES_META_KEY] == {}
    free_busy = _mcp(
        client,
        owner,
        "tools/call",
        {
            "name": "free_busy",
            "arguments": {
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )["result"]
    assert free_busy["structuredContent"]["queried_calendar_count"] == 0
    assert free_busy["structuredContent"]["busy"] == []
    rejected_reference = _mcp(
        client,
        owner,
        "tools/call",
        {
            "name": "events_list",
            "arguments": {
                "calendar_ref": mcp_calendar_ref,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )
    assert rejected_reference["error"]["code"] == -32001

    enabled = client.patch(
        f"/v1/accounts/{account_ref}/calendars/{personal['calendar_ref']}",
        headers=owner,
        json={"enabled": True},
    )
    assert enabled.status_code == 200
    assert (
        len(
            _mcp(
                client,
                owner,
                "tools/call",
                {"name": "calendars_list", "arguments": {"account_ref": account_ref}},
            )["result"]["structuredContent"]["calendars"]
        )
        == 1
    )

    rotated = client.patch(
        f"/v1/accounts/{account_ref}",
        headers=owner,
        json={
            "auth": {
                "type": "password",
                "username": "rotated-user",
                "password": "rotated-secret",
                "mode": "basic",
            }
        },
    )
    assert rotated.status_code == 200
    rediscovered = client.get(f"/v1/accounts/{account_ref}/calendars", headers=owner)
    assert rediscovered.status_code == 200
    assert rediscovered.json()["calendars"][0]["calendar_ref"] != personal["calendar_ref"]
    assert b"https://dav.example/personal/" not in db_path.read_bytes()

    tenant_admin = _headers(
        private_pem,
        scopes="dav:tenant-accounts:read dav:tenant-accounts:write",
    )
    tenant_payload = _account_payload(password="tenant-calendar-preference")
    tenant_created = client.post("/v1/tenant/accounts", headers=tenant_admin, json=tenant_payload)
    assert tenant_created.status_code == 201
    tenant_ref = tenant_created.json()["account_ref"]
    tenant_calendars = client.get(
        f"/v1/tenant/accounts/{tenant_ref}/calendars", headers=tenant_admin
    )
    assert tenant_calendars.status_code == 200
    tenant_calendar_ref = tenant_calendars.json()["calendars"][0]["calendar_ref"]
    tenant_disabled = client.patch(
        f"/v1/tenant/accounts/{tenant_ref}/calendars/{tenant_calendar_ref}",
        headers=tenant_admin,
        json={"enabled": False},
    )
    assert tenant_disabled.status_code == 200
    assert tenant_disabled.json()["enabled"] is False
    assert (
        client.get(
            f"/v1/tenant/accounts/{tenant_ref}/calendars",
            headers=_headers(
                private_pem,
                tenant_id="tenant-b",
                scopes="dav:tenant-accounts:read",
            ),
        ).status_code
        == 404
    )

    assert client.delete(f"/v1/accounts/{account_ref}", headers=owner).status_code == 204
    assert (
        client.delete(f"/v1/tenant/accounts/{tenant_ref}", headers=tenant_admin).status_code == 204
    )


def test_carddav_personal_and_tenant_account_lifecycle(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, connector, db_path = gateway
    personal_headers = _headers(
        private_pem,
        scopes="dav:accounts:read dav:accounts:write dav:calendar:read",
    )
    payload = _account_payload(password="carddav-personal-secret")
    payload.update(
        {
            "kind": "carddav",
            "label": "Personal address book",
            "base_url": "https://dav.example/addressbooks/personal/",
        }
    )
    created = client.post("/v1/accounts", headers=personal_headers, json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["kind"] == "carddav"
    assert created.json()["addressbook_count"] == 2
    assert "calendar_count" not in created.json()
    personal_ref = created.json()["account_ref"]
    assert (
        client.get(f"/v1/accounts/{personal_ref}/calendars", headers=personal_headers).status_code
        == 404
    )
    assert connector.calls[-1].kind == "carddav"

    tested = client.post(f"/v1/accounts/{personal_ref}/test", headers=personal_headers)
    assert tested.status_code == 200
    assert tested.json()["addressbook_count"] == 2
    calendar_accounts = _mcp(
        client,
        personal_headers,
        "tools/call",
        {"name": "calendar_accounts_list", "arguments": {}},
    )["result"]["structuredContent"]["accounts"]
    assert personal_ref not in {account["account_ref"] for account in calendar_accounts}

    tenant_headers = _headers(
        private_pem,
        scopes="dav:tenant-accounts:read dav:tenant-accounts:write",
    )
    tenant_payload = _account_payload(password="carddav-tenant-secret")
    tenant_payload.update(
        {
            "kind": "carddav",
            "label": "Shared address book",
            "base_url": "https://dav.example/addressbooks/shared/",
            "initial_access": {"user_id": "user-a", "permission": "read_write"},
        }
    )
    tenant_created = client.post("/v1/tenant/accounts", headers=tenant_headers, json=tenant_payload)
    assert tenant_created.status_code == 201, tenant_created.text
    assert tenant_created.json()["kind"] == "carddav"
    assert tenant_created.json()["addressbook_count"] == 2
    tenant_ref = tenant_created.json()["account_ref"]
    assert (
        client.get(
            f"/v1/tenant/accounts/{tenant_ref}/calendars", headers=tenant_headers
        ).status_code
        == 404
    )
    tenant_tested = client.post(f"/v1/tenant/accounts/{tenant_ref}/test", headers=tenant_headers)
    assert tenant_tested.status_code == 200
    assert tenant_tested.json()["addressbook_count"] == 2

    assert b"carddav-personal-secret" not in db_path.read_bytes()
    assert b"carddav-tenant-secret" not in db_path.read_bytes()
    invalid = _account_payload()
    invalid["kind"] = "webdav"
    rejected = client.post("/v1/accounts", headers=personal_headers, json=invalid)
    assert rejected.status_code == 422

    assert (
        client.delete(f"/v1/accounts/{personal_ref}", headers=personal_headers).status_code == 204
    )
    assert (
        client.delete(f"/v1/tenant/accounts/{tenant_ref}", headers=tenant_headers).status_code
        == 204
    )


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


def _contacts_mcp(
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
    response = client.post("/contacts/mcp", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_gateway_mcp_supports_sdk_v2_discovery_and_private_metadata(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    headers = _headers(private_pem)
    metadata = {
        "io.modelcontextprotocol/protocolVersion": SDK_MCP_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "gateway-sdk-test", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }

    for path, expected_name in (
        ("/mcp", "private-dav-gateway"),
        ("/contacts/mcp", "private-dav-gateway-contacts"),
    ):
        discover = client.post(
            path,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "server/discover",
                "params": {"_meta": metadata},
            },
        )
        assert discover.status_code == 200
        assert discover.json()["result"]["supportedVersions"] == [SDK_MCP_PROTOCOL_VERSION]
        assert (
            discover.json()["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"]
            == expected_name
        )

    contacts = client.post(
        "/contacts/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "contacts_list",
                "arguments": {},
                "_meta": metadata,
            },
        },
    ).json()["result"]
    assert contacts["resultType"] == "complete"
    assert contacts["_meta"][PRIVATE_VALUES_META_KEY]
    assert (
        contacts["_meta"]["io.modelcontextprotocol/serverInfo"]["name"]
        == "private-dav-gateway-contacts"
    )


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


def test_gateway_contacts_mcp_requires_identity_scopes_and_protects_values(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    response = client.post(
        "/contacts/mcp",
        headers=_headers(private_pem),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "contacts_list", "arguments": {}},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert "error" not in body
    result = body["result"]
    assert "Private Person" not in json.dumps(result["structuredContent"])
    assert set(result["_meta"]["io.minigent/private-values"].values()) == {"Private Person"}

    denied = client.post(
        "/contacts/mcp",
        headers=_headers(private_pem, scopes="dav:calendar:read"),
        json={
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "contacts_list", "arguments": {}},
        },
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "permission_denied"


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
        response = calendar_gateway.call_tool(identity, name, {})
        assert response is not None and "error" not in response
        return response["structuredContent"]

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


def test_resource_catalog_is_safe_scoped_and_enforces_permissions(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    unauthenticated = client.get("/v1/resources")
    assert unauthenticated.status_code == 401
    denied = client.get(
        "/v1/resources",
        headers=_headers(private_pem, scopes="dav:calendar:read"),
    )
    assert denied.status_code == 403

    response = client.get("/v1/resources", headers=_headers(private_pem))
    assert response.status_code == 200
    assert response.json() == {
        "resources": [
            {
                "resource_id": "caldav:primary",
                "kind": "caldav",
                "label": "Personal calendar",
                "allowed_permissions": ["read", "read_write"],
                "configured": True,
                "enabled": True,
            },
            {
                "resource_id": "carddav:contacts",
                "kind": "carddav",
                "label": "Contacts",
                "allowed_permissions": ["read", "read_write"],
                "configured": True,
                "enabled": True,
            },
            {
                "resource_id": "ics:holidays",
                "kind": "ics",
                "label": "Holidays",
                "allowed_permissions": ["read"],
                "configured": True,
                "enabled": True,
            },
        ]
    }
    encoded = json.dumps(response.json())
    assert "https://" not in encoded
    assert "password" not in encoded
    assert "username" not in encoded

    unsupported = client.put(
        "/v1/resource-grants",
        headers=_headers(private_pem),
        json={
            "resource_id": "ics:holidays",
            "user_id": "user-a",
            "permission": "read_write",
            "enabled": True,
        },
    )
    assert unsupported.status_code == 422
    assert unsupported.json()["error"]["code"] == "unsupported_permission"


def test_resource_grant_api_is_tenant_scoped(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    owner_headers = _headers(private_pem)
    created = client.put(
        "/v1/resource-grants",
        headers=owner_headers,
        json={
            "resource_id": "caldav:primary",
            "user_id": "*",
            "permission": "read_write",
            "enabled": True,
        },
    )
    assert created.status_code == 200
    assert created.json()["tenant_id"] == "tenant-a"
    assert created.json()["updated_by"] == "user-a"

    listed = client.get("/v1/resource-grants", headers=owner_headers)
    assert listed.status_code == 200
    assert [(item["resource_id"], item["user_id"]) for item in listed.json()["grants"]] == [
        ("caldav:primary", "*")
    ]
    other_tenant = client.get(
        "/v1/resource-grants",
        headers=_headers(private_pem, tenant_id="tenant-b"),
    )
    assert other_tenant.status_code == 200
    assert other_tenant.json()["grants"] == []

    deleted = client.delete(
        "/v1/resource-grants/caldav:primary",
        params={"user_id": "*"},
        headers=owner_headers,
    )
    assert deleted.status_code == 204

    audit = client.get("/v1/resource-grant-audit", headers=owner_headers)
    assert audit.status_code == 200
    assert audit.json()["next_cursor"] is None
    assert [entry["operation"] for entry in audit.json()["entries"]] == [
        "resource_grant.delete",
        "resource_grant.create",
    ]
    assert audit.json()["entries"][0] == {
        "audit_id": 2,
        "resource_id": "caldav:primary",
        "tenant_id": "tenant-a",
        "user_id": "*",
        "actor_id": "user-a",
        "operation": "resource_grant.delete",
        "previous": {"permission": "read_write", "enabled": True},
        "resulting": None,
        "created_at": audit.json()["entries"][0]["created_at"],
    }
    other_audit = client.get(
        "/v1/resource-grant-audit",
        headers=_headers(private_pem, tenant_id="tenant-b"),
    )
    assert other_audit.status_code == 200
    assert other_audit.json() == {"entries": [], "next_cursor": None}


def test_tenant_account_grant_api_is_scoped_audited_and_non_sensitive(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    tenant_account = client.post(
        "/v1/tenant/accounts",
        headers=_headers(private_pem, scopes="dav:tenant-accounts:write"),
        json=_account_payload(),
    )
    assert tenant_account.status_code == 201, tenant_account.text
    account_ref = tenant_account.json()["account_ref"]
    read_headers = _headers(private_pem, scopes="dav:account-grants:read")
    write_headers = _headers(private_pem, scopes="dav:account-grants:write")
    admin_headers = _headers(
        private_pem,
        scopes="dav:account-grants:read dav:account-grants:write",
    )
    grant_url = f"/v1/tenant/accounts/{account_ref}/grants"

    assert client.get(grant_url, headers=write_headers).status_code == 403
    assert (
        client.put(
            grant_url,
            headers=read_headers,
            json={"user_id": "user-b", "permission": "read", "enabled": True},
        ).status_code
        == 403
    )

    created = client.put(
        grant_url,
        headers=admin_headers,
        json={"user_id": "user-b", "permission": "read", "enabled": True},
    )
    assert created.status_code == 200, created.text
    assert created.json() == {
        "account_ref": account_ref,
        "tenant_id": "tenant-a",
        "user_id": "user-b",
        "permission": "read",
        "enabled": True,
        "updated_by": "user-a",
        "created_at": created.json()["created_at"],
        "updated_at": created.json()["updated_at"],
    }
    assert "Private calendar canary" not in created.text
    assert "https://" not in created.text
    assert "secret-canary" not in created.text

    rejected_tenant = client.put(
        grant_url,
        headers=admin_headers,
        json={
            "tenant_id": "tenant-b",
            "user_id": "user-b",
            "permission": "read",
            "enabled": True,
        },
    )
    assert rejected_tenant.status_code == 422

    updated = client.put(
        grant_url,
        headers=admin_headers,
        json={"user_id": "user-b", "permission": "read_write", "enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["permission"] == "read_write"
    assert updated.json()["enabled"] is False
    touched = client.put(
        grant_url,
        headers=admin_headers,
        json={"user_id": "user-b", "permission": "read_write", "enabled": False},
    )
    assert touched.status_code == 200
    wildcard = client.put(
        grant_url,
        headers=admin_headers,
        json={"user_id": "*", "permission": "read", "enabled": True},
    )
    assert wildcard.status_code == 200

    listed = client.get(grant_url, headers=read_headers)
    assert listed.status_code == 200
    assert [grant["user_id"] for grant in listed.json()["grants"]] == ["*", "user-b"]
    assert "Private calendar canary" not in listed.text

    other_tenant = client.get(
        grant_url,
        headers=_headers(
            private_pem,
            tenant_id="tenant-b",
            scopes="dav:account-grants:read",
        ),
    )
    assert other_tenant.status_code == 404

    personal = client.post(
        "/v1/accounts",
        headers=_headers(private_pem, scopes="dav:accounts:write"),
        json=_account_payload(),
    )
    assert personal.status_code == 201
    personal_grant = client.put(
        f"/v1/tenant/accounts/{personal.json()['account_ref']}/grants",
        headers=write_headers,
        json={"user_id": "user-b", "permission": "read", "enabled": True},
    )
    assert personal_grant.status_code == 404

    deleted = client.delete(
        f"{grant_url}/user-b",
        headers=write_headers,
    )
    assert deleted.status_code == 204
    assert client.delete(f"{grant_url}/user-b", headers=write_headers).status_code == 404

    first_audit_page = client.get(
        "/v1/tenant/account-grant-audit",
        headers=read_headers,
        params={"limit": 2},
    )
    assert first_audit_page.status_code == 200
    assert first_audit_page.json()["next_cursor"] is not None
    assert [entry["operation"] for entry in first_audit_page.json()["entries"]] == [
        "account_grant.delete",
        "account_grant.create",
    ]
    second_audit_page = client.get(
        "/v1/tenant/account-grant-audit",
        headers=read_headers,
        params={"limit": 10, "before_id": first_audit_page.json()["next_cursor"]},
    )
    assert second_audit_page.status_code == 200
    assert [entry["operation"] for entry in second_audit_page.json()["entries"]] == [
        "account_grant.touch",
        "account_grant.update",
        "account_grant.create",
    ]
    assert all(entry["tenant_id"] == "tenant-a" for entry in second_audit_page.json()["entries"])
    assert "Private calendar canary" not in second_audit_page.text
    assert client.get(
        "/v1/tenant/account-grant-audit",
        headers=_headers(
            private_pem,
            tenant_id="tenant-b",
            scopes="dav:account-grants:read",
        ),
    ).json() == {"entries": [], "next_cursor": None}


def test_tenant_account_lifecycle_is_scoped_idempotent_and_atomic(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, connector, db_path = gateway
    read_headers = _headers(private_pem, scopes="dav:tenant-accounts:read")
    write_headers = _headers(private_pem, scopes="dav:tenant-accounts:write")
    admin_b_headers = _headers(
        private_pem,
        user_id="admin-b",
        scopes="dav:tenant-accounts:read dav:tenant-accounts:write",
    )
    payload = _account_payload(password="tenant-lifecycle-secret")
    payload["label"] = "Tenant lifecycle canary"
    payload["initial_access"] = {"user_id": "user-b", "permission": "read_write"}

    assert client.get("/v1/tenant/accounts", headers=write_headers).status_code == 403
    assert client.post("/v1/tenant/accounts", headers=read_headers, json=payload).status_code == 403
    rejected_owner = client.post(
        "/v1/tenant/accounts",
        headers=write_headers,
        json={**payload, "tenant_id": "tenant-b"},
    )
    assert rejected_owner.status_code == 422

    created = client.post(
        "/v1/tenant/accounts",
        headers={**write_headers, "Idempotency-Key": "create-tenant-lifecycle"},
        json=payload,
    )
    assert created.status_code == 201, created.text
    account_ref = created.json()["account_ref"]
    assert created.json()["owner_type"] == "tenant"
    assert created.json()["calendar_count"] == 2
    assert "tenant-lifecycle-secret" not in created.text

    retried = client.post(
        "/v1/tenant/accounts",
        headers={**admin_b_headers, "Idempotency-Key": "create-tenant-lifecycle"},
        json=payload,
    )
    assert retried.status_code == 201
    assert retried.json()["account_ref"] == account_ref
    conflict_payload = dict(payload)
    conflict_payload["label"] = "Different tenant label"
    conflict = client.post(
        "/v1/tenant/accounts",
        headers={**write_headers, "Idempotency-Key": "create-tenant-lifecycle"},
        json=conflict_payload,
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "conflict"

    listed = client.get("/v1/tenant/accounts", headers=read_headers)
    assert listed.status_code == 200
    assert account_ref in {account["account_ref"] for account in listed.json()["accounts"]}
    assert all(account["owner_type"] == "tenant" for account in listed.json()["accounts"])
    assert client.get(
        "/v1/tenant/accounts",
        headers=_headers(
            private_pem,
            tenant_id="tenant-b",
            scopes="dav:tenant-accounts:read",
        ),
    ).json() == {"accounts": [], "next_cursor": None}

    selected = client.get(f"/v1/tenant/accounts/{account_ref}", headers=read_headers)
    assert selected.status_code == 200
    assert selected.json()["label"] == "Tenant lifecycle canary"
    assert (
        client.get(
            f"/v1/tenant/accounts/{account_ref}",
            headers=_headers(
                private_pem,
                tenant_id="tenant-b",
                scopes="dav:tenant-accounts:read",
            ),
        ).status_code
        == 404
    )

    initial_grants = client.get(
        f"/v1/tenant/accounts/{account_ref}/grants",
        headers=_headers(private_pem, scopes="dav:account-grants:read"),
    )
    assert initial_grants.status_code == 200
    assert [
        (grant["user_id"], grant["permission"], grant["updated_by"])
        for grant in initial_grants.json()["grants"]
    ] == [("user-b", "read_write", "user-a")]

    renamed = client.patch(
        f"/v1/tenant/accounts/{account_ref}",
        headers=admin_b_headers,
        json={"label": "Renamed tenant calendar"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["label"] == "Renamed tenant calendar"

    failed_rotation = client.patch(
        f"/v1/tenant/accounts/{account_ref}",
        headers=admin_b_headers,
        json={
            "auth": {
                "type": "password",
                "username": "tenant-user",
                "password": "bad-password",
                "mode": "basic",
            }
        },
    )
    assert failed_rotation.status_code == 422
    assert failed_rotation.json()["error"]["code"] == "authentication_failed"
    tested = client.post(f"/v1/tenant/accounts/{account_ref}/test", headers=admin_b_headers)
    assert tested.status_code == 200
    assert connector.calls[-1].credential.password == "tenant-lifecycle-secret"

    deleted = client.delete(f"/v1/tenant/accounts/{account_ref}", headers=write_headers)
    assert deleted.status_code == 204
    assert client.get(f"/v1/tenant/accounts/{account_ref}", headers=read_headers).status_code == 404
    assert (
        client.get(
            f"/v1/tenant/accounts/{account_ref}/grants",
            headers=_headers(private_pem, scopes="dav:account-grants:read"),
        ).status_code
        == 404
    )

    store = AccountStore(
        db_path,
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    lifecycle_audit = [
        entry
        for entry in store.list_tenant_account_audit("tenant-a", limit=100)
        if entry.account_ref == account_ref
    ]
    assert [entry.operation for entry in lifecycle_audit] == [
        "tenant_account.delete",
        "tenant_account.test",
        "tenant_account.update",
        "tenant_account.create",
    ]
    assert [entry.actor_user_id for entry in lifecycle_audit] == [
        "user-a",
        "admin-b",
        "admin-b",
        "user-a",
    ]
    for database_file in db_path.parent.glob("gateway.db*"):
        content = database_file.read_bytes()
        assert b"tenant-lifecycle-secret" not in content
        assert b"Tenant lifecycle canary" not in content
        assert b"Renamed tenant calendar" not in content


def test_shared_tenant_account_mcp_is_grant_aware_and_caller_bound(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    tenant_admin = _headers(
        private_pem,
        scopes="dav:tenant-accounts:write dav:account-grants:write",
    )
    payload = _account_payload(password="shared-mcp-secret")
    payload["label"] = "Shared MCP calendar"
    payload["initial_access"] = {"user_id": "user-a", "permission": "read_write"}
    created = client.post("/v1/tenant/accounts", headers=tenant_admin, json=payload)
    assert created.status_code == 201, created.text
    account_ref = created.json()["account_ref"]
    grant_url = f"/v1/tenant/accounts/{account_ref}/grants"
    for user_id, permission in (("user-b", "read_write"), ("user-c", "read")):
        response = client.put(
            grant_url,
            headers=tenant_admin,
            json={"user_id": user_id, "permission": permission, "enabled": True},
        )
        assert response.status_code == 200, response.text

    user_a = _headers(
        private_pem,
        user_id="user-a",
        scopes="dav:calendar:read dav:calendar:write",
    )
    user_b = _headers(
        private_pem,
        user_id="user-b",
        scopes="dav:calendar:read dav:calendar:write",
    )
    user_c = _headers(
        private_pem,
        user_id="user-c",
        scopes="dav:calendar:read dav:calendar:write",
    )
    ungranted_admin = _headers(
        private_pem,
        user_id="admin-no-access",
        scopes="dav:calendar:read dav:tenant-accounts:read dav:tenant-accounts:write",
    )

    for headers in (user_a, user_b, user_c):
        accounts = _mcp(
            client,
            headers,
            "tools/call",
            {"name": "calendar_accounts_list", "arguments": {}},
        )["result"]
        assert account_ref in {
            account["account_ref"] for account in accounts["structuredContent"]["accounts"]
        }
        assert "Shared MCP calendar" not in str(accounts["structuredContent"])

    denied_admin = _mcp(
        client,
        ungranted_admin,
        "tools/call",
        {"name": "calendars_list", "arguments": {"account_ref": account_ref}},
    )
    assert denied_admin["error"]["code"] == -32001

    def calendar_ref(headers: dict[str, str]) -> str:
        result = _mcp(
            client,
            headers,
            "tools/call",
            {"name": "calendars_list", "arguments": {"account_ref": account_ref}},
        )["result"]
        calendars = result["structuredContent"]["calendars"]
        assert len(calendars) == 1
        return calendars[0]["calendar_ref"]

    calendar_a = calendar_ref(user_a)
    calendar_b = calendar_ref(user_b)
    calendar_c = calendar_ref(user_c)
    assert len({calendar_a, calendar_b, calendar_c}) == 3

    cross_caller = _mcp(
        client,
        user_b,
        "tools/call",
        {
            "name": "events_list",
            "arguments": {
                "calendar_ref": calendar_a,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )
    assert cross_caller["error"]["code"] == -32001

    read_only_write = _mcp(
        client,
        user_c,
        "tools/call",
        {
            "name": "events_create",
            "arguments": {
                "calendar_ref": calendar_c,
                "summary": "Denied shared mutation",
                "start": "2026-08-01T10:00:00Z",
                "end": "2026-08-01T11:00:00Z",
            },
        },
    )
    assert read_only_write["error"]["code"] == -32001

    allowed_write = _mcp(
        client,
        user_b,
        "tools/call",
        {
            "name": "events_create",
            "arguments": {
                "calendar_ref": calendar_b,
                "summary": "Allowed shared mutation",
                "start": "2026-08-01T10:00:00Z",
                "end": "2026-08-01T11:00:00Z",
            },
        },
    )
    assert allowed_write["result"]["structuredContent"]["status"] == "created"

    revoked = client.delete(f"{grant_url}/user-b", headers=tenant_admin)
    assert revoked.status_code == 204
    revoked_reference = _mcp(
        client,
        user_b,
        "tools/call",
        {
            "name": "events_list",
            "arguments": {
                "calendar_ref": calendar_b,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )
    assert revoked_reference["error"]["code"] == -32001

    renamed = client.patch(
        f"/v1/tenant/accounts/{account_ref}",
        headers=tenant_admin,
        json={"label": "Updated shared calendar"},
    )
    assert renamed.status_code == 200
    stale_reference = _mcp(
        client,
        user_a,
        "tools/call",
        {
            "name": "events_list",
            "arguments": {
                "calendar_ref": calendar_a,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )
    assert stale_reference["error"]["code"] == -32001
    current_calendar_a = calendar_ref(user_a)

    disabled = client.patch(
        f"/v1/tenant/accounts/{account_ref}",
        headers=tenant_admin,
        json={"enabled": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "disabled"
    disabled_accounts = _mcp(
        client,
        user_a,
        "tools/call",
        {"name": "calendar_accounts_list", "arguments": {}},
    )["result"]
    assert account_ref not in {
        account["account_ref"] for account in disabled_accounts["structuredContent"]["accounts"]
    }
    disabled_reference = _mcp(
        client,
        user_a,
        "tools/call",
        {
            "name": "events_list",
            "arguments": {
                "calendar_ref": current_calendar_a,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        },
    )
    assert disabled_reference["error"]["code"] == -32001

    assert (
        client.delete(f"/v1/tenant/accounts/{account_ref}", headers=tenant_admin).status_code == 204
    )


def test_shared_tenant_carddav_mcp_is_grant_aware_and_caller_bound(
    gateway: tuple[TestClient, str, FakeConnector, Path],
) -> None:
    client, private_pem, _connector, _db_path = gateway
    tenant_admin = _headers(
        private_pem,
        scopes="dav:tenant-accounts:write dav:account-grants:write",
    )
    payload = _account_payload(password="shared-carddav-secret")
    payload.update(
        {
            "kind": "carddav",
            "label": "Shared tenant contacts",
            "base_url": "https://dav.example/addressbooks/shared/",
            "initial_access": {"user_id": "user-a", "permission": "read_write"},
        }
    )
    created = client.post("/v1/tenant/accounts", headers=tenant_admin, json=payload)
    assert created.status_code == 201, created.text
    account_ref = created.json()["account_ref"]
    grant_url = f"/v1/tenant/accounts/{account_ref}/grants"
    for user_id, permission in (("user-b", "read_write"), ("user-c", "read")):
        response = client.put(
            grant_url,
            headers=tenant_admin,
            json={"user_id": user_id, "permission": permission, "enabled": True},
        )
        assert response.status_code == 200

    def user_headers(user_id: str) -> dict[str, str]:
        return _headers(
            private_pem,
            user_id=user_id,
            scopes="dav:contacts:read dav:contacts:write",
        )

    user_a = user_headers("user-a")
    user_b = user_headers("user-b")
    user_c = user_headers("user-c")
    for headers in (user_a, user_b, user_c):
        accounts = _contacts_mcp(
            client,
            headers,
            "tools/call",
            {"name": "contact_accounts_list", "arguments": {}},
        )["result"]
        assert account_ref in {
            account["account_ref"] for account in accounts["structuredContent"]["accounts"]
        }
        assert "Shared tenant contacts" not in str(accounts["structuredContent"])

    def contact_ref(headers: dict[str, str]) -> str:
        result = _contacts_mcp(
            client,
            headers,
            "tools/call",
            {
                "name": "contacts_list",
                "arguments": {"account_ref": account_ref},
            },
        )["result"]
        contacts = result["structuredContent"]["contacts"]
        assert len(contacts) == 1
        return contacts[0]["contact_ref"]

    contact_a = contact_ref(user_a)
    contact_b = contact_ref(user_b)
    contact_c = contact_ref(user_c)
    assert len({contact_a, contact_b, contact_c}) == 3

    cross_caller = _contacts_mcp(
        client,
        user_b,
        "tools/call",
        {
            "name": "contacts_get",
            "arguments": {"contact_ref": contact_a, "fields": ["emails"]},
        },
    )
    assert cross_caller["error"]["code"] == -32001

    read_only_write = _contacts_mcp(
        client,
        user_c,
        "tools/call",
        {
            "name": "contacts_create",
            "arguments": {"account_ref": account_ref, "name": "Denied contact"},
        },
    )
    assert read_only_write["error"]["code"] == -32001
    allowed_write = _contacts_mcp(
        client,
        user_b,
        "tools/call",
        {
            "name": "contacts_create",
            "arguments": {"account_ref": account_ref, "name": "Allowed contact"},
        },
    )
    assert allowed_write["result"]["structuredContent"]["status"] == "created"

    ungranted_admin = user_headers("admin-no-contact-access")
    denied_admin = _contacts_mcp(
        client,
        ungranted_admin,
        "tools/call",
        {
            "name": "contacts_list",
            "arguments": {"account_ref": account_ref},
        },
    )
    assert denied_admin["error"]["code"] == -32001

    assert client.delete(f"{grant_url}/user-b", headers=tenant_admin).status_code == 204
    revoked = _contacts_mcp(
        client,
        user_b,
        "tools/call",
        {
            "name": "contacts_get",
            "arguments": {"contact_ref": contact_b, "fields": ["emails"]},
        },
    )
    assert revoked["error"]["code"] == -32001

    renamed = client.patch(
        f"/v1/tenant/accounts/{account_ref}",
        headers=tenant_admin,
        json={"label": "Updated tenant contacts"},
    )
    assert renamed.status_code == 200
    stale = _contacts_mcp(
        client,
        user_a,
        "tools/call",
        {
            "name": "contacts_get",
            "arguments": {"contact_ref": contact_a, "fields": ["emails"]},
        },
    )
    assert stale["error"]["code"] == -32001
    current_contact = contact_ref(user_a)

    disabled = client.patch(
        f"/v1/tenant/accounts/{account_ref}",
        headers=tenant_admin,
        json={"enabled": False},
    )
    assert disabled.status_code == 200
    disabled_accounts = _contacts_mcp(
        client,
        user_a,
        "tools/call",
        {"name": "contact_accounts_list", "arguments": {}},
    )["result"]
    assert account_ref not in {
        account["account_ref"] for account in disabled_accounts["structuredContent"]["accounts"]
    }
    disabled_ref = _contacts_mcp(
        client,
        user_a,
        "tools/call",
        {
            "name": "contacts_get",
            "arguments": {"contact_ref": current_contact, "fields": ["emails"]},
        },
    )
    assert disabled_ref["error"]["code"] == -32001
    assert (
        client.delete(f"/v1/tenant/accounts/{account_ref}", headers=tenant_admin).status_code == 204
    )


def test_resource_grants_support_tenant_and_user_permissions(tmp_path: Path) -> None:
    store = AccountStore(
        tmp_path / "grants.db",
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    assert store.resource_access("caldav:primary", "tenant-a", "user-a", permission="read") is None

    store.upsert_resource_grant(
        resource_id="caldav:primary",
        tenant_id="tenant-a",
        user_id="*",
        permission="read",
        enabled=True,
        updated_by="admin-a",
    )
    assert store.resource_access("caldav:primary", "tenant-a", "user-a", permission="read") is True
    assert (
        store.resource_access("caldav:primary", "tenant-a", "user-a", permission="write") is False
    )
    assert store.resource_access("caldav:primary", "tenant-b", "user-a", permission="read") is False

    store.upsert_resource_grant(
        resource_id="caldav:primary",
        tenant_id="tenant-a",
        user_id="user-a",
        permission="read_write",
        enabled=True,
        updated_by="admin-a",
    )
    assert store.resource_access("caldav:primary", "tenant-a", "user-a", permission="write") is True
    assert [
        (grant.user_id, grant.permission) for grant in store.list_resource_grants("tenant-a")
    ] == [
        ("*", "read"),
        ("user-a", "read_write"),
    ]


def test_resource_grant_audit_is_transactional_and_append_only(tmp_path: Path) -> None:
    db_path = tmp_path / "grant-audit.db"
    store = AccountStore(
        db_path,
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    values = {
        "resource_id": "carddav:contacts",
        "tenant_id": "tenant-a",
        "user_id": "user-a",
        "updated_by": "admin-a",
    }
    store.upsert_resource_grant(permission="read", enabled=True, **values)
    store.upsert_resource_grant(permission="read_write", enabled=True, **values)
    store.upsert_resource_grant(permission="read_write", enabled=False, **values)
    store.upsert_resource_grant(permission="read_write", enabled=True, **values)
    assert store.delete_resource_grant(
        "carddav:contacts", "tenant-a", "user-a", deleted_by="admin-b"
    )

    entries = list(reversed(store.list_resource_grant_audit("tenant-a", limit=10)))
    assert [entry.operation for entry in entries] == [
        "resource_grant.create",
        "resource_grant.permission_change",
        "resource_grant.disable",
        "resource_grant.enable",
        "resource_grant.delete",
    ]
    assert entries[0].previous_permission is None
    assert entries[0].resulting_permission == "read"
    assert entries[-1].actor_id == "admin-b"
    assert entries[-1].previous_enabled is True
    assert entries[-1].resulting_permission is None

    with sqlite3.connect(db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM dav_resource_grant_audit")
    assert len(store.list_resource_grant_audit("tenant-a", limit=10)) == 5


def test_static_caldav_resource_grant_overrides_legacy_owner(tmp_path: Path) -> None:
    store = AccountStore(
        tmp_path / "calendar-grants.db",
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    template = StaticCalendarAccount(
        account_id="primary",
        label="Personal",
        base_url="https://dav.example/calendars/",
        username="calendar-user",
        password="environment-secret",
        tenant_id="legacy-tenant",
        user_id="legacy-user",
    )
    broker = GatewayCalendarMCP(
        store,
        static_accounts=(template,),
        require_resource_grants=True,
        server_factory=lambda _account: PrivateCalendarMCPServer(
            calendars=[Calendar("Personal", "https://dav.example/personal/")]
        ),
    )
    identity = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-b",
        token_id="granted-token",
        scopes=frozenset({"dav:calendar:read"}),
    )
    assert (
        broker.call_tool(identity, "calendar_accounts_list", {})["structuredContent"]["accounts"]
        == []
    )

    store.upsert_resource_grant(
        resource_id=template.resource_id,
        tenant_id="tenant-a",
        user_id="*",
        permission="read",
        enabled=True,
        updated_by="admin-a",
    )
    accounts = broker.call_tool(identity, "calendar_accounts_list", {})["structuredContent"][
        "accounts"
    ]
    assert len(accounts) == 1


def test_static_carddav_resource_grants_enforce_read_write(tmp_path: Path) -> None:
    store = AccountStore(
        tmp_path / "contact-grants.db",
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    account = StaticContactAccount(
        account_id="contacts",
        addressbook_url="https://dav.example/addressbooks/",
        username="contacts-user",
        password="contacts-secret",
        tenant_id="legacy-tenant",
        user_id="legacy-user",
    )
    broker = GatewayContactsMCP(
        account,
        store=store,
        require_resource_grants=True,
        server_factory=lambda _account: PrivateContactsMCPServer(
            contacts=[Contact("Private Person")]
        ),
    )
    identity = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-b",
        token_id="granted-token",
        scopes=frozenset({"dav:contacts:read", "dav:contacts:write"}),
    )
    store.upsert_resource_grant(
        resource_id=account.resource_id,
        tenant_id="tenant-a",
        user_id="*",
        permission="read",
        enabled=True,
        updated_by="admin-a",
    )
    assert broker.call_tool(identity, "contacts_list", {})["structuredContent"]["contacts"]
    with pytest.raises(MCPToolCallFailure) as exc_info:
        broker.call_tool(identity, "contacts_create", {"name": "New Person"})
    assert exc_info.value.code == -32001

    store.upsert_resource_grant(
        resource_id=account.resource_id,
        tenant_id="tenant-a",
        user_id="*",
        permission="read_write",
        enabled=True,
        updated_by="admin-a",
    )
    created = broker.call_tool(identity, "contacts_create", {"name": "New Person"})
    assert created["structuredContent"]["status"] == "created"


@pytest.mark.parametrize("required", ["true", "1", "yes"])
def test_gateway_settings_parse_required_resource_grants(
    monkeypatch: pytest.MonkeyPatch, required: str
) -> None:
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_JWT_ISSUER", ISSUER)
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_JWT_PUBLIC_KEYS", json.dumps({"key-1": "public"}))
    monkeypatch.setenv(
        "PRIVATE_DAV_GATEWAY_ENCRYPTION_KEYS",
        json.dumps({"1": base64.urlsafe_b64encode(b"k" * 32).decode()}),
    )
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_REQUIRE_RESOURCE_GRANTS", required)
    assert GatewaySettings.from_env().require_resource_grants is True


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
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CARDDAV_URL", "https://dav.example/addressbooks/")
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CARDDAV_USERNAME", "contacts-user")
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CARDDAV_PASSWORD", "contacts-secret")
    monkeypatch.setenv("PRIVATE_DAV_GATEWAY_CARDDAV_USER_ID", "user-a")
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
    assert settings.static_contact_account is not None
    assert settings.static_contact_account.addressbook_url == "https://dav.example/addressbooks/"
    assert settings.static_contact_account.user_id == "user-a"
    assert settings.static_contact_account.password == "contacts-secret"
    assert "contacts-secret" not in repr(settings.static_contact_account)
    assert "environment-secret" not in repr(account)


def test_static_caldav_resource_migration_is_scoped_atomic_and_idempotent(
    tmp_path: Path, signing_keys: tuple[str, str]
) -> None:
    private_pem, public_pem = signing_keys
    db_path = tmp_path / "static-migration.db"
    store = AccountStore(
        db_path,
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    verifier = IdentityVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        public_keys={"test-key": public_pem},
        leeway_seconds=0,
    )
    connector = FakeConnector()
    policy = OutboundURLPolicy(resolver=lambda _host: ["93.184.216.34"])

    def client_for(password: str) -> TestClient:
        static_account = StaticCalendarAccount(
            account_id="primary",
            label="Static shared calendar",
            base_url="https://dav.example/calendars/",
            username="static-user",
            password=password,
            tenant_id="tenant-a",
            user_id="legacy-user",
        )
        settings = GatewaySettings(
            db_path=str(db_path),
            jwt_issuer=ISSUER,
            jwt_audience=AUDIENCE,
            jwt_public_keys={"test-key": public_pem},
            encryption_keyring={1: b"k" * 32},
            active_encryption_key_version=1,
            allowed_networks=(),
            allowed_host_suffixes=(),
            static_accounts=(static_account,),
            static_contact_account=None,
            require_resource_grants=True,
        )
        return TestClient(
            create_gateway_app(
                verifier=verifier,
                store=store,
                connector=connector,
                url_policy=policy,
                settings=settings,
                calendar_mcp=GatewayCalendarMCP(
                    store,
                    static_accounts=(static_account,),
                    server_factory=lambda _account: PrivateCalendarMCPServer(
                        calendars=[Calendar("Shared", "https://dav.example/calendars/shared/")]
                    ),
                    require_resource_grants=True,
                ),
            )
        )

    client = client_for("static-secret")
    resource_admin = _headers(private_pem, scopes="dav:grants:write")
    for user_id, permission in (("user-a", "read"), ("user-b", "read_write")):
        response = client.put(
            "/v1/resource-grants",
            headers=resource_admin,
            json={
                "resource_id": "caldav:primary",
                "user_id": user_id,
                "permission": permission,
                "enabled": True,
            },
        )
        assert response.status_code == 200

    migration_path = "/v1/tenant/static-resources/caldav:primary/migrate"
    assert (
        client.post(
            migration_path,
            headers=_headers(private_pem, scopes="dav:tenant-accounts:write"),
        ).status_code
        == 403
    )
    migration_headers = _headers(
        private_pem,
        scopes=("dav:tenant-accounts:write dav:account-grants:write dav:grants:read"),
    )
    migrated = client.post(migration_path, headers=migration_headers)
    assert migrated.status_code == 201, migrated.text
    body = migrated.json()
    assert body["created"] is True
    assert body["source_resource_id"] == "caldav:primary"
    assert body["grant_count"] == 2
    assert body["calendar_count"] == 2
    account_ref = body["account"]["account_ref"]
    assert body["account"]["owner_type"] == "tenant"
    assert "static-secret" not in migrated.text

    account = store.get_account_for_tenant("tenant-a", account_ref)
    assert account is not None
    assert account.credential.password == "static-secret"
    grants = store.list_account_grants(account_ref, "tenant-a")
    assert {(grant.user_id, grant.permission) for grant in grants} == {
        ("user-a", "read"),
        ("user-b", "read_write"),
    }
    assert b"static-secret" not in db_path.read_bytes()

    retried = client.post(migration_path, headers=migration_headers)
    assert retried.status_code == 200
    assert retried.json()["created"] is False
    assert retried.json()["account"]["account_ref"] == account_ref
    assert len(store.list_tenant_accounts("tenant-a", limit=100)) == 1
    migration_audit = store.list_tenant_account_audit("tenant-a", limit=100)
    assert len(migration_audit) == 1
    assert migration_audit[0].operation == "tenant_account.migrate"
    assert len(store.list_account_grant_audit("tenant-a", limit=100)) == 2

    cross_tenant = client.post(
        migration_path,
        headers=_headers(
            private_pem,
            tenant_id="tenant-b",
            scopes=("dav:tenant-accounts:write dav:account-grants:write dav:grants:read"),
        ),
    )
    assert cross_tenant.status_code == 404

    changed_configuration = client_for("rotated-static-secret")
    conflict = changed_configuration.post(migration_path, headers=migration_headers)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "migration_conflict"
    assert b"rotated-static-secret" not in db_path.read_bytes()


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
    owner_accounts = broker.call_tool(owner, "calendar_accounts_list", {})
    assert owner_accounts is not None
    account_ref = owner_accounts["structuredContent"]["accounts"][0]["account_ref"]
    other_accounts = broker.call_tool(other, "calendar_accounts_list", {})
    assert other_accounts is not None
    assert other_accounts["structuredContent"]["accounts"] == []

    calendars = broker.call_tool(owner, "calendars_list", {"account_ref": account_ref})
    assert calendars is not None
    assert len(calendars["structuredContent"]["calendars"]) == 1
    assert seen_accounts[0].credential.password == "environment-secret"
    assert store.list_accounts("tenant-a", "user-a", limit=100) == []


def test_static_carddav_account_is_authenticated_and_owner_scoped() -> None:
    broker = GatewayContactsMCP(
        StaticContactAccount(
            account_id="contacts",
            addressbook_url="https://dav.example/addressbooks/",
            username="contacts-user",
            password="contacts-secret",
            tenant_id="tenant-a",
            user_id="user-a",
        ),
        server_factory=lambda _account: PrivateContactsMCPServer(
            contacts=[Contact("Private Person", emails=("private@example.com",))]
        ),
    )
    owner = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-a",
        token_id="owner-token",
        scopes=frozenset({"dav:contacts:read"}),
    )
    other = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-b",
        token_id="other-token",
        scopes=frozenset({"dav:contacts:read"}),
    )

    listed = broker.call_tool(owner, "contacts_list", {})
    assert listed is not None and "error" not in listed
    contact_ref = listed["structuredContent"]["contacts"][0]["contact_ref"]
    assert "Private Person" not in json.dumps(listed["structuredContent"])

    with pytest.raises(MCPToolCallFailure) as exc_info:
        broker.call_tool(other, "contacts_get", {"contact_ref": contact_ref, "fields": ["emails"]})
    assert exc_info.value.code == -32001

    with pytest.raises(MCPToolCallFailure) as exc_info:
        broker.call_tool(owner, "contacts_create", {"name": "New Person"})
    assert exc_info.value.code == -32001


def test_contact_protection_treats_names_across_accounts_as_one_namespace(
    tmp_path: Path,
) -> None:
    store = AccountStore(
        tmp_path / "contact-protection.db",
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    store.create_account(
        tenant_id="tenant-a",
        user_id="user-a",
        kind="carddav",
        label="Managed contacts",
        base_url="https://dav.example/addressbooks/managed/",
        credential=PasswordCredential(username="managed", password="secret", mode="basic"),
        enabled=True,
        status="ready",
        last_error=None,
        idempotency_key=None,
        request_hash=None,
    )
    static_template = StaticContactAccount(
        account_id="static-contacts",
        addressbook_url="https://dav.example/addressbooks/static/",
        username="static",
        password="secret",
        tenant_id="tenant-a",
        user_id="user-a",
    )
    broker = GatewayContactsMCP(
        static_template,
        store=store,
        server_factory=lambda _account: PrivateContactsMCPServer(contacts=[Contact("SameEntry")]),
        account_server_factory=lambda _account: PrivateContactsMCPServer(
            contacts=[Contact("SameEntry")]
        ),
    )
    identity = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-a",
        scopes=frozenset({"dav:contacts:read"}),
        token_id="token-a",
    )

    result = broker.call_tool(identity, "contacts_protect_text", {"text": "Email Alex Smith today"})
    assert result["structuredContent"] == {
        "text": "Email Alex Smith today",
        "protected_contact_count": 0,
    }
    assert result["_meta"][PRIVATE_VALUES_META_KEY] == {}

    class FailingContactSource(StaticContactSource):
        def list_contact_resources(self, *, limit: int) -> tuple[list[ContactResource], bool]:
            raise RuntimeError("provider unavailable")

    fail_closed = GatewayContactsMCP(
        static_template,
        store=store,
        server_factory=lambda _account: PrivateContactsMCPServer(contacts=[Contact("UniqueEntry")]),
        account_server_factory=lambda _account: PrivateContactsMCPServer(
            contact_source=FailingContactSource()
        ),
    )
    with pytest.raises(MCPToolCallFailure) as exc_info:
        fail_closed.call_tool(
            identity, "contacts_protect_text", {"text": "Email UniqueEntry today"}
        )
    assert exc_info.value.code == -32002


def test_managed_carddav_references_are_caller_bound_across_instances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = AccountStore(
        tmp_path / "managed-carddav.db",
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    account, _created = store.create_tenant_account(
        tenant_id="tenant-a",
        actor_user_id="admin-a",
        kind="carddav",
        label="Shared durable contacts",
        base_url="https://dav.example/addressbooks/shared/",
        credential=PasswordCredential(username="shared", password="secret", mode="basic"),
        enabled=True,
        status="ready",
        last_error=None,
        idempotency_key=None,
        request_hash=None,
        initial_access=("user-a", "read_write"),
    )
    store.upsert_account_grant(
        account_ref=account.account_ref,
        tenant_id="tenant-a",
        user_id="user-b",
        permission="read_write",
        enabled=True,
        updated_by="admin-a",
    )
    monkeypatch.setattr(
        "private_dav_mcp.gateway_contacts.CardDAVContactSource",
        lambda **_kwargs: StaticContactSource(
            contacts=[Contact("Shared Person", emails=("contact-value",))]
        ),
    )
    user_a = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-a",
        scopes=frozenset({"dav:contacts:read", "dav:contacts:write"}),
        token_id="token-a",
    )
    user_b = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-b",
        scopes=frozenset({"dav:contacts:read", "dav:contacts:write"}),
        token_id="token-b",
    )
    gateway_a = GatewayContactsMCP(None, store=store)
    gateway_b = GatewayContactsMCP(None, store=store)

    listed = gateway_a.call_tool(user_a, "contacts_list", {"account_ref": account.account_ref})
    contact_ref = listed["structuredContent"]["contacts"][0]["contact_ref"]
    selected = gateway_b.call_tool(
        user_a, "contacts_get", {"contact_ref": contact_ref, "fields": ["emails"]}
    )
    assert len(selected["structuredContent"]["emails"]) == 1

    with pytest.raises(MCPToolCallFailure) as exc_info:
        gateway_b.call_tool(
            user_b,
            "contacts_get",
            {"contact_ref": contact_ref, "fields": ["emails"]},
        )
    assert exc_info.value.code == -32001
    assert store.list_references("tenant-a", "user-a", account.account_ref)
    assert store.list_references("tenant-a", "user-b", account.account_ref) == []


def test_shared_account_durable_references_are_caller_bound_across_instances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "shared-account.db"
    store = AccountStore(
        database,
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    account, _created = store.create_tenant_account(
        tenant_id="tenant-a",
        actor_user_id="admin-a",
        kind="caldav",
        label="Shared durable calendar",
        base_url="https://dav.example/shared/",
        credential=PasswordCredential(username="shared", password="secret", mode="basic"),
        enabled=True,
        status="ready",
        last_error=None,
        idempotency_key=None,
        request_hash=None,
        initial_access=("user-a", "read_write"),
    )
    store.upsert_account_grant(
        account_ref=account.account_ref,
        tenant_id="tenant-a",
        user_id="user-b",
        permission="read_write",
        enabled=True,
        updated_by="admin-a",
    )
    monkeypatch.setattr(
        "private_dav_mcp.gateway_mcp.CalDAVCalendarSource",
        lambda **_kwargs: StaticCalendarSource(
            calendars=[Calendar("Shared", "https://dav.example/shared/calendar/")],
            events=[
                Event(
                    "Shared event",
                    "2026-08-01T14:00:00Z",
                    "2026-08-01T15:00:00Z",
                )
            ],
        ),
    )
    user_a = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-a",
        scopes=frozenset({"dav:calendar:read", "dav:calendar:write"}),
        token_id="token-a",
    )
    user_b = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-b",
        scopes=frozenset({"dav:calendar:read", "dav:calendar:write"}),
        token_id="token-b",
    )
    gateway_a = GatewayCalendarMCP(store)
    gateway_b = GatewayCalendarMCP(store)

    listed = gateway_a.call_tool(user_a, "calendars_list", {})
    calendar_ref = listed["structuredContent"]["calendars"][0]["calendar_ref"]
    selected = gateway_b.call_tool(
        user_a,
        "events_list",
        {
            "calendar_ref": calendar_ref,
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-02T00:00:00Z",
        },
    )
    assert len(selected["structuredContent"]["events"]) == 1

    with pytest.raises(MCPToolCallFailure) as exc_info:
        gateway_b.call_tool(
            user_b,
            "events_list",
            {
                "calendar_ref": calendar_ref,
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        )
    assert exc_info.value.code == -32001
    assert store.list_references("tenant-a", "user-a", account.account_ref)
    assert store.list_references("tenant-a", "user-b", account.account_ref) == []


def test_durable_references_resolve_across_gateway_instances(tmp_path: Path) -> None:
    database = tmp_path / "shared-gateway.db"

    def new_store() -> AccountStore:
        return AccountStore(
            database,
            cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
        )

    identity = GatewayIdentity(
        tenant_id="tenant-a",
        user_id="user-a",
        token_id="owner-token",
        scopes=frozenset({"dav:calendar:read", "dav:calendar:write", "dav:contacts:read"}),
    )
    contact_account = StaticContactAccount(
        account_id="contacts",
        addressbook_url="https://dav.example/addressbooks/",
        username="contact-user",
        password="contact-password",
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
    )

    def contact_factory(_account: StaticContactAccount) -> PrivateContactsMCPServer:
        cache = DurableReferenceCache[CachedContact](
            new_store(),
            tenant_id=identity.tenant_id,
            user_id=identity.user_id,
            account_ref=contact_account.account_id,
            account_updated_at=contact_account.revision,
            encode=_encode_contact_reference,
            decode=_decode_contact_reference,
            reference_types=frozenset({"contact"}),
        )
        return PrivateContactsMCPServer(
            contacts=[Contact("Durable Person", emails=("durable@example.test",))],
            clock=time.time,
            contact_references=cache,
        )

    contacts_a = GatewayContactsMCP(
        contact_account,
        store=new_store(),
        server_factory=contact_factory,
    )
    contacts_b = GatewayContactsMCP(
        contact_account,
        store=new_store(),
        server_factory=contact_factory,
    )
    listed_contacts = contacts_a.call_tool(identity, "contacts_list", {})
    assert listed_contacts is not None and "error" not in listed_contacts
    contact_ref = listed_contacts["structuredContent"]["contacts"][0]["contact_ref"]
    selected_contact = contacts_b.call_tool(
        identity, "contacts_get", {"contact_ref": contact_ref, "fields": ["emails"]}
    )
    assert selected_contact is not None and "error" not in selected_contact

    calendar_template = StaticCalendarAccount(
        account_id="primary",
        label="Durable calendar",
        base_url="https://dav.example/calendars/",
        username="calendar-user",
        password="calendar-password",
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
    )

    def calendar_factory(account: GatewayAccount) -> PrivateCalendarMCPServer:
        cache = DurableReferenceCache[CachedReference](
            new_store(),
            tenant_id=account.tenant_id,
            user_id=account.user_id,
            account_ref=account.account_ref,
            account_updated_at=account.updated_at,
            encode=_encode_calendar_reference,
            decode=_decode_calendar_reference,
            reference_types=frozenset({"calendar", "event"}),
        )
        return PrivateCalendarMCPServer(
            calendars=[Calendar("Durable", "https://dav.example/calendars/durable/")],
            events=[
                Event(
                    "Durable event",
                    "2026-08-01T14:00:00Z",
                    "2026-08-01T15:00:00Z",
                    description="Cross-instance details",
                )
            ],
            clock=time.time,
            references=cache,
        )

    calendars_a = GatewayCalendarMCP(
        new_store(), static_accounts=(calendar_template,), server_factory=calendar_factory
    )
    calendars_b = GatewayCalendarMCP(
        new_store(), static_accounts=(calendar_template,), server_factory=calendar_factory
    )
    listed_calendars = calendars_a.call_tool(identity, "calendars_list", {})
    assert listed_calendars is not None and "error" not in listed_calendars
    calendar_ref = listed_calendars["structuredContent"]["calendars"][0]["calendar_ref"]
    listed_events = calendars_b.call_tool(
        identity,
        "events_list",
        {
            "calendar_ref": calendar_ref,
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-02T00:00:00Z",
        },
    )
    assert listed_events is not None and "error" not in listed_events
    event_ref = listed_events["structuredContent"]["events"][0]["event_ref"]
    selected_event = calendars_a.call_tool(
        identity, "events_get", {"event_ref": event_ref, "fields": ["description"]}
    )
    assert selected_event is not None and "error" not in selected_event

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dav_references").fetchone()[0] == 3
    for database_file in database.parent.glob("shared-gateway.db*"):
        content = database_file.read_bytes()
        assert b"Durable Person" not in content
        assert b"durable@example.test" not in content
        assert b"Durable event" not in content
        assert b"Cross-instance details" not in content

    rotating_store = AccountStore(
        database,
        cipher=AccountCipher(keyring={1: b"k" * 32, 2: b"n" * 32}, active_version=2),
    )
    assert rotating_store.rotate_references_to_active_key() == 3
    with sqlite3.connect(database) as connection:
        assert {
            row[0] for row in connection.execute("SELECT DISTINCT key_version FROM dav_references")
        } == {2}
    new_only_store = AccountStore(
        database,
        cipher=AccountCipher(keyring={2: b"n" * 32}, active_version=2),
    )
    assert new_only_store.list_references(identity.tenant_id, identity.user_id, "contacts")
    old_only_store = AccountStore(
        database,
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
    with pytest.raises(RuntimeError, match="key version is unavailable"):
        old_only_store.list_references(identity.tenant_id, identity.user_id, "contacts")


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
