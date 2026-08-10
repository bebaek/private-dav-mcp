from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import logging
import os
import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Annotated, Any, Protocol
from urllib.parse import urlsplit

import uvicorn
from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.concurrency import run_in_threadpool
from uvicorn.config import LOGGING_CONFIG

from private_dav_mcp.caldav import CalDAVCalendarSource, Calendar
from private_dav_mcp.carddav import CardDAVContactSource
from private_dav_mcp.gateway_access import AccountAccessPolicy
from private_dav_mcp.gateway_contacts import GatewayContactsMCP, StaticContactAccount
from private_dav_mcp.gateway_identity import GatewayIdentity, IdentityError, IdentityVerifier
from private_dav_mcp.gateway_mcp import (
    GatewayCalendarMCP,
    StaticCalendarAccount,
    StaticGatewayAccount,
    StaticICSSubscription,
)
from private_dav_mcp.gateway_store import (
    AccountCipher,
    AccountStore,
    CalendarPreference,
    GatewayAccount,
    PasswordCredential,
)
from private_dav_mcp.mcp_sdk import run_mcp_sdk_request

ACCOUNTS_READ_SCOPE = "dav:accounts:read"
ACCOUNTS_WRITE_SCOPE = "dav:accounts:write"
ACCOUNT_GRANTS_READ_SCOPE = "dav:account-grants:read"
ACCOUNT_GRANTS_WRITE_SCOPE = "dav:account-grants:write"
TENANT_ACCOUNTS_READ_SCOPE = "dav:tenant-accounts:read"
TENANT_ACCOUNTS_WRITE_SCOPE = "dav:tenant-accounts:write"
GRANTS_READ_SCOPE = "dav:grants:read"
GRANTS_WRITE_SCOPE = "dav:grants:write"


class JSONLogFormatter(logging.Formatter):
    """Render gateway logs as one JSON object per line for production collectors."""

    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            event["exception"] = self.formatException(record.exc_info)
        return json.dumps(event, ensure_ascii=False)


class HealthcheckAccessLogFilter(logging.Filter):
    """Keep routine liveness and readiness probes out of the access log."""

    _HEALTHCHECK_PATHS = frozenset({"/health/live", "/health/ready"})

    def filter(self, record: logging.LogRecord) -> bool:
        arguments = record.args
        if isinstance(arguments, tuple) and len(arguments) >= 3:
            path = arguments[2]
            if isinstance(path, str) and path.split("?", 1)[0] in self._HEALTHCHECK_PATHS:
                return False
        return True


def _uvicorn_log_config(*, json_format: bool = False) -> dict[str, Any]:
    log_config = copy.deepcopy(LOGGING_CONFIG)
    if json_format:
        log_config["formatters"]["default"] = {"()": "private_dav_mcp.gateway.JSONLogFormatter"}
        log_config["formatters"]["access"] = {"()": "private_dav_mcp.gateway.JSONLogFormatter"}
    log_config.setdefault("filters", {})["healthcheck"] = {
        "()": "private_dav_mcp.gateway.HealthcheckAccessLogFilter"
    }
    log_config["handlers"]["access"]["filters"] = ["healthcheck"]
    return log_config


class GatewayAPIError(RuntimeError):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        fields: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.fields = fields


class URLPolicyError(ValueError):
    pass


class AccountConnectionError(RuntimeError):
    def __init__(self, code: str = "connection_failed") -> None:
        super().__init__(code)
        self.code = code


class AccountConnector(Protocol):
    def test(self, account: GatewayAccount) -> int: ...

    def discover_calendars(self, account: GatewayAccount) -> list[Calendar]: ...


class CalDAVAccountConnector:
    @staticmethod
    def _source(account: GatewayAccount) -> CalDAVCalendarSource:
        return CalDAVCalendarSource(
            calendar_url=account.base_url,
            username=account.credential.username,
            password=account.credential.password,
            auth_mode=account.credential.mode,
        )

    def discover_calendars(self, account: GatewayAccount) -> list[Calendar]:
        try:
            return self._source(account).list_calendars()
        except RuntimeError as exc:
            message = str(exc).lower()
            code = (
                "authentication_failed"
                if "401" in message or "authentication" in message
                else "dav_discovery_failed"
            )
            raise AccountConnectionError(code) from exc

    def test(self, account: GatewayAccount) -> int:
        return len(self.discover_calendars(account))


class DAVAccountConnector:
    def discover_calendars(self, account: GatewayAccount) -> list[Calendar]:
        if account.kind != "caldav":
            raise AccountConnectionError("unsupported_account_kind")
        return CalDAVAccountConnector().discover_calendars(account)

    def test(self, account: GatewayAccount) -> int:
        if account.kind == "caldav":
            return CalDAVAccountConnector().test(account)
        if account.kind == "carddav":
            try:
                source = CardDAVContactSource(
                    addressbook_url=account.base_url,
                    username=account.credential.username,
                    password=account.credential.password,
                    auth_mode=account.credential.mode,
                )
                source.check_ready()
                return 1
            except RuntimeError as exc:
                message = str(exc).lower()
                code = (
                    "authentication_failed"
                    if "401" in message or "authentication" in message
                    else "dav_discovery_failed"
                )
                raise AccountConnectionError(code) from exc
        raise AccountConnectionError("unsupported_account_kind")


class OutboundURLPolicy:
    def __init__(
        self,
        *,
        allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (),
        allowed_host_suffixes: tuple[str, ...] = (),
        resolver: Callable[[str], list[str]] | None = None,
    ) -> None:
        self._allowed_networks = allowed_networks
        self._allowed_host_suffixes = tuple(
            value.lower().lstrip(".") for value in allowed_host_suffixes
        )
        self._resolver = resolver or _resolve_host

    def validate(self, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise URLPolicyError("URL must use HTTPS and include a host")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise URLPolicyError("URL must not include credentials or a fragment")
        host = parsed.hostname.lower().rstrip(".")
        if self._allowed_host_suffixes and not any(
            host == suffix or host.endswith(f".{suffix}") for suffix in self._allowed_host_suffixes
        ):
            raise URLPolicyError("URL host is not allowed")
        try:
            addresses = [str(ipaddress.ip_address(host))]
        except ValueError:
            try:
                addresses = self._resolver(host)
            except OSError as exc:
                raise URLPolicyError("URL host could not be resolved") from exc
        if not addresses:
            raise URLPolicyError("URL host could not be resolved")
        for address_value in addresses:
            address = ipaddress.ip_address(address_value)
            explicitly_allowed = any(address in network for network in self._allowed_networks)
            if not address.is_global and not explicitly_allowed:
                raise URLPolicyError("URL resolves to a restricted network")
        return value


class PasswordAuthInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(pattern="^password$")
    username: str = Field(min_length=1, max_length=320)
    password: SecretStr = Field(min_length=1, max_length=4096)
    mode: str = Field(pattern="^(auto|basic|digest)$")


class AccountGrantPutInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=200)
    permission: str = Field(pattern="^(read|read_write)$")
    enabled: bool = True


class ResourceGrantPutInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_id: str = Field(min_length=1, max_length=200, pattern=r"^[a-z0-9][a-z0-9:._-]+$")
    user_id: str = Field(min_length=1, max_length=200)
    permission: str = Field(pattern="^(read|read_write)$")
    enabled: bool = True


class AccountCreateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(pattern="^(caldav|carddav)$")
    label: str = Field(min_length=1, max_length=100)
    base_url: str = Field(min_length=1, max_length=2048)
    auth: PasswordAuthInput
    enabled: bool = True


class InitialAccountAccessInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=200)
    permission: str = Field(pattern="^(read|read_write)$")


class TenantAccountCreateInput(AccountCreateInput):
    initial_access: InitialAccountAccessInput | None = None


class CalendarPreferencePatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


class AccountPatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, min_length=1, max_length=100)
    base_url: str | None = Field(default=None, min_length=1, max_length=2048)
    auth: PasswordAuthInput | None = None
    enabled: bool | None = None


def _static_accounts_from_env(env: Mapping[str, str]) -> tuple[StaticCalendarAccount, ...]:
    raw = env.get("PRIVATE_DAV_GATEWAY_STATIC_CALDAV_ACCOUNTS", "").strip()
    legacy_url = env.get("PRIVATE_DAV_GATEWAY_CALDAV_URL", "").strip()
    if raw and legacy_url:
        raise RuntimeError(
            "Configure static CalDAV accounts with JSON or legacy variables, not both"
        )
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Static CalDAV accounts setting must be valid JSON") from exc
        if not isinstance(parsed, list) or len(parsed) > 20:
            raise RuntimeError(
                "Static CalDAV accounts setting must be an array of at most 20 items"
            )
        entries = parsed
    elif legacy_url:
        entries = [
            {
                "id": env.get("PRIVATE_DAV_GATEWAY_CALDAV_ACCOUNT_ID", "primary"),
                "label": env.get("PRIVATE_DAV_GATEWAY_CALDAV_LABEL", "Personal calendar"),
                "base_url": legacy_url,
                "username": env.get("PRIVATE_DAV_GATEWAY_CALDAV_USERNAME", ""),
                "password": env.get("PRIVATE_DAV_GATEWAY_CALDAV_PASSWORD", ""),
                "auth_mode": env.get("PRIVATE_DAV_GATEWAY_CALDAV_AUTH_MODE", "basic"),
                "tenant_id": env.get("PRIVATE_DAV_GATEWAY_CALDAV_TENANT_ID", "*"),
                "user_id": env.get("PRIVATE_DAV_GATEWAY_CALDAV_USER_ID", "*"),
            }
        ]
    else:
        return ()

    accounts: list[StaticCalendarAccount] = []
    identities: set[tuple[str, str, str]] = set()
    required = ("id", "label", "base_url", "username", "password")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise RuntimeError(f"Static CalDAV account {index} must be an object")
        if any(not isinstance(entry.get(key), str) or not entry[key] for key in required):
            raise RuntimeError(f"Static CalDAV account {index} is missing a required string field")
        auth_mode = entry.get("auth_mode", "basic")
        tenant_id = entry.get("tenant_id", "*")
        user_id = entry.get("user_id", "*")
        if auth_mode not in {"auto", "basic", "digest"}:
            raise RuntimeError(f"Static CalDAV account {index} has an invalid auth_mode")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise RuntimeError(f"Static CalDAV account {index} has an invalid tenant_id")
        if not isinstance(user_id, str) or not user_id:
            raise RuntimeError(f"Static CalDAV account {index} has an invalid user_id")
        identity = (tenant_id, user_id, entry["id"])
        if identity in identities:
            raise RuntimeError(f"Static CalDAV account {index} has a duplicate owner and id")
        identities.add(identity)
        accounts.append(
            StaticCalendarAccount(
                account_id=entry["id"],
                label=entry["label"],
                base_url=entry["base_url"],
                username=entry["username"],
                password=entry["password"],
                auth_mode=auth_mode,
                tenant_id=tenant_id,
                user_id=user_id,
            )
        )
    return tuple(accounts)


def _static_ics_subscriptions_from_env(
    env: Mapping[str, str],
) -> tuple[StaticICSSubscription, ...]:
    raw = env.get("PRIVATE_DAV_GATEWAY_STATIC_ICS_SUBSCRIPTIONS", "").strip()
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Static ICS subscriptions setting must be valid JSON") from exc
    if not isinstance(parsed, list) or len(parsed) > 50:
        raise RuntimeError("Static ICS subscriptions setting must be an array of at most 50 items")
    subscriptions: list[StaticICSSubscription] = []
    identities: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            raise RuntimeError(f"Static ICS subscription {index} must be an object")
        if any(
            not isinstance(entry.get(key), str) or not entry[key] for key in ("id", "label", "url")
        ):
            raise RuntimeError(
                f"Static ICS subscription {index} is missing a required string field"
            )
        tenant_id = entry.get("tenant_id", "*")
        user_id = entry.get("user_id", "*")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise RuntimeError(f"Static ICS subscription {index} has an invalid tenant_id")
        if not isinstance(user_id, str) or not user_id:
            raise RuntimeError(f"Static ICS subscription {index} has an invalid user_id")
        identity = (tenant_id, user_id, entry["id"])
        if identity in identities:
            raise RuntimeError(f"Static ICS subscription {index} has a duplicate owner and id")
        identities.add(identity)
        subscriptions.append(
            StaticICSSubscription(
                subscription_id=entry["id"],
                label=entry["label"],
                url=entry["url"],
                tenant_id=tenant_id,
                user_id=user_id,
            )
        )
    return tuple(subscriptions)


def _static_contact_account_from_env(env: Mapping[str, str]) -> StaticContactAccount | None:
    addressbook_url = env.get("PRIVATE_DAV_GATEWAY_CARDDAV_URL", "").strip()
    if not addressbook_url:
        return None
    username = env.get("PRIVATE_DAV_GATEWAY_CARDDAV_USERNAME", "")
    password = env.get("PRIVATE_DAV_GATEWAY_CARDDAV_PASSWORD", "")
    auth_mode = env.get("PRIVATE_DAV_GATEWAY_CARDDAV_AUTH_MODE", "auto")
    tenant_id = env.get("PRIVATE_DAV_GATEWAY_CARDDAV_TENANT_ID", "*")
    user_id = env.get("PRIVATE_DAV_GATEWAY_CARDDAV_USER_ID", "*")
    if not username or not password:
        raise RuntimeError("Static CardDAV account requires username and password")
    if auth_mode not in {"auto", "basic", "digest"}:
        raise RuntimeError("Static CardDAV account has an invalid auth mode")
    if not tenant_id or not user_id:
        raise RuntimeError("Static CardDAV account has an invalid owner")
    return StaticContactAccount(
        account_id=env.get("PRIVATE_DAV_GATEWAY_CARDDAV_ACCOUNT_ID", "contacts"),
        addressbook_url=addressbook_url,
        username=username,
        password=password,
        auth_mode=auth_mode,
        tenant_id=tenant_id,
        user_id=user_id,
    )


@dataclass(frozen=True)
class DAVResource:
    resource_id: str
    kind: str
    label: str
    allowed_permissions: tuple[str, ...]
    configured: bool = True
    enabled: bool = True


@dataclass(frozen=True)
class GatewaySettings:
    db_path: str
    jwt_issuer: str
    jwt_audience: str
    jwt_public_keys: dict[str, str]
    encryption_keyring: dict[int, bytes]
    active_encryption_key_version: int
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_host_suffixes: tuple[str, ...]
    static_accounts: tuple[StaticGatewayAccount, ...]
    static_contact_account: StaticContactAccount | None
    require_resource_grants: bool

    @classmethod
    def from_env(cls) -> GatewaySettings:
        jwt_keys_raw = os.environ.get("PRIVATE_DAV_GATEWAY_JWT_PUBLIC_KEYS", "")
        keyring_raw = os.environ.get("PRIVATE_DAV_GATEWAY_ENCRYPTION_KEYS", "")
        if not jwt_keys_raw or not keyring_raw:
            raise RuntimeError("Gateway JWT and encryption keyrings are required")
        jwt_keys = json.loads(jwt_keys_raw)
        encoded_keyring = json.loads(keyring_raw)
        if not isinstance(jwt_keys, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in jwt_keys.items()
        ):
            raise RuntimeError("Gateway JWT public keyring is invalid")
        if not isinstance(encoded_keyring, dict):
            raise RuntimeError("Gateway encryption keyring is invalid")
        allowed_networks = tuple(
            ipaddress.ip_network(value.strip())
            for value in os.environ.get("PRIVATE_DAV_GATEWAY_ALLOWED_NETWORKS", "").split(",")
            if value.strip()
        )
        suffixes = tuple(
            value.strip()
            for value in os.environ.get("PRIVATE_DAV_GATEWAY_ALLOWED_HOST_SUFFIXES", "").split(",")
            if value.strip()
        )
        return cls(
            db_path=os.environ.get("PRIVATE_DAV_GATEWAY_DB_PATH", "/data/private-dav-gateway.db"),
            jwt_issuer=os.environ["PRIVATE_DAV_GATEWAY_JWT_ISSUER"],
            jwt_audience=os.environ.get("PRIVATE_DAV_GATEWAY_JWT_AUDIENCE", "private-dav"),
            jwt_public_keys=jwt_keys,
            encryption_keyring=AccountCipher.decode_keyring(encoded_keyring),
            active_encryption_key_version=int(
                os.environ.get("PRIVATE_DAV_GATEWAY_ACTIVE_ENCRYPTION_KEY_VERSION", "1")
            ),
            allowed_networks=allowed_networks,
            allowed_host_suffixes=suffixes,
            static_accounts=(
                *_static_accounts_from_env(os.environ),
                *_static_ics_subscriptions_from_env(os.environ),
            ),
            static_contact_account=_static_contact_account_from_env(os.environ),
            require_resource_grants=_bool_env(
                os.environ, "PRIVATE_DAV_GATEWAY_REQUIRE_RESOURCE_GRANTS", False
            ),
        )


def create_gateway_app(
    *,
    verifier: IdentityVerifier | None = None,
    store: AccountStore | None = None,
    connector: AccountConnector | None = None,
    url_policy: OutboundURLPolicy | None = None,
    calendar_mcp: GatewayCalendarMCP | None = None,
    contacts_mcp: GatewayContactsMCP | None = None,
    settings: GatewaySettings | None = None,
    resource_catalog: tuple[DAVResource, ...] | None = None,
    account_access_policy: AccountAccessPolicy | None = None,
) -> FastAPI:
    if verifier is None or store is None:
        settings = settings or GatewaySettings.from_env()
        verifier = verifier or IdentityVerifier(
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            public_keys=settings.jwt_public_keys,
        )
        store = store or AccountStore(
            settings.db_path,
            cipher=AccountCipher(
                keyring=settings.encryption_keyring,
                active_version=settings.active_encryption_key_version,
            ),
        )
        url_policy = url_policy or OutboundURLPolicy(
            allowed_networks=settings.allowed_networks,
            allowed_host_suffixes=settings.allowed_host_suffixes,
        )
    connector = connector or DAVAccountConnector()
    url_policy = url_policy or OutboundURLPolicy()
    account_access_policy = account_access_policy or AccountAccessPolicy(store)
    static_accounts = settings.static_accounts if settings is not None else ()
    static_contact_account = settings.static_contact_account if settings is not None else None
    require_resource_grants = settings.require_resource_grants if settings is not None else False
    if resource_catalog is None:
        resource_catalog = _configured_resource_catalog(static_accounts, static_contact_account)
    resource_by_id = {resource.resource_id: resource for resource in resource_catalog}
    static_caldav_by_resource = {
        account.resource_id: account
        for account in static_accounts
        if isinstance(account, StaticCalendarAccount)
    }
    configured_resource_ids = (
        set(resource_by_id) if settings is not None or resource_catalog else None
    )
    for static_account in static_accounts:
        url_policy.validate(static_account.base_url)
    if static_contact_account is not None:
        url_policy.validate(static_contact_account.addressbook_url)
    calendar_mcp = calendar_mcp or GatewayCalendarMCP(
        store,
        static_accounts=static_accounts,
        require_resource_grants=require_resource_grants,
        access_policy=account_access_policy,
    )
    contacts_mcp = contacts_mcp or GatewayContactsMCP(
        static_contact_account,
        store=store,
        require_resource_grants=require_resource_grants,
    )
    app = FastAPI(title="Private DAV Gateway", version="1")

    @app.exception_handler(GatewayAPIError)
    async def handle_gateway_error(_request: Request, exc: GatewayAPIError) -> JSONResponse:
        error: dict[str, Any] = {"code": exc.code, "message": exc.message}
        if exc.fields:
            error["fields"] = exc.fields
        return JSONResponse(status_code=exc.status_code, content={"error": error})

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        fields: dict[str, str] = {}
        for error in exc.errors():
            location = [str(value) for value in error.get("loc", ()) if value != "body"]
            if location:
                fields[".".join(location)] = "Invalid value."
        gateway_error = GatewayAPIError(
            422, "invalid_request", "Request validation failed.", fields=fields or None
        )
        return await handle_gateway_error(_request, gateway_error)

    async def authenticate(
        authorization: str | None = Header(default=None),
    ) -> GatewayIdentity:
        if not authorization or not authorization.startswith("Bearer "):
            raise GatewayAPIError(401, "authentication_required", "Authentication is required.")
        try:
            return verifier.verify(authorization.removeprefix("Bearer ").strip())
        except IdentityError as exc:
            raise GatewayAPIError(
                401, "authentication_required", "Authentication is required."
            ) from exc

    def require_scope(identity: GatewayIdentity, scope: str) -> None:
        try:
            identity.require(scope)
        except PermissionError as exc:
            raise GatewayAPIError(403, "permission_denied", "Permission is denied.") from exc

    @app.get("/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    async def health_ready() -> JSONResponse:
        try:
            await run_in_threadpool(store.check_ready)
            await run_in_threadpool(calendar_mcp.check_ready)
            await run_in_threadpool(contacts_mcp.check_ready)
        except Exception:
            return JSONResponse(status_code=503, content={"status": "not_ready"})
        return JSONResponse(status_code=200, content={"status": "ready"})

    @app.post("/mcp")
    async def mcp_endpoint(
        request: Request,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        try:
            payload = await request.json()
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Invalid JSON"},
                },
            )
        if not isinstance(payload, dict):
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Request must be an object"},
                },
            )
        if payload.get("method") == "tools/call":
            params = payload.get("params")
            tool_name = params.get("name") if isinstance(params, dict) else None
            if isinstance(tool_name, str):
                required_scope = (
                    "dav:calendar:write"
                    if tool_name in {"events_create", "events_update", "events_delete"}
                    else "dav:calendar:read"
                )
                require_scope(identity, required_scope)
        result = await run_mcp_sdk_request(calendar_mcp.build_sdk_server(identity), payload)
        if result is None:
            return Response(status_code=202)
        return JSONResponse(status_code=200, content=result)

    @app.post("/contacts/mcp")
    async def contacts_mcp_endpoint(
        request: Request,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        try:
            payload = await request.json()
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Invalid JSON"},
                },
            )
        if not isinstance(payload, dict):
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Request must be an object"},
                },
            )
        if payload.get("method") == "tools/call":
            params = payload.get("params")
            tool_name = params.get("name") if isinstance(params, dict) else None
            if isinstance(tool_name, str):
                required_scope = (
                    "dav:contacts:write"
                    if tool_name in {"contacts_create", "contacts_update", "contacts_delete"}
                    else "dav:contacts:read"
                )
                require_scope(identity, required_scope)
        result = await run_mcp_sdk_request(contacts_mcp.build_sdk_server(identity), payload)
        if result is None:
            return Response(status_code=202)
        return JSONResponse(status_code=200, content=result)

    @app.get("/v1/resources")
    async def list_resources(
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, GRANTS_READ_SCOPE)
        return {
            "resources": [_resource_response(resource) for resource in resource_catalog],
        }

    @app.get("/v1/resource-grants")
    async def list_resource_grants(
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, GRANTS_READ_SCOPE)
        grants = await run_in_threadpool(store.list_resource_grants, identity.tenant_id)
        return {"grants": [_resource_grant_response(grant) for grant in grants]}

    @app.get("/v1/resource-grant-audit")
    async def list_resource_grant_audit(
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
        limit: int = 100,
        before_id: int | None = None,
    ) -> dict[str, Any]:
        require_scope(identity, GRANTS_READ_SCOPE)
        if limit < 1 or limit > 500:
            raise GatewayAPIError(422, "invalid_request", "Limit must be between 1 and 500.")
        if before_id is not None and before_id < 1:
            raise GatewayAPIError(422, "invalid_request", "Audit cursor must be positive.")
        entries = await run_in_threadpool(
            store.list_resource_grant_audit,
            identity.tenant_id,
            limit=limit + 1,
            before_id=before_id,
        )
        has_more = len(entries) > limit
        entries = entries[:limit]
        return {
            "entries": [_resource_grant_audit_response(entry) for entry in entries],
            "next_cursor": entries[-1].audit_id if has_more else None,
        }

    @app.put("/v1/resource-grants")
    async def put_resource_grant(
        payload: ResourceGrantPutInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, GRANTS_WRITE_SCOPE)
        if (
            configured_resource_ids is not None
            and payload.resource_id not in configured_resource_ids
        ):
            raise GatewayAPIError(404, "not_found", "DAV resource was not found.")
        configured_resource = resource_by_id.get(payload.resource_id)
        if (
            configured_resource is not None
            and payload.permission not in configured_resource.allowed_permissions
        ):
            raise GatewayAPIError(
                422,
                "unsupported_permission",
                "Permission is not supported by this DAV resource.",
                fields={"permission": "Permission is not supported by this resource."},
            )
        grant = await run_in_threadpool(
            store.upsert_resource_grant,
            resource_id=payload.resource_id,
            tenant_id=identity.tenant_id,
            user_id=payload.user_id,
            permission=payload.permission,
            enabled=payload.enabled,
            updated_by=identity.user_id,
        )
        return _resource_grant_response(grant)

    @app.delete("/v1/resource-grants/{resource_id}", status_code=204)
    async def delete_resource_grant(
        resource_id: str,
        user_id: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        require_scope(identity, GRANTS_WRITE_SCOPE)
        deleted = await run_in_threadpool(
            store.delete_resource_grant,
            resource_id,
            identity.tenant_id,
            user_id,
            deleted_by=identity.user_id,
        )
        if not deleted:
            raise GatewayAPIError(404, "not_found", "Resource grant was not found.")
        return Response(status_code=204)

    @app.post("/v1/tenant/static-resources/{resource_id}/migrate")
    async def migrate_static_caldav_resource(
        resource_id: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        require_scope(identity, TENANT_ACCOUNTS_WRITE_SCOPE)
        require_scope(identity, ACCOUNT_GRANTS_WRITE_SCOPE)
        require_scope(identity, GRANTS_READ_SCOPE)
        static_account = static_caldav_by_resource.get(resource_id)
        if static_account is None or static_account.tenant_id not in {
            "*",
            identity.tenant_id,
        }:
            raise GatewayAPIError(404, "not_found", "Static CalDAV resource was not found.")
        base_url = await _validate_url(url_policy, static_account.base_url)
        credential = PasswordCredential(
            username=static_account.username,
            password=static_account.password,
            mode=static_account.auth_mode,
        )
        candidate = _candidate_tenant_account(
            identity.tenant_id,
            "caldav",
            static_account.label,
            base_url,
            credential,
            True,
        )
        calendar_count = await _test_account(connector, candidate)
        resource_grants = await run_in_threadpool(store.list_resource_grants, identity.tenant_id)
        access_entries = tuple(
            sorted(
                (
                    (grant.user_id, grant.permission)
                    for grant in resource_grants
                    if grant.resource_id == resource_id and grant.enabled
                ),
                key=lambda entry: entry[0],
            )
        )
        if len(access_entries) > 500:
            raise GatewayAPIError(
                409,
                "account_grant_limit_reached",
                "Tenant account grant limit was reached.",
            )
        if not access_entries and not require_resource_grants:
            access_entries = ((static_account.user_id, "read_write"),)
        migration_payload = {
            "resource_id": resource_id,
            "label": static_account.label,
            "base_url": base_url,
            "username": static_account.username,
            "password": static_account.password,
            "auth_mode": static_account.auth_mode,
            "access": access_entries,
        }
        migration_key = (
            "static-caldav:"
            + hashlib.sha256(f"{identity.tenant_id}\0{resource_id}".encode()).hexdigest()
        )
        try:
            account, created = await run_in_threadpool(
                store.create_tenant_account,
                tenant_id=identity.tenant_id,
                actor_user_id=identity.user_id,
                kind="caldav",
                label=static_account.label,
                base_url=base_url,
                credential=credential,
                enabled=True,
                status="ready",
                last_error=None,
                idempotency_key=migration_key,
                request_hash=store.request_hash(migration_payload),
                initial_accesses=access_entries,
                audit_operation="tenant_account.migrate",
            )
        except ValueError as exc:
            raise GatewayAPIError(
                409,
                "migration_conflict",
                "Static resource configuration changed after migration.",
            ) from exc
        except OverflowError as exc:
            raise GatewayAPIError(
                409, "account_limit_reached", "Tenant account limit was reached."
            ) from exc
        response = {
            "source_resource_id": resource_id,
            "created": created,
            "grant_count": len(access_entries),
            "calendar_count": calendar_count,
            "account": _account_response(account),
        }
        return JSONResponse(status_code=201 if created else 200, content=response)

    @app.get("/v1/tenant/accounts")
    async def list_tenant_accounts(
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
        limit: int = 100,
    ) -> dict[str, Any]:
        require_scope(identity, TENANT_ACCOUNTS_READ_SCOPE)
        if limit < 1 or limit > 100:
            raise GatewayAPIError(422, "invalid_request", "Limit must be between 1 and 100.")
        accounts = await run_in_threadpool(
            store.list_tenant_accounts, identity.tenant_id, limit=limit
        )
        return {
            "accounts": [_account_response(account) for account in accounts],
            "next_cursor": None,
        }

    @app.post("/v1/tenant/accounts", status_code=201)
    async def create_tenant_account(
        payload: TenantAccountCreateInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        require_scope(identity, TENANT_ACCOUNTS_WRITE_SCOPE)
        if idempotency_key is not None and not 1 <= len(idempotency_key) <= 200:
            raise GatewayAPIError(422, "invalid_request", "Idempotency-Key is invalid.")
        base_url = await _validate_url(url_policy, payload.base_url)
        credential = _credential(payload.auth)
        candidate = _candidate_tenant_account(
            identity.tenant_id,
            payload.kind,
            payload.label,
            base_url,
            credential,
            payload.enabled,
        )
        collection_count = await _test_account(connector, candidate)
        request_payload = payload.model_dump(mode="json")
        request_payload["auth"]["password"] = payload.auth.password.get_secret_value()
        initial_access = (
            (payload.initial_access.user_id, payload.initial_access.permission)
            if payload.initial_access is not None
            else None
        )
        try:
            account, _created = await run_in_threadpool(
                store.create_tenant_account,
                tenant_id=identity.tenant_id,
                actor_user_id=identity.user_id,
                kind=payload.kind,
                label=payload.label,
                base_url=base_url,
                credential=credential,
                enabled=payload.enabled,
                status="ready" if payload.enabled else "disabled",
                last_error=None,
                idempotency_key=idempotency_key,
                request_hash=store.request_hash(request_payload) if idempotency_key else None,
                initial_access=initial_access,
            )
        except ValueError as exc:
            raise GatewayAPIError(409, "conflict", "Idempotency key conflicts.") from exc
        except OverflowError as exc:
            raise GatewayAPIError(
                409, "account_limit_reached", "Tenant account limit was reached."
            ) from exc
        response = _account_response(account)
        response.update(_collection_count(account.kind, collection_count))
        return response

    @app.get("/v1/tenant/accounts/{account_ref}")
    async def get_tenant_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, TENANT_ACCOUNTS_READ_SCOPE)
        account = await _tenant_owned_account(account_access_policy, identity, account_ref)
        return _account_response(account)

    @app.get("/v1/tenant/accounts/{account_ref}/calendars")
    async def list_tenant_account_calendars(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, TENANT_ACCOUNTS_READ_SCOPE)
        account = await _tenant_owned_account(account_access_policy, identity, account_ref)
        preferences = await _discover_calendar_preferences(connector, store, account)
        return {"calendars": [_calendar_preference_response(item) for item in preferences]}

    @app.patch("/v1/tenant/accounts/{account_ref}/calendars/{calendar_ref}")
    async def patch_tenant_account_calendar(
        account_ref: str,
        calendar_ref: str,
        payload: CalendarPreferencePatchInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, TENANT_ACCOUNTS_WRITE_SCOPE)
        account = await _tenant_owned_account(account_access_policy, identity, account_ref)
        _require_caldav_account(account)
        preference = await run_in_threadpool(
            store.set_calendar_enabled,
            identity.tenant_id,
            account_ref,
            calendar_ref,
            enabled=payload.enabled,
            actor_user_id=identity.user_id,
            audit_operation="tenant_calendar.preference_update",
        )
        if preference is None:
            raise GatewayAPIError(404, "not_found", "Calendar was not found.")
        return _calendar_preference_response(preference)

    @app.patch("/v1/tenant/accounts/{account_ref}")
    async def patch_tenant_account(
        account_ref: str,
        payload: AccountPatchInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, TENANT_ACCOUNTS_WRITE_SCOPE)
        if not payload.model_fields_set:
            raise GatewayAPIError(422, "invalid_request", "At least one field is required.")
        current = await _tenant_owned_account(account_access_policy, identity, account_ref)
        base_url = (
            await _validate_url(url_policy, payload.base_url)
            if payload.base_url is not None
            else current.base_url
        )
        credential = _credential(payload.auth) if payload.auth is not None else current.credential
        enabled = payload.enabled if payload.enabled is not None else current.enabled
        candidate = replace(
            current,
            label=payload.label if payload.label is not None else current.label,
            base_url=base_url,
            credential=credential,
            enabled=enabled,
            status="ready" if enabled else "disabled",
            last_error=None,
        )
        if enabled and (payload.base_url is not None or payload.auth is not None):
            await _test_account(connector, candidate)
            candidate = replace(candidate, last_checked_at=_now())
        try:
            updated = await run_in_threadpool(
                store.update_tenant_account,
                candidate,
                actor_user_id=identity.user_id,
                audit_operation="tenant_account.update",
                clear_calendar_preferences=(
                    payload.base_url is not None or payload.auth is not None
                ),
            )
        except LookupError as exc:
            raise GatewayAPIError(404, "not_found", "Account was not found.") from exc
        return _account_response(updated)

    @app.post("/v1/tenant/accounts/{account_ref}/test")
    async def test_tenant_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, TENANT_ACCOUNTS_WRITE_SCOPE)
        account = await _tenant_owned_account(account_access_policy, identity, account_ref)
        try:
            collection_count = await _test_account(connector, account)
        except GatewayAPIError as exc:
            checked_at = _now()
            await run_in_threadpool(
                store.update_tenant_account,
                replace(
                    account,
                    status="error",
                    last_checked_at=checked_at,
                    last_error=exc.code,
                ),
                actor_user_id=identity.user_id,
                audit_operation="tenant_account.test",
            )
            raise
        checked_at = _now()
        await run_in_threadpool(
            store.update_tenant_account,
            replace(account, status="ready", last_checked_at=checked_at, last_error=None),
            actor_user_id=identity.user_id,
            audit_operation="tenant_account.test",
        )
        return {
            "status": "ready",
            **_collection_count(account.kind, collection_count),
            "checked_at": checked_at,
        }

    @app.delete("/v1/tenant/accounts/{account_ref}", status_code=204)
    async def delete_tenant_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        require_scope(identity, TENANT_ACCOUNTS_WRITE_SCOPE)
        await _tenant_owned_account(account_access_policy, identity, account_ref)
        deleted = await run_in_threadpool(
            store.delete_tenant_account,
            identity.tenant_id,
            account_ref,
            actor_user_id=identity.user_id,
        )
        if not deleted:
            raise GatewayAPIError(404, "not_found", "Account was not found.")
        return Response(status_code=204)

    @app.get("/v1/tenant/accounts/{account_ref}/grants")
    async def list_account_grants(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNT_GRANTS_READ_SCOPE)
        await _tenant_owned_account(account_access_policy, identity, account_ref)
        grants = await run_in_threadpool(store.list_account_grants, account_ref, identity.tenant_id)
        return {"grants": [_account_grant_response(grant) for grant in grants]}

    @app.put("/v1/tenant/accounts/{account_ref}/grants")
    async def put_account_grant(
        account_ref: str,
        payload: AccountGrantPutInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNT_GRANTS_WRITE_SCOPE)
        await _tenant_owned_account(account_access_policy, identity, account_ref)
        try:
            grant = await run_in_threadpool(
                store.upsert_account_grant,
                account_ref=account_ref,
                tenant_id=identity.tenant_id,
                user_id=payload.user_id,
                permission=payload.permission,
                enabled=payload.enabled,
                updated_by=identity.user_id,
            )
        except LookupError as exc:  # pragma: no cover - guarded above and checked transactionally
            raise GatewayAPIError(404, "not_found", "Account was not found.") from exc
        except OverflowError as exc:
            raise GatewayAPIError(
                409,
                "account_grant_limit_reached",
                "Account grant limit was reached.",
            ) from exc
        return _account_grant_response(grant)

    @app.delete("/v1/tenant/accounts/{account_ref}/grants/{user_id}", status_code=204)
    async def delete_account_grant(
        account_ref: str,
        user_id: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        require_scope(identity, ACCOUNT_GRANTS_WRITE_SCOPE)
        if not 1 <= len(user_id) <= 200:
            raise GatewayAPIError(422, "invalid_request", "Account grant user ID is invalid.")
        await _tenant_owned_account(account_access_policy, identity, account_ref)
        try:
            deleted = await run_in_threadpool(
                store.delete_account_grant,
                account_ref,
                identity.tenant_id,
                user_id,
                deleted_by=identity.user_id,
            )
        except LookupError as exc:  # pragma: no cover - guarded above and checked transactionally
            raise GatewayAPIError(404, "not_found", "Account was not found.") from exc
        if not deleted:
            raise GatewayAPIError(404, "not_found", "Account grant was not found.")
        return Response(status_code=204)

    @app.get("/v1/tenant/account-grant-audit")
    async def list_account_grant_audit(
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
        limit: int = 100,
        before_id: int | None = None,
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNT_GRANTS_READ_SCOPE)
        if limit < 1 or limit > 500:
            raise GatewayAPIError(422, "invalid_request", "Limit must be between 1 and 500.")
        if before_id is not None and before_id < 1:
            raise GatewayAPIError(422, "invalid_request", "Audit cursor must be positive.")
        entries = await run_in_threadpool(
            store.list_account_grant_audit,
            identity.tenant_id,
            limit=limit + 1,
            before_id=before_id,
        )
        has_more = len(entries) > limit
        entries = entries[:limit]
        return {
            "entries": [_account_grant_audit_response(entry) for entry in entries],
            "next_cursor": entries[-1].audit_id if has_more else None,
        }

    @app.get("/v1/accounts")
    async def list_accounts(
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
        limit: int = 100,
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_READ_SCOPE)
        if limit < 1 or limit > 100:
            raise GatewayAPIError(422, "invalid_request", "Limit must be between 1 and 100.")
        accounts = await run_in_threadpool(
            account_access_policy.list_personal_accounts,
            identity,
            limit=limit,
        )
        return {
            "accounts": [_account_response(account) for account in accounts],
            "next_cursor": None,
        }

    @app.post("/v1/accounts", status_code=201)
    async def create_account(
        payload: AccountCreateInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        if idempotency_key is not None and not 1 <= len(idempotency_key) <= 200:
            raise GatewayAPIError(422, "invalid_request", "Idempotency-Key is invalid.")
        base_url = await _validate_url(url_policy, payload.base_url)
        credential = _credential(payload.auth)
        candidate = _candidate_account(
            identity, payload.kind, payload.label, base_url, credential, payload.enabled
        )
        collection_count = await _test_account(connector, candidate)
        request_payload = payload.model_dump(mode="json")
        request_payload["auth"]["password"] = payload.auth.password.get_secret_value()
        try:
            account, _created = await run_in_threadpool(
                store.create_account,
                tenant_id=identity.tenant_id,
                user_id=identity.user_id,
                kind=payload.kind,
                label=payload.label,
                base_url=base_url,
                credential=credential,
                enabled=payload.enabled,
                status="ready" if payload.enabled else "disabled",
                last_error=None,
                idempotency_key=idempotency_key,
                request_hash=store.request_hash(request_payload) if idempotency_key else None,
            )
        except ValueError as exc:
            raise GatewayAPIError(409, "conflict", "Idempotency key conflicts.") from exc
        except OverflowError as exc:
            raise GatewayAPIError(
                409, "account_limit_reached", "Account limit was reached."
            ) from exc
        response = _account_response(account)
        response.update(_collection_count(account.kind, collection_count))
        return response

    @app.get("/v1/accounts/{account_ref}")
    async def get_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_READ_SCOPE)
        account = await _owned_account(account_access_policy, identity, account_ref)
        return _account_response(account)

    @app.get("/v1/accounts/{account_ref}/calendars")
    async def list_account_calendars(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_READ_SCOPE)
        account = await _owned_account(account_access_policy, identity, account_ref)
        preferences = await _discover_calendar_preferences(connector, store, account)
        return {"calendars": [_calendar_preference_response(item) for item in preferences]}

    @app.patch("/v1/accounts/{account_ref}/calendars/{calendar_ref}")
    async def patch_account_calendar(
        account_ref: str,
        calendar_ref: str,
        payload: CalendarPreferencePatchInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        account = await _owned_account(account_access_policy, identity, account_ref)
        _require_caldav_account(account)
        preference = await run_in_threadpool(
            store.set_calendar_enabled,
            identity.tenant_id,
            account_ref,
            calendar_ref,
            enabled=payload.enabled,
            actor_user_id=identity.user_id,
            audit_operation="calendar.preference_update",
        )
        if preference is None:
            raise GatewayAPIError(404, "not_found", "Calendar was not found.")
        return _calendar_preference_response(preference)

    @app.patch("/v1/accounts/{account_ref}")
    async def patch_account(
        account_ref: str,
        payload: AccountPatchInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        if not payload.model_fields_set:
            raise GatewayAPIError(422, "invalid_request", "At least one field is required.")
        current = await _owned_account(account_access_policy, identity, account_ref)
        base_url = (
            await _validate_url(url_policy, payload.base_url)
            if payload.base_url is not None
            else current.base_url
        )
        credential = _credential(payload.auth) if payload.auth is not None else current.credential
        enabled = payload.enabled if payload.enabled is not None else current.enabled
        candidate = replace(
            current,
            label=payload.label if payload.label is not None else current.label,
            base_url=base_url,
            credential=credential,
            enabled=enabled,
            status="ready" if enabled else "disabled",
            last_error=None,
        )
        if enabled and (payload.base_url is not None or payload.auth is not None):
            await _test_account(connector, candidate)
            candidate = replace(candidate, last_checked_at=_now())
        updated = await run_in_threadpool(
            store.update_account,
            candidate,
            audit_operation="account.update",
            clear_calendar_preferences=(payload.base_url is not None or payload.auth is not None),
        )
        return _account_response(updated)

    @app.post("/v1/accounts/{account_ref}/test")
    async def test_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        account = await _owned_account(account_access_policy, identity, account_ref)
        try:
            collection_count = await _test_account(connector, account)
        except GatewayAPIError as exc:
            checked_at = _now()
            await run_in_threadpool(
                store.update_account,
                replace(
                    account,
                    status="error",
                    last_checked_at=checked_at,
                    last_error=exc.code,
                ),
                audit_operation="account.test",
            )
            raise
        checked_at = _now()
        await run_in_threadpool(
            store.update_account,
            replace(account, status="ready", last_checked_at=checked_at, last_error=None),
            audit_operation="account.test",
        )
        return {
            "status": "ready",
            **_collection_count(account.kind, collection_count),
            "checked_at": checked_at,
        }

    @app.delete("/v1/accounts/{account_ref}", status_code=204)
    async def delete_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        await _owned_account(account_access_policy, identity, account_ref)
        deleted = await run_in_threadpool(
            store.delete_account, identity.tenant_id, identity.user_id, account_ref
        )
        if not deleted:
            raise GatewayAPIError(404, "not_found", "Account was not found.")
        return Response(status_code=204)

    return app


async def _tenant_owned_account(
    access_policy: AccountAccessPolicy, identity: GatewayIdentity, account_ref: str
) -> GatewayAccount:
    account = await run_in_threadpool(access_policy.get_tenant_account, identity, account_ref)
    if account is None:
        raise GatewayAPIError(404, "not_found", "Account was not found.")
    return account


async def _owned_account(
    access_policy: AccountAccessPolicy, identity: GatewayIdentity, account_ref: str
) -> GatewayAccount:
    account = await run_in_threadpool(access_policy.get_personal_account, identity, account_ref)
    if account is None:
        raise GatewayAPIError(404, "not_found", "Account was not found.")
    return account


async def _validate_url(policy: OutboundURLPolicy, value: str) -> str:
    try:
        return await run_in_threadpool(policy.validate, value)
    except URLPolicyError as exc:
        raise GatewayAPIError(
            422,
            "url_not_allowed",
            "Account URL is not allowed.",
            fields={"base_url": "URL is not allowed."},
        ) from exc


async def _test_account(connector: AccountConnector, account: GatewayAccount) -> int:
    try:
        return await run_in_threadpool(connector.test, account)
    except AccountConnectionError as exc:
        raise GatewayAPIError(422, exc.code, "Account connection test failed.") from exc
    except Exception as exc:
        raise GatewayAPIError(422, "connection_failed", "Account connection test failed.") from exc


def _credential(auth: PasswordAuthInput) -> PasswordCredential:
    return PasswordCredential(
        username=auth.username,
        password=auth.password.get_secret_value(),
        mode=auth.mode,
    )


def _candidate_tenant_account(
    tenant_id: str,
    kind: str,
    label: str,
    base_url: str,
    credential: PasswordCredential,
    enabled: bool,
) -> GatewayAccount:
    now = _now()
    return GatewayAccount(
        account_ref="pending",
        tenant_id=tenant_id,
        owner_type="tenant",
        owner_user_id=None,
        kind=kind,
        label=label,
        base_url=base_url,
        credential=credential,
        status="ready" if enabled else "disabled",
        enabled=enabled,
        last_checked_at=now,
        last_error=None,
        created_at=now,
        updated_at=now,
    )


def _candidate_account(
    identity: GatewayIdentity,
    kind: str,
    label: str,
    base_url: str,
    credential: PasswordCredential,
    enabled: bool,
) -> GatewayAccount:
    now = _now()
    return GatewayAccount(
        account_ref="pending",
        tenant_id=identity.tenant_id,
        owner_type="user",
        owner_user_id=identity.user_id,
        kind=kind,
        label=label,
        base_url=base_url,
        credential=credential,
        status="ready" if enabled else "disabled",
        enabled=enabled,
        last_checked_at=now,
        last_error=None,
        created_at=now,
        updated_at=now,
    )


async def _discover_calendar_preferences(
    connector: AccountConnector, store: AccountStore, account: GatewayAccount
) -> list[CalendarPreference]:
    _require_caldav_account(account)
    try:
        calendars = await run_in_threadpool(connector.discover_calendars, account)
    except AccountConnectionError as exc:
        raise GatewayAPIError(422, exc.code, "Calendar discovery failed.") from exc
    except Exception as exc:
        raise GatewayAPIError(422, "connection_failed", "Calendar discovery failed.") from exc
    return await run_in_threadpool(
        store.sync_calendar_preferences,
        account,
        [(calendar.href, calendar.name, calendar.color, False) for calendar in calendars],
    )


def _require_caldav_account(account: GatewayAccount) -> None:
    if account.kind != "caldav":
        raise GatewayAPIError(404, "not_found", "CalDAV account was not found.")


def _calendar_preference_response(preference: CalendarPreference) -> dict[str, Any]:
    return {
        "calendar_ref": preference.calendar_ref,
        "name": preference.name,
        "color": preference.color,
        "enabled": preference.enabled,
        "read_only": preference.read_only,
    }


def _collection_count(kind: str, count: int) -> dict[str, int]:
    return {"addressbook_count" if kind == "carddav" else "calendar_count": count}


def _account_response(account: GatewayAccount) -> dict[str, Any]:
    return {
        "account_ref": account.account_ref,
        "owner_type": account.owner_type,
        "kind": account.kind,
        "label": account.label,
        "base_url": account.base_url,
        "auth_type": "password",
        "auth_mode": account.credential.mode,
        "username_hint": _username_hint(account.credential.username),
        "status": account.status,
        "enabled": account.enabled,
        "last_checked_at": account.last_checked_at,
        "last_error": account.last_error,
        "created_at": account.created_at,
        "updated_at": account.updated_at,
    }


def _username_hint(username: str) -> str:
    if len(username) <= 2:
        return "…"
    if "@" in username:
        local, domain = username.rsplit("@", 1)
        return f"{local[:1]}…@{domain}"
    return f"{username[:1]}…{username[-1:]}"


def _configured_resource_catalog(
    static_accounts: tuple[StaticGatewayAccount, ...],
    static_contact_account: StaticContactAccount | None,
) -> tuple[DAVResource, ...]:
    resources = [
        DAVResource(
            resource_id=account.resource_id,
            kind="ics" if isinstance(account, StaticICSSubscription) else "caldav",
            label=account.label,
            allowed_permissions=(
                ("read",) if isinstance(account, StaticICSSubscription) else ("read", "read_write")
            ),
        )
        for account in static_accounts
    ]
    if static_contact_account is not None:
        resources.append(
            DAVResource(
                resource_id=static_contact_account.resource_id,
                kind="carddav",
                label="Contacts",
                allowed_permissions=("read", "read_write"),
            )
        )
    return tuple(sorted(resources, key=lambda resource: resource.resource_id))


def _resource_response(resource: DAVResource) -> dict[str, Any]:
    return {
        "resource_id": resource.resource_id,
        "kind": resource.kind,
        "label": resource.label,
        "allowed_permissions": list(resource.allowed_permissions),
        "configured": resource.configured,
        "enabled": resource.enabled,
    }


def _account_grant_response(grant: Any) -> dict[str, Any]:
    return {
        "account_ref": grant.account_ref,
        "tenant_id": grant.tenant_id,
        "user_id": grant.user_id,
        "permission": grant.permission,
        "enabled": grant.enabled,
        "updated_by": grant.updated_by,
        "created_at": grant.created_at,
        "updated_at": grant.updated_at,
    }


def _account_grant_audit_response(entry: Any) -> dict[str, Any]:
    return {
        "audit_id": entry.audit_id,
        "account_ref": entry.account_ref,
        "tenant_id": entry.tenant_id,
        "user_id": entry.user_id,
        "actor_id": entry.actor_id,
        "operation": entry.operation,
        "previous": (
            {"permission": entry.previous_permission, "enabled": entry.previous_enabled}
            if entry.previous_permission is not None
            else None
        ),
        "resulting": (
            {"permission": entry.resulting_permission, "enabled": entry.resulting_enabled}
            if entry.resulting_permission is not None
            else None
        ),
        "created_at": entry.created_at,
    }


def _resource_grant_response(grant: Any) -> dict[str, Any]:
    return {
        "resource_id": grant.resource_id,
        "tenant_id": grant.tenant_id,
        "user_id": grant.user_id,
        "permission": grant.permission,
        "enabled": grant.enabled,
        "updated_by": grant.updated_by,
        "created_at": grant.created_at,
        "updated_at": grant.updated_at,
    }


def _resource_grant_audit_response(entry: Any) -> dict[str, Any]:
    return {
        "audit_id": entry.audit_id,
        "resource_id": entry.resource_id,
        "tenant_id": entry.tenant_id,
        "user_id": entry.user_id,
        "actor_id": entry.actor_id,
        "operation": entry.operation,
        "previous": (
            {"permission": entry.previous_permission, "enabled": entry.previous_enabled}
            if entry.previous_permission is not None
            else None
        ),
        "resulting": (
            {"permission": entry.resulting_permission, "enabled": entry.resulting_enabled}
            if entry.resulting_permission is not None
            else None
        ),
        "created_at": entry.created_at,
    }


def _bool_env(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean")


def _resolve_host(host: str) -> list[str]:
    return sorted(
        {
            str(result[4][0])
            for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            if result[4]
        }
    )


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the multi-tenant Private DAV gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8769)
    parser.add_argument("--log-level", default="info")
    parser.add_argument(
        "--log-format",
        choices=("text", "json"),
        default=os.environ.get("PRIVATE_DAV_GATEWAY_LOG_FORMAT", "text"),
    )
    args = parser.parse_args()
    app = create_gateway_app()
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        log_config=_uvicorn_log_config(json_format=args.log_format == "json"),
    )


if __name__ == "__main__":
    main()
