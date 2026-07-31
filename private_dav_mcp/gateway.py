from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Annotated, Any, Protocol
from urllib.parse import urlsplit

import uvicorn
from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from starlette.concurrency import run_in_threadpool

from private_dav_mcp.caldav import CalDAVCalendarSource
from private_dav_mcp.gateway_identity import GatewayIdentity, IdentityError, IdentityVerifier
from private_dav_mcp.gateway_mcp import GatewayCalendarMCP, StaticCalendarAccount
from private_dav_mcp.gateway_store import (
    AccountCipher,
    AccountStore,
    GatewayAccount,
    PasswordCredential,
)

ACCOUNTS_READ_SCOPE = "dav:accounts:read"
ACCOUNTS_WRITE_SCOPE = "dav:accounts:write"


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


class CalDAVAccountConnector:
    def test(self, account: GatewayAccount) -> int:
        try:
            source = CalDAVCalendarSource(
                calendar_url=account.base_url,
                username=account.credential.username,
                password=account.credential.password,
                auth_mode=account.credential.mode,
            )
            return len(source.list_calendars())
        except RuntimeError as exc:
            message = str(exc).lower()
            code = (
                "authentication_failed"
                if "401" in message or "authentication" in message
                else "dav_discovery_failed"
            )
            raise AccountConnectionError(code) from exc


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


class AccountCreateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(pattern="^caldav$")
    label: str = Field(min_length=1, max_length=100)
    base_url: str = Field(min_length=1, max_length=2048)
    auth: PasswordAuthInput
    enabled: bool = True


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
    static_accounts: tuple[StaticCalendarAccount, ...]

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
            static_accounts=_static_accounts_from_env(os.environ),
        )


def create_gateway_app(
    *,
    verifier: IdentityVerifier | None = None,
    store: AccountStore | None = None,
    connector: AccountConnector | None = None,
    url_policy: OutboundURLPolicy | None = None,
    calendar_mcp: GatewayCalendarMCP | None = None,
    settings: GatewaySettings | None = None,
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
    connector = connector or CalDAVAccountConnector()
    url_policy = url_policy or OutboundURLPolicy()
    static_accounts = settings.static_accounts if settings is not None else ()
    for static_account in static_accounts:
        url_policy.validate(static_account.base_url)
    calendar_mcp = calendar_mcp or GatewayCalendarMCP(
        store,
        static_accounts=static_accounts,
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
        result = await run_in_threadpool(calendar_mcp.handle, identity, payload)
        if result is None:
            return Response(status_code=202)
        return JSONResponse(status_code=200, content=result)

    @app.get("/v1/accounts")
    async def list_accounts(
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
        limit: int = 100,
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_READ_SCOPE)
        if limit < 1 or limit > 100:
            raise GatewayAPIError(422, "invalid_request", "Limit must be between 1 and 100.")
        accounts = await run_in_threadpool(
            store.list_accounts, identity.tenant_id, identity.user_id, limit=limit
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
        calendar_count = await _test_account(connector, candidate)
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
        response["calendar_count"] = calendar_count
        return response

    @app.get("/v1/accounts/{account_ref}")
    async def get_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_READ_SCOPE)
        account = await _owned_account(store, identity, account_ref)
        return _account_response(account)

    @app.patch("/v1/accounts/{account_ref}")
    async def patch_account(
        account_ref: str,
        payload: AccountPatchInput,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        if not payload.model_fields_set:
            raise GatewayAPIError(422, "invalid_request", "At least one field is required.")
        current = await _owned_account(store, identity, account_ref)
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
            store.update_account, candidate, audit_operation="account.update"
        )
        return _account_response(updated)

    @app.post("/v1/accounts/{account_ref}/test")
    async def test_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> dict[str, Any]:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        account = await _owned_account(store, identity, account_ref)
        try:
            calendar_count = await _test_account(connector, account)
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
        return {"status": "ready", "calendar_count": calendar_count, "checked_at": checked_at}

    @app.delete("/v1/accounts/{account_ref}", status_code=204)
    async def delete_account(
        account_ref: str,
        identity: GatewayIdentity = Depends(authenticate),  # noqa: B008
    ) -> Response:
        require_scope(identity, ACCOUNTS_WRITE_SCOPE)
        deleted = await run_in_threadpool(
            store.delete_account, identity.tenant_id, identity.user_id, account_ref
        )
        if not deleted:
            raise GatewayAPIError(404, "not_found", "Account was not found.")
        return Response(status_code=204)

    return app


async def _owned_account(
    store: AccountStore, identity: GatewayIdentity, account_ref: str
) -> GatewayAccount:
    account = await run_in_threadpool(
        store.get_account, identity.tenant_id, identity.user_id, account_ref
    )
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
        user_id=identity.user_id,
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


def _account_response(account: GatewayAccount) -> dict[str, Any]:
    return {
        "account_ref": account.account_ref,
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
    args = parser.parse_args()
    app = create_gateway_app()
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
